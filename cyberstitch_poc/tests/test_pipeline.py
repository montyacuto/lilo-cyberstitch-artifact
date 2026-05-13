import json
import tempfile
import unittest
from pathlib import Path

from cyberstitch.autodoc_eval import parse_response, run_autodoc_eval
from cyberstitch.config import load_config
from cyberstitch.codeql_pack import write_codeql_pack_corpus
from cyberstitch.discovery import score_results_without_expected_rule_ids
from cyberstitch.fcir import fcir_to_query, parse_sexpr, query_to_fcir, write_corpus
from cyberstitch.llm import run_llm_propose
from cyberstitch.lilo_loop import (
    export_lilo_loop_input,
    prepare_lilo_loop_partitions,
    render_lilo_loop_prompt,
    run_lilo_loop,
    select_lilo_prompt_inventory,
)
from cyberstitch.manifest import validate_manifest
from cyberstitch.parser import format_query, parse_query
from cyberstitch.rewrite import rewrite_queries
from cyberstitch.sarif import score_sarif
from cyberstitch.seedgen import generate_seed_profile, validate_seed_manifest
from cyberstitch.semantic import mine_semantic_candidates
from cyberstitch.stitch import _candidates_from_stitch
from cyberstitch.syntax import run_codeql_check
from cyberstitch.validate import validate_candidates


ROOT = Path(__file__).resolve().parents[1]


def _lilo_item(
    name,
    role="Source",
    accepted=None,
    accepted_for_lilo=None,
    rewrite=False,
    use_sites=2,
):
    validation = {}
    if accepted is not None:
        validation["accepted"] = accepted
    if accepted_for_lilo is not None:
        validation["accepted_for_lilo"] = accepted_for_lilo
    schema = "java_source_predicate_helper_v1" if role == "Source" else "java_sink_predicate_helper_v1"
    if role == "Barrier":
        schema = "java_barrier_predicate_helper_v1"
    if role == "HelperPredicate":
        schema = "java_codeql_helper_predicate_template_v1"
    item = {
        "id": "candidate:{}".format(name),
        "type": "semantic_abstraction_candidate",
        "name": name,
        "display_name": name,
        "kind": "codeql_helper" if rewrite else "semantic_template",
        "origin": "test",
        "schema": schema,
        "language": "java",
        "semantic_hash": "hash-{}".format(name),
        "semantic_role": role,
        "semantic_target": "{}Target".format(role),
        "semantic_usefulness": "semantic",
        "rewrite_eligible": rewrite,
        "validation": validation,
        "description": "Test candidate {}".format(name),
        "predicate": "{}Predicate".format(name),
        "helper_module": "CyberStitchJavaHelpers",
        "use_sites": [
            {"query": "query_{}.ql".format(index), "predicate": "is{}".format(role)}
            for index in range(use_sites)
        ],
        "semantic_validation": {"ok": True, "reasons": [], "evidence": {}},
    }
    item["candidate"] = {
        "candidate_version": "cyberstitch-candidate-v2",
        "name": name,
        "kind": item["kind"],
        "origin": "test",
        "schema": schema,
        "language": "java",
        "helper_module": item["helper_module"],
        "predicate": item["predicate"],
        "display_name": name,
        "description": item["description"],
        "body": "predicate {}(DataFlow::Node n) {{ any() }}".format(item["predicate"]),
        "use_sites": item["use_sites"],
        "rewrite_eligible": rewrite,
        "semantic_hash": item["semantic_hash"],
        "semantic_role": role,
        "semantic_target": item["semantic_target"],
        "semantic_validation": item["semantic_validation"],
    }
    return item


class PipelineTest(unittest.TestCase):
    def test_parse_and_roundtrip_seed_queries(self):
        for query_path in sorted((ROOT / "queries").glob("*.ql")):
            query = parse_query(query_path)
            self.assertIn("name", query.metadata)
            self.assertIn("isSource", {p.name for p in query.config_modules[0].predicates})
            self.assertNotIn("RawBody", json.dumps(query.to_dict()))
            roundtrip = format_query(query)
            reparsed = parse_query(_write_temp_query(roundtrip))
            self.assertEqual(query.metadata["id"], reparsed.metadata["id"])

    def test_fcir_contains_query_shape(self):
        query = parse_query(ROOT / "queries" / "remote-to-exec.ql")
        program = query_to_fcir(query)
        self.assertIn("RemoteToExecConfig", program)
        self.assertIn("(Source", program)
        self.assertIn("(Sink", program)
        self.assertNotIn("RawBody", program)
        self.assertNotIn('"', program)
        self.assertEqual(parse_sexpr(program)[0], "Query")

    def test_write_corpus_emits_stitch_programs_and_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            query = parse_query(ROOT / "queries" / "java" / "owasp-cwe078-command.ql")
            sqir_path = tmp / "query.json"
            sqir_path.write_text(json.dumps(query.to_dict(), indent=2))
            result = write_corpus([sqir_path], tmp / "fcir" / "corpus.json")
            programs = json.loads(Path(result["programs_path"]).read_text())
            provenance = json.loads(Path(result["provenance_path"]).read_text())
            self.assertIsInstance(programs, list)
            self.assertEqual(len(programs), 1)
            self.assertEqual(provenance["programs"][0]["sqir_hash"], query.stable_hash())
            concepts = [
                node
                for node in provenance["programs"][0]["semantic_nodes"]
                if node["kind"] == "Concept"
            ]
            self.assertIn("Concepts", programs[0])
            self.assertIn("RemoteFlowSource", {node["target"] for node in concepts})
            self.assertIn("java.lang.Runtime.exec", {node["target"] for node in concepts})
            inverted = fcir_to_query(programs[0], provenance["programs"][0])
            self.assertEqual(inverted.stable_hash(), query.stable_hash())

    def test_stitch_exact_term_mapping_can_emit_codeql_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sqir_paths = []
            for name in ["owasp-cwe078-command.ql", "owasp-cwe089-sql.ql"]:
                query = parse_query(ROOT / "queries" / "java" / name)
                path = tmp / "{}.json".format(name)
                path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(path)
            result = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            provenance_path = Path(result["provenance_path"])
            provenance = json.loads(provenance_path.read_text())
            source_term = next(
                item["term"]
                for program in provenance["programs"]
                for item in program["term_index"]
                if item["kind"] == "Predicate" and item["role"] == "Source"
            )
            candidates = _candidates_from_stitch(
                {"num_abstractions": 1, "abstractions": [{"name": "fn_0", "body": source_term}]},
                provenance_path,
            )
            candidate = candidates["candidates"][0]
            self.assertEqual(candidate["kind"], "codeql_helper")
            self.assertEqual(candidate["candidate_version"], "cyberstitch-candidate-v2")
            self.assertEqual(candidate["name"], "java_remote_flow_source")
            self.assertEqual(len(candidate["use_sites"]), 2)
            self.assertIn("predicate isRemoteFlowSource(DataFlow::Node source)", candidate["body"])

    def test_stitch_generalized_template_derives_semantic_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sqir_paths = []
            for name in ["owasp-cwe078-command.ql", "owasp-cwe089-sql.ql"]:
                query = parse_query(ROOT / "queries" / "java" / name)
                path = tmp / "{}.json".format(name)
                path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(path)
            result = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            provenance_path = Path(result["provenance_path"])
            provenance = json.loads(provenance_path.read_text())
            source_term = next(
                item["term"]
                for program in provenance["programs"]
                for item in program["term_index"]
                if item["kind"] == "Predicate" and item["role"] == "Source"
            )
            sink_terms = [
                item["term"]
                for program in provenance["programs"]
                for item in program["term_index"]
                if item["kind"] == "Predicate" and item["role"] == "Sink"
            ]
            abstract_body = (
                "(Predicates {} "
                "(Predicate isSink (Role (Sink #2)) (Hash #1) "
                "(Params (Param DataFlow_Node sink)) "
                "(Expr (Exists (Vars (VarDecl MethodCall call)) (Body #0)))))"
            ).format(source_term)
            uses = [
                {"fn_0 use{}".format(i): "(Predicates {} {})".format(source_term, sink_term)}
                for i, sink_term in enumerate(sink_terms)
            ]
            candidates = _candidates_from_stitch(
                {
                    "num_abstractions": 1,
                    "abstractions": [{"name": "fn_0", "body": abstract_body, "uses": uses}],
                },
                provenance_path,
            )
            schemas = {candidate["schema"] for candidate in candidates["candidates"]}
            self.assertIn("java_remote_source_parameterized_sink_template_v1", schemas)
            self.assertIn("java_source_predicate_helper_v1", schemas)
            helper = next(candidate for candidate in candidates["candidates"] if candidate["kind"] == "codeql_helper")
            self.assertTrue(helper["rewrite_eligible"])
            template = next(candidate for candidate in candidates["candidates"] if candidate["kind"] == "semantic_template")
            self.assertFalse(template["rewrite_eligible"])

    def test_expanded_stitch_shapes_normalize_to_semantic_codeql_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sqir_paths = []
            for query_path in sorted((ROOT / "query_profiles" / "combined" / "java").glob("*.ql")):
                query = parse_query(query_path)
                path = tmp / "{}.json".format(query_path.stem)
                path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(path)
            result = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            provenance_path = Path(result["provenance_path"])
            provenance = json.loads(provenance_path.read_text())

            predicates = [
                item
                for program in provenance["programs"]
                for item in program["term_index"]
                if item["kind"] == "Predicate"
            ]
            targets = {(item["role"], item["target"]) for item in predicates}
            self.assertIn(("Sink", "CommandInjectionSink"), targets)
            self.assertIn(("Sink", "QueryInjectionSink"), targets)
            self.assertIn(("Sink", "sinkNode:sql-injection"), targets)
            self.assertIn(("Barrier", "CommandInjectionSanitizer"), targets)
            self.assertIn(("Sink", "method-names:execute|executeQuery|executeUpdate"), targets)

            source_terms = {}
            path_terms = []
            for program in provenance["programs"]:
                for item in program["term_index"]:
                    if item["kind"] == "Predicate" and item["role"] == "Source":
                        source_terms.setdefault(item["target"], item["term"])
                    if item["kind"] == "PathQuery":
                        path_terms.append(item["term"])
            raw = {
                "num_abstractions": 3,
                "abstractions": [
                    {
                        "name": "fn_0",
                        "body": (
                            "(Predicates (Predicate isSource (Role (Source #0)) "
                            "(Hash #1) (Params (Param DataFlow_Node source)) "
                            "(Expr (Exists (Vars (VarDecl #0 remote)) "
                            "(Body (Eq (Var source) (Var remote)))))))"
                        ),
                        "uses": [
                            {"fn_0 {}".format(target): "(Predicates {})".format(term)}
                            for target, term in sorted(source_terms.items())
                        ],
                    },
                    {
                        "name": "fn_1",
                        "body": (
                            "(#1 (FlowPath source sink) (Select (PathSelect "
                            "(MethodCall (Var sink) getNode Args) (Var source) "
                            "(Var sink) (Message #0))))"
                        ),
                        "uses": [
                            {"fn_1 use{}".format(index): term}
                            for index, term in enumerate(path_terms)
                        ],
                    },
                    {
                        "name": "fn_2",
                        "body": (
                            "(And (MethodCall (MethodCall (Var call) getMethod Args) "
                            "hasName (Args (String #0))) (Eq (MethodCall (Var sink) "
                            "asExpr Args) (ArgumentSelection (Var call) 0)))"
                        ),
                        "uses": [
                            {
                                "fn_2 {}".format(name): (
                                    "(And (MethodCall (MethodCall (Var call) getMethod Args) "
                                    "hasName (Args (String {}))) (Eq (MethodCall (Var sink) "
                                    "asExpr Args) (ArgumentSelection (Var call) 0)))"
                                ).format(name)
                            }
                            for name in ["execute", "executeQuery", "executeUpdate"]
                        ],
                    },
                ],
            }
            candidates = _candidates_from_stitch(raw, provenance_path)["candidates"]
            by_name = {candidate["name"]: candidate for candidate in candidates}
            self.assertIn("java_active_threat_model_source", by_name)
            self.assertIn("java_remote_flow_source", by_name)
            self.assertIn("java_sql_statement_execution_sink", by_name)
            self.assertIn("java_path_query_scaffold_template", next(
                candidate["name"] for candidate in candidates
                if candidate["schema"] == "java_path_query_scaffold_template_v1"
            ))
            self.assertEqual(by_name["java_sql_statement_execution_sink"]["kind"], "codeql_helper")
            self.assertTrue(by_name["java_sql_statement_execution_sink"]["rewrite_eligible"])
            self.assertFalse(next(
                candidate for candidate in candidates
                if candidate["schema"] == "java_path_query_scaffold_template_v1"
            )["rewrite_eligible"])

    def test_codeql_pack_ingestion_emits_query_and_library_terms(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / "java-queries"
            query_dir = pack / "Security" / "CWE" / "CWE-078"
            experimental_dir = pack / "experimental" / "Security" / "CWE" / "CWE-078"
            library_dir = pack / ".codeql" / "libraries" / "codeql" / "java-all" / "9.0.0" / "semmle" / "code" / "java" / "security"
            query_dir.mkdir(parents=True)
            experimental_dir.mkdir(parents=True)
            library_dir.mkdir(parents=True)
            (query_dir / "ExecTainted.ql").write_text(
                """/**
 * @name Uncontrolled command line
 * @kind path-problem
 * @id java/command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 */
import java
import semmle.code.java.security.CommandLineQuery
import InputToArgumentToExecFlow::PathGraph

from InputToArgumentToExecFlow::PathNode source, InputToArgumentToExecFlow::PathNode sink, Expr execArg
where execIsTainted(source, sink, execArg)
select execArg, source, sink, "This command line depends on a $@.", source.getNode(), "user-provided value"
"""
            )
            (experimental_dir / "ExecTainted.ql").write_text(
                """/**
 * @name Experimental command line
 * @kind path-problem
 * @id java/command-line-injection-experimental
 * @tags security
 *       experimental
 *       external/cwe/cwe-078
 */
import java
deprecated import CommandInjectionRuntimeExec
deprecated import ExecUserFlow::PathGraph

from ExecUserFlow::PathNode source, ExecUserFlow::PathNode sink
where ExecUserFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Experimental command injection."
"""
            )
            (experimental_dir / "CommandInjectionRuntimeExec.qll").write_text(
                """module ExecUserConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CommandInjectionSink }
}
module ExecUserFlow = TaintTracking::Global<ExecUserConfig>;
"""
            )
            (library_dir / "CommandLineQuery.qll").write_text(
                """import java
module InputToArgumentToExecFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof ActiveThreatModelSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof CommandInjectionSink }
  predicate isBarrier(DataFlow::Node node) { node instanceof CommandInjectionSanitizer }
}
module InputToArgumentToExecFlow = TaintTracking::Global<InputToArgumentToExecFlowConfig>;
predicate execIsTainted(InputToArgumentToExecFlow::PathNode source, InputToArgumentToExecFlow::PathNode sink, Expr execArg) {
  InputToArgumentToExecFlow::flowPath(source, sink) and
  argumentToExec(execArg, sink.getNode())
}
"""
            )
            result = write_codeql_pack_corpus(pack, Path(tmp) / "out", cwes=[78], include_experimental=True)
            programs = json.loads(Path(result["programs_path"]).read_text())
            joined = "\n".join(programs)
            self.assertEqual(len(programs), 4)
            self.assertIn("java_command_line_injection", joined)
            self.assertIn("java_command_line_injection_experimental", joined)
            self.assertIn("ActiveThreatModelSource", joined)
            self.assertIn("CommandInjectionSink", joined)
            self.assertIn("Concept", joined)
            self.assertNotIn('"', joined)

    def test_semantic_mine_emits_meaningful_concept_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sqir_paths = []
            for query_path in sorted((ROOT / "query_profiles" / "combined" / "java").glob("*.ql")):
                query = parse_query(query_path)
                path = tmp / "{}.json".format(query_path.stem)
                path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(path)
            result = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            mined = mine_semantic_candidates(
                [Path(result["provenance_path"])],
                tmp / "semantic" / "candidates.json",
            )
            self.assertGreater(mined["concepts"], 0)
            schemas = {candidate["schema"] for candidate in mined["candidates"]}
            self.assertIn("java_remote_source_kind_template_v1", schemas)
            self.assertIn("java_modeled_sink_helper_v1", schemas)
            self.assertIn("java_barrier_predicate_helper_v1", schemas)
            semantic_only = [
                candidate for candidate in mined["candidates"]
                if candidate["kind"] == "semantic_template"
            ]
            self.assertTrue(semantic_only)
            self.assertTrue(all(candidate["semantic_usefulness"] == "semantic" for candidate in semantic_only))

    def test_official_flow_profile_is_sqir_compatible(self):
        for query_path in sorted((ROOT / "query_profiles" / "official-flow" / "java").glob("*.ql")):
            query = parse_query(query_path)
            self.assertEqual(query.language, "java")
            self.assertTrue(query.metadata["id"].startswith("java/cyberstitch/official-"))
            self.assertIn("isSource", {p.name for p in query.config_modules[0].predicates})

    def test_combined_profile_is_sqir_compatible(self):
        queries = sorted((ROOT / "query_profiles" / "combined" / "java").glob("*.ql"))
        self.assertGreaterEqual(len(queries), 10)
        for query_path in queries:
            query = parse_query(query_path)
            self.assertEqual(query.language, "java")
            self.assertTrue(query.metadata["id"].startswith("java/cyberstitch/"))
            predicates = {p.name for p in query.config_modules[0].predicates}
            self.assertIn("isSource", predicates)
            self.assertIn("isSink", predicates)

    def test_official_expanded_profile_is_sqir_compatible_and_semantically_rich(self):
        queries = sorted((ROOT / "query_profiles" / "official-expanded" / "java").glob("*.ql"))
        self.assertEqual(len(queries), 22)
        rule_ids = []

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sqir_paths = []
            for query_path in queries:
                query = parse_query(query_path)
                rule_ids.append(query.metadata["id"])
                self.assertEqual(query.language, "java")
                self.assertTrue(query.metadata["id"].startswith("java/cyberstitch/"))
                self.assertTrue(
                    "external/cwe/cwe-078" in query.metadata.get("tags", "")
                    or "external/cwe/cwe-089" in query.metadata.get("tags", "")
                )
                predicates = {p.name for p in query.config_modules[0].predicates}
                self.assertIn("isSource", predicates)
                self.assertIn("isSink", predicates)
                path = tmp / "sqir" / "{}.json".format(query_path.stem)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(path)

            self.assertEqual(len(rule_ids), len(set(rule_ids)))
            result = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            provenance = json.loads(Path(result["provenance_path"]).read_text())
            targets = {
                (node["concept_kind"], node["target"])
                for program in provenance["programs"]
                for node in program["semantic_nodes"]
                if node["kind"] == "Concept"
            }
            self.assertIn(("SourceKind", "sourceNode:remote"), targets)
            self.assertIn(("SourceKind", "sourceNode:database"), targets)
            self.assertIn(("SourceKind", "sourceNode:environment"), targets)
            self.assertIn(("SinkKind", "sinkNode:command-injection"), targets)
            self.assertIn(("SinkKind", "sinkNode:environment-injection"), targets)
            self.assertIn(("SinkKind", "sinkNode:sql-injection"), targets)
            self.assertIn(("ModeledSinkType", "CommandInjectionSink"), targets)
            self.assertIn(("ModeledSinkType", "QueryInjectionSink"), targets)

            mined = mine_semantic_candidates(
                [Path(result["provenance_path"])],
                tmp / "semantic" / "candidates.json",
            )
            decisions = validate_candidates(
                tmp / "semantic" / "candidates.json",
                tmp / "validation" / "decisions.json",
                language="java",
            )
            self.assertGreaterEqual(mined["concepts"], 120)
            self.assertGreaterEqual(len(mined["candidates"]), 30)
            self.assertGreaterEqual(sum(1 for item in decisions if item["accepted"]), 15)
            self.assertGreaterEqual(sum(1 for item in decisions if item.get("accepted_for_lilo")), 30)

    def test_official_expanded_manifest_matches_full_manifest_with_expanded_rule_ids(self):
        base = json.loads(
            (ROOT / "benchmarks" / "owasp_cmdi_sqli_all_benchmarkjava.json").read_text()
        )
        expanded = json.loads(
            (
                ROOT
                / "benchmarks"
                / "owasp_cmdi_sqli_all_benchmarkjava_official_expanded.json"
            ).read_text()
        )
        rule_ids_by_cwe = expanded["seed_profile"]["rule_ids_by_cwe"]

        self.assertEqual(len(expanded["cases"]), 755)
        self.assertEqual(len(expanded["cases"]), len(base["cases"]))
        self.assertEqual(len(rule_ids_by_cwe["78"]), 11)
        self.assertEqual(len(rule_ids_by_cwe["89"]), 11)

        for base_case, expanded_case in zip(base["cases"], expanded["cases"]):
            for field in ["test_id", "file", "cwe", "category", "expected_vulnerable"]:
                self.assertEqual(expanded_case[field], base_case[field])
            expected_rule_ids = expanded_case["expected_rule_ids"]
            cwe_key = str(expanded_case["cwe"])
            self.assertEqual(set(expected_rule_ids), set(rule_ids_by_cwe[cwe_key]))
            self.assertGreater(len(expected_rule_ids), len(base_case["expected_rule_ids"]))

    def test_bounded_seed_manifest_generates_valid_semantic_inventory(self):
        manifest_path = ROOT / "query_profiles" / "bounded-java" / "seed_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        validation = validate_seed_manifest(manifest)
        self.assertTrue(validation["ok"], validation)
        self.assertGreaterEqual(validation["seeds"], 30)

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            generated_dir = tmp / "generated"
            summary = generate_seed_profile(manifest_path, generated_dir)
            self.assertEqual(summary["seeds"], validation["seeds"])

            sqir_paths = []
            combined_source_text = []
            combined_sink_text = []
            for query_path in sorted((generated_dir / "java").glob("*.ql")):
                query = parse_query(query_path)
                self.assertEqual(query.language, "java")
                predicates = {p.name: p for p in query.config_modules[0].predicates}
                self.assertIn("isSource", predicates)
                self.assertIn("isSink", predicates)
                combined_source_text.append(json.dumps(predicates["isSource"].expression))
                combined_sink_text.append(json.dumps(predicates["isSink"].expression))
                path = tmp / "sqir" / "{}.json".format(query_path.stem)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(path)

            self.assertIn("RemoteFlowSource", "\n".join(combined_source_text))
            self.assertIn("ActiveThreatModelSource", "\n".join(combined_source_text))
            self.assertIn("sourceNode", "\n".join(combined_source_text))
            self.assertIn("CommandInjectionSink", "\n".join(combined_sink_text))
            self.assertIn("QueryInjectionSink", "\n".join(combined_sink_text))
            self.assertIn("BasicDBObject", "\n".join(combined_sink_text))

            result = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            mined = mine_semantic_candidates(
                [Path(result["provenance_path"])],
                tmp / "semantic" / "candidates.json",
            )
            decisions = validate_candidates(
                tmp / "semantic" / "candidates.json",
                tmp / "validation" / "decisions.json",
                language="java",
            )
            rewrite_accepted = sum(1 for decision in decisions if decision["accepted"])
            lilo_accepted = sum(1 for decision in decisions if decision.get("accepted_for_lilo"))
            self.assertGreaterEqual(mined["concepts"], 150)
            self.assertGreaterEqual(rewrite_accepted, 20)
            self.assertGreaterEqual(lilo_accepted, 20)
            self.assertLessEqual(lilo_accepted, 50)

    def test_seed_discovery_score_ignores_expected_rule_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            sarif = Path(tmp) / "official.sarif"
            sarif.write_text(json.dumps({
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "java/command-line-injection",
                                "message": {"text": "official rule"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00078.java"
                                            },
                                            "region": {"startLine": 42},
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }))
            score = score_results_without_expected_rule_ids(
                sarif,
                ROOT / "benchmarks" / "owasp_curated_subset.json",
                cwe=78,
            )
            self.assertEqual(score["totals"][78], {"TP": 1, "FN": 0, "TN": 1, "FP": 0})

    def test_validate_accepts_reused_fixture_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "decisions.json"
            decisions = validate_candidates(ROOT / "fixtures" / "stitch_candidates.json", out)
            self.assertEqual([d["accepted"] for d in decisions], [True, True, False, False])

    def test_validate_keeps_semantic_template_out_of_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "candidates.json"
            out = Path(tmp) / "decisions.json"
            path.write_text(json.dumps({
                "candidates": [
                    {
                        "candidate_version": "cyberstitch-candidate-v2",
                        "name": "template",
                        "kind": "semantic_template",
                        "origin": "stitch",
                        "schema": "java_remote_source_parameterized_sink_template_v1",
                        "language": "java",
                        "body": "(Predicates)",
                        "use_sites": [{"query": "a.ql", "predicate": "isSink"}, {"query": "b.ql", "predicate": "isSink"}],
                        "rewrite_eligible": False,
                        "semantic_hash": "abc",
                        "semantic_validation": {"ok": True, "reasons": [], "evidence": {}},
                    }
                ]
            }))
            decisions = validate_candidates(path, out, language="java")
            self.assertFalse(decisions[0]["accepted"])
            self.assertIn("not rewrite eligible", decisions[0]["reasons"])
            self.assertTrue(decisions[0]["accepted_for_lilo"])
            self.assertEqual(decisions[0]["lilo_reasons"], [])

    def test_manifest_fixture_validates(self):
        result = validate_manifest(
            ROOT / "benchmarks" / "owasp_curated_subset.json",
            ROOT / "benchmarks" / "owasp-fixture",
            [78, 89],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["cases"]), 4)

    def test_rewrite_emits_helper_and_rewritten_queries(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            decisions = tmp / "decisions.json"
            validate_candidates(ROOT / "fixtures" / "stitch_candidates.json", decisions)
            result = rewrite_queries(decisions, ROOT / "queries", tmp / "rewritten")
            self.assertTrue(Path(result["helpers"]["javascript"]).exists())
            self.assertTrue(Path(result["helpers"]["java"]).exists())
            rewritten = Path(result["queries"]) / "remote-to-exec.ql"
            text = rewritten.read_text()
            self.assertIn("import cyberstitch_helpers", text)
            self.assertIn("CyberStitchHelpers::isRemoteRequestSource(source)", text)
            java_rewritten = Path(result["queries"]) / "java" / "owasp-cwe078-command.ql"
            java_text = java_rewritten.read_text()
            self.assertIn("import cyberstitch_helpers_java", java_text)
            self.assertIn("CyberStitchJavaHelpers::isRemoteFlowSource(source)", java_text)

    def test_llm_fixture_normalizes_to_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            query = parse_query(ROOT / "queries" / "java" / "owasp-cwe078-command.ql")
            sqir_path = tmp / "query.json"
            sqir_path.write_text(json.dumps(query.to_dict(), indent=2))
            result = write_corpus([sqir_path], tmp / "fcir" / "corpus.json")
            output = tmp / "llm" / "candidates.json"
            summary = run_llm_propose(
                result["provenance_path"],
                output,
                fixture_path=ROOT / "fixtures" / "llm_proposals.json",
            )
            data = json.loads(output.read_text())
            self.assertEqual(summary["candidates"], 1)
            self.assertEqual(data["candidates"][0]["origin"], "llm")
            self.assertEqual(data["candidates"][0]["schema"], "java_source_predicate_helper_v1")

    def test_lilo_loop_export_and_fixture_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sqir_paths = []
            for query_name in ["owasp-cwe078-command.ql", "owasp-cwe089-sql.ql"]:
                query = parse_query(ROOT / "queries" / "java" / query_name)
                sqir_path = tmp / "sqir" / query_name.replace(".ql", ".json")
                sqir_path.parent.mkdir(parents=True, exist_ok=True)
                sqir_path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(sqir_path)

            corpus = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            mine_semantic_candidates(
                [Path(corpus["provenance_path"])],
                tmp / "semantic" / "candidates.json",
            )
            validate_candidates(
                tmp / "semantic" / "candidates.json",
                tmp / "validation" / "decisions.json",
                language="java",
            )

            config = load_config(ROOT)
            config.results_dir = tmp
            exported = export_lilo_loop_input(config, tmp / "lilo-loop" / "input.json")
            names = {item["name"] for item in exported["library_items"]}
            self.assertIn("java_remote_flow_source", names)
            self.assertTrue(exported["concepts"])

            output = tmp / "lilo-loop" / "candidates.json"
            summary = run_llm_propose(
                corpus["provenance_path"],
                output,
                fixture_path=ROOT / "fixtures" / "lilo_loop_outputs.json",
                lilo_input_path=tmp / "lilo-loop" / "input.json",
            )
            data = json.loads(output.read_text())
            self.assertEqual(summary["autodoc"][0]["schema"], "autodoc_v1")
            self.assertTrue(data["groupings"])
            self.assertTrue(data["query_synthesis_hints"])
            self.assertTrue(data["ignored_outputs"])
            by_schema = {candidate["schema"]: candidate for candidate in data["candidates"]}
            self.assertEqual(by_schema["java_source_predicate_helper_v1"]["origin"], "lilo-loop")
            self.assertFalse(by_schema["raw_codeql_helper_v1"]["semantic_validation"]["ok"])

    def test_lilo_prompt_selection_is_ranked_and_keeps_rewrite_accepted(self):
        items = []
        for index in range(8):
            items.append(
                _lilo_item(
                    "zzz_fallback_{}".format(index),
                    role="HelperPredicate",
                    accepted=False,
                    accepted_for_lilo=False,
                    rewrite=False,
                    use_sites=1,
                )
            )
        for name in ["rewrite_b", "rewrite_a", "rewrite_c"]:
            items.append(
                _lilo_item(
                    name,
                    role="Source",
                    accepted=True,
                    accepted_for_lilo=True,
                    rewrite=True,
                    use_sites=3,
                )
            )
        items.append(
            _lilo_item(
                "lilo_only_sink",
                role="Sink",
                accepted=False,
                accepted_for_lilo=True,
                rewrite=False,
                use_sites=4,
            )
        )

        selected = select_lilo_prompt_inventory({"library_items": list(reversed(items))}, max_library_items=2)
        names = [item["name"] for item in selected]
        self.assertEqual(names[:3], ["rewrite_a", "rewrite_b", "rewrite_c"])
        self.assertNotIn("zzz_fallback_0", names)

    def test_lilo_prompt_rendering_is_compact(self):
        item = _lilo_item(
            "dangerous_candidate",
            role="Source",
            accepted=True,
            accepted_for_lilo=True,
            rewrite=True,
            use_sites=4,
        )
        item["predicate"] = "secretPredicateName"
        item["candidate"]["body"] = "predicate secretGeneratedBody(DataFlow::Node n) { any() }"
        item["candidate"]["candidate"] = {"nested": "NESTED_CANDIDATE_SENTINEL"}
        item["semantic_validation"] = {"ok": True, "evidence": {"large": "SEMANTIC_VALIDATION_SENTINEL"}}
        prompt = render_lilo_loop_prompt(
            {
                "domain": "codeql-java-security",
                "summary": {},
                "library_items": [item],
                "concepts": [],
                "prompt_options": {"max_use_site_examples": 2},
            }
        )
        self.assertIn("dangerous_candidate", prompt)
        self.assertIn("use_site_count", prompt)
        self.assertNotIn("secretGeneratedBody", prompt)
        self.assertNotIn("secretPredicateName", prompt)
        self.assertNotIn("NESTED_CANDIDATE_SENTINEL", prompt)
        self.assertNotIn("SEMANTIC_VALIDATION_SENTINEL", prompt)

    def test_lilo_prompt_partitioning_is_deterministic(self):
        items = [
            _lilo_item("source_a", role="Source", accepted=True, accepted_for_lilo=True, rewrite=True),
            _lilo_item("sink_a", role="Sink", accepted=True, accepted_for_lilo=True, rewrite=True),
            _lilo_item("barrier_a", role="Barrier", accepted=True, accepted_for_lilo=True, rewrite=True),
            _lilo_item("flow_a", role="HelperPredicate", accepted=False, accepted_for_lilo=True),
        ]
        concepts = [
            {
                "id": "concept:source",
                "query": "q.ql",
                "concept_kind": "SourceKind",
                "semantic_role": "SourceKind",
                "target": "RemoteFlowSource",
            },
            {
                "id": "concept:sink",
                "query": "q.ql",
                "concept_kind": "SinkKind",
                "semantic_role": "SinkKind",
                "target": "CommandInjectionSink",
            },
        ]
        lilo_input = {"library_items": items, "concepts": concepts, "summary": {}}
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            single = prepare_lilo_loop_partitions(
                lilo_input,
                tmp / "single",
                partition_mode="auto",
                prompt_byte_budget=100000,
            )
            self.assertEqual(single["partition_count"], 1)
            self.assertEqual(single["partitions"][0]["id"], "all")

            role = prepare_lilo_loop_partitions(
                lilo_input,
                tmp / "role",
                partition_mode="role",
                prompt_byte_budget=100000,
            )
            partition_ids = [partition["id"] for partition in role["partitions"]]
            self.assertEqual(partition_ids, ["sources", "sinks", "barriers", "flow_helpers"])
            seen = [
                item_id
                for partition in role["partitions"]
                for item_id in partition["library_item_ids"]
            ]
            self.assertEqual(sorted(seen), sorted(item["id"] for item in items))
            self.assertEqual(len(seen), len(set(seen)))

            role_again = prepare_lilo_loop_partitions(
                lilo_input,
                tmp / "role-again",
                partition_mode="role",
                prompt_byte_budget=100000,
            )
            self.assertEqual(
                [partition["library_item_ids"] for partition in role["partitions"]],
                [partition["library_item_ids"] for partition in role_again["partitions"]],
            )

    def test_lilo_loop_partitioned_fixture_merges_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sqir_paths = []
            for query_name in ["owasp-cwe078-command.ql", "owasp-cwe089-sql.ql"]:
                query = parse_query(ROOT / "queries" / "java" / query_name)
                sqir_path = tmp / "sqir" / query_name.replace(".ql", ".json")
                sqir_path.parent.mkdir(parents=True, exist_ok=True)
                sqir_path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(sqir_path)

            corpus = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            mine_semantic_candidates(
                [Path(corpus["provenance_path"])],
                tmp / "semantic" / "candidates.json",
            )
            validate_candidates(
                tmp / "semantic" / "candidates.json",
                tmp / "validation" / "decisions.json",
                language="java",
            )
            config = load_config(ROOT)
            config.results_dir = tmp
            exported = export_lilo_loop_input(config, tmp / "lilo-loop" / "input.json")
            active = dict(next(item for item in exported["library_items"] if item["name"] == "java_remote_flow_source"))
            active["id"] = "candidate:java_active_threat_model_source"
            active["name"] = "java_active_threat_model_source"
            active["validation"] = {"accepted": True, "accepted_for_lilo": True}
            active["candidate"] = dict(active["candidate"])
            active["candidate"]["name"] = "java_active_threat_model_source"
            exported["library_items"].append(active)
            (tmp / "lilo-loop" / "input.json").write_text(json.dumps(exported, indent=2))

            result = run_lilo_loop(
                provenance_path=corpus["provenance_path"],
                output_dir=tmp / "lilo-loop",
                input_path=tmp / "lilo-loop" / "input.json",
                mode="fixture",
                fixture_path=ROOT / "fixtures" / "lilo_loop_outputs.json",
                partition_mode="role",
                prompt_byte_budget=45000,
            )
            self.assertTrue((tmp / "lilo-loop" / "partitions.json").exists())
            self.assertTrue(json.loads((tmp / "lilo-loop" / "autodoc.json").read_text()))
            self.assertTrue(json.loads((tmp / "lilo-loop" / "groupings.json").read_text()))
            self.assertTrue(json.loads((tmp / "lilo-loop" / "query-synthesis-hints.json").read_text()))
            self.assertTrue(json.loads((tmp / "lilo-loop" / "ignored.json").read_text()))
            self.assertGreaterEqual(result["partition_count"], 1)

    def test_autodoc_eval_fixture_scores_conditions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sqir_paths = []
            for query_name in ["owasp-cwe078-command.ql", "owasp-cwe089-sql.ql"]:
                query = parse_query(ROOT / "queries" / "java" / query_name)
                sqir_path = tmp / "sqir" / query_name.replace(".ql", ".json")
                sqir_path.parent.mkdir(parents=True, exist_ok=True)
                sqir_path.write_text(json.dumps(query.to_dict(), indent=2))
                sqir_paths.append(sqir_path)

            corpus = write_corpus(sqir_paths, tmp / "fcir" / "corpus.json")
            mine_semantic_candidates(
                [Path(corpus["provenance_path"])],
                tmp / "semantic" / "candidates.json",
            )
            validate_candidates(
                tmp / "semantic" / "candidates.json",
                tmp / "validation" / "decisions.json",
                language="java",
            )
            autodoc_dir = tmp / "lilo-loop"
            autodoc_dir.mkdir(parents=True, exist_ok=True)
            (autodoc_dir / "autodoc.json").write_text(
                json.dumps(
                    [
                        {
                            "schema": "autodoc_v1",
                            "target_id": "candidate:java_remote_flow_source",
                            "display_name": "remote_flow_source",
                            "description": "Recognizes remote user-controlled Java flow sources.",
                            "rationale": "This is a stable source abstraction.",
                        }
                    ],
                    indent=2,
                )
            )

            config = load_config(ROOT)
            config.results_dir = tmp
            summary = run_autodoc_eval(
                config,
                source_results=tmp,
                output_dir=tmp / "autodoc-eval",
                mode="fixture",
                fixture_path=ROOT / "fixtures" / "autodoc_eval_responses.json",
                samples=1,
            )
            scores = summary["scores"]
            self.assertGreater(
                scores["autodoc_docstrings"]["aggregate_score"],
                scores["raw_names"]["aggregate_score"],
            )
            self.assertEqual(scores["autodoc_docstrings"]["parse_rate"], 1.0)
            conditions = json.loads((tmp / "autodoc-eval" / "conditions.json").read_text())
            self.assertNotIn("body", json.dumps(conditions))

    def test_autodoc_eval_parses_fenced_json(self):
        parsed = parse_response('Here is JSON:\\n```json\\n{"selected": ["candidate:x"]}\\n```')
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["data"]["selected"], ["candidate:x"])

    @unittest.skipUnless((ROOT.parent / "codeql" / "codeql").exists(), "CodeQL is not available")
    def test_codeql_check_compiles_rewritten_java_helpers(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            config = load_config(ROOT)
            config.results_dir = tmp
            config.sarif_dir = tmp / "sarif"
            config.codeql_database_dir = tmp / "codeql-dbs"
            decisions = tmp / "decisions.json"
            validate_candidates(ROOT / "fixtures" / "stitch_candidates.json", decisions, language="java")
            rewrite_queries(decisions, ROOT / "queries", tmp / "rewritten", target_language="java")
            result = run_codeql_check(config, decisions_path=decisions, rewritten_dir=tmp / "rewritten", target_language="java")
            self.assertTrue(result["ok"], result["final"]["stderr"])

    def test_score_manifest_cases(self):
        score = score_sarif(
            ROOT / "fixtures" / "sample_owasp.sarif",
            ROOT / "benchmarks" / "owasp_curated_subset.json",
        )
        self.assertEqual(score["totals"][78], {"TP": 1, "FN": 0, "TN": 1, "FP": 0})
        self.assertEqual(score["totals"][89], {"TP": 1, "FN": 0, "TN": 1, "FP": 0})


def _write_temp_query(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".ql", delete=False)
    try:
        handle.write(text)
        return Path(handle.name)
    finally:
        handle.close()


if __name__ == "__main__":
    unittest.main()

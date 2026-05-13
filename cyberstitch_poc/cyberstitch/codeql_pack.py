import json
import re
from pathlib import Path

from .fcir import FCIR_VERSION, _hash_token, _symbol
from .semantic import (
    semantic_concepts_for_codeql_library,
    semantic_concepts_for_codeql_query,
)


SUPPORTED_CWE_DIRS = {
    78: Path("Security/CWE/CWE-078"),
    89: Path("Security/CWE/CWE-089"),
}

EXPERIMENTAL_CWE_DIRS = {
    78: Path("experimental/Security/CWE/CWE-078"),
    89: Path("experimental/Security/CWE/CWE-089"),
}

SUPPORT_LIBRARY_NAMES = [
    "FlowSources",
    "CommandLineQuery",
    "ExternalProcess",
    "CommandArguments",
    "TaintedEnvironmentVariableQuery",
    "QueryInjection",
    "SqlInjectionQuery",
]

METADATA_RE = re.compile(r"^\s*\*\s*@([A-Za-z0-9_.-]+)\s+(.*?)\s*$", re.MULTILINE)
IMPORT_RE = re.compile(
    r"^\s*(?:(?:private|deprecated)\s+)*import\s+(.+?)\s*$", re.MULTILINE
)
MODULE_RE = re.compile(
    r"^\s*(?:private\s+|deprecated\s+)*module\s+(\w+)\s+implements\s+([\w:]+)\s*\{(.*?)^\s*\}",
    re.DOTALL | re.MULTILINE,
)
FLOW_ALIAS_RE = re.compile(
    r"^\s*(?:private\s+|deprecated\s+)*module\s+(\w+)\s*=\s*(\w+)::(\w+)<(\w+)>;\s*$",
    re.MULTILINE,
)
PREDICATE_RE = re.compile(
    r"^\s*(?:private\s+|cached\s+|deprecated\s+|query\s+)*predicate\s+(\w+)\s*\((.*?)\)\s*\{(.*?)^\s*\}",
    re.DOTALL | re.MULTILINE,
)


def write_codeql_pack_corpus(pack_root, output_dir, cwes=(78, 89), include_experimental=False):
    java_queries_root = find_java_queries_pack(pack_root)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    programs_path = output_dir / "programs.json"
    provenance_path = output_dir / "provenance.json"

    programs = []
    provenance = []
    seen_libraries = set()
    for cwe_dir, cwe, tier in _query_dirs(java_queries_root, cwes, include_experimental):
        for query_path in sorted(cwe_dir.glob("*.ql")):
            program_id = "codeql_q{}".format(len(programs))
            program, entry, imports = _query_to_program(query_path, int(cwe), program_id, tier)
            programs.append(program)
            provenance.append(entry)
            for import_name in imports:
                library_path = _resolve_library(java_queries_root, query_path.parent, import_name)
                if not library_path or library_path in seen_libraries:
                    continue
                seen_libraries.add(library_path)
                lib_program_id = "codeql_lib{}".format(len(programs))
                lib_program, lib_entry = _library_to_program(library_path, lib_program_id)
                programs.append(lib_program)
                provenance.append(lib_entry)
    for library_path in _support_libraries(java_queries_root):
        if library_path in seen_libraries:
            continue
        seen_libraries.add(library_path)
        lib_program_id = "codeql_lib{}".format(len(programs))
        lib_program, lib_entry = _library_to_program(library_path, lib_program_id)
        programs.append(lib_program)
        provenance.append(lib_entry)

    programs_path.write_text(json.dumps(programs, indent=2))
    provenance_path.write_text(
        json.dumps(
            {
                "format": "cyberstitch-codeql-pack-provenance",
                "version": FCIR_VERSION,
                "java_queries_root": str(java_queries_root),
                "include_experimental": include_experimental,
                "programs_file": programs_path.name,
                "programs": provenance,
            },
            indent=2,
        )
    )
    return {
        "programs": programs,
        "provenance": provenance,
        "programs_path": str(programs_path),
        "provenance_path": str(provenance_path),
        "java_queries_root": str(java_queries_root),
        "include_experimental": include_experimental,
    }


def find_java_queries_pack(pack_root):
    root = Path(pack_root).resolve()
    if (root / "Security" / "CWE").exists():
        return root
    candidates = sorted((root / "qlpacks" / "codeql" / "java-queries").glob("*"))
    candidates.extend(sorted(root.glob("codeql/java-queries/*")))
    candidates.extend(sorted(root.glob("java-queries/*")))
    candidates = [item for item in candidates if (item / "Security" / "CWE").exists()]
    if not candidates:
        raise FileNotFoundError("Could not find a codeql/java-queries pack under {}".format(root))
    return candidates[-1]


def _query_dirs(java_queries_root, cwes, include_experimental):
    for cwe in cwes:
        cwe = int(cwe)
        cwe_dir = java_queries_root / SUPPORTED_CWE_DIRS[cwe]
        if not cwe_dir.exists():
            raise FileNotFoundError("CodeQL Java query directory not found: {}".format(cwe_dir))
        yield cwe_dir, cwe, "official"
        if include_experimental and cwe in EXPERIMENTAL_CWE_DIRS:
            experimental_dir = java_queries_root / EXPERIMENTAL_CWE_DIRS[cwe]
            if experimental_dir.exists():
                yield experimental_dir, cwe, "experimental"


def _query_to_program(path, cwe, program_id, tier):
    text = path.read_text()
    metadata = {key: value for key, value in METADATA_RE.findall(text)}
    imports = [item for item in IMPORT_RE.findall(text) if not item.endswith("::PathGraph")]
    from_clause = _section_between(text, "from", "where")
    where_clause = _section_between(text, "where", "select")
    select_clause = _section_after(text, "select")
    variables = _variables_to_term(from_clause)
    where = _clause_to_term("Where", where_clause)
    select = _select_to_term(select_clause)
    import_terms = " ".join("(Import {})".format(_symbol(item, "import")) for item in imports)
    kind = metadata.get("kind", "unknown")
    rule_id = metadata.get("id", path.stem)
    semantic_nodes = [
        {
            "id": "{}:query".format(program_id),
            "kind": "CodeQLQuery",
            "role": kind,
            "name": rule_id,
            "target": "CWE-{}".format(cwe),
            "term": "",
            "source_hash": _hash_text(text),
            "source": {"path": str(path), "span": None},
        }
    ]
    semantic_nodes.extend(
        semantic_concepts_for_codeql_query(
            path,
            metadata,
            cwe,
            program_id,
            imports,
            {"from": from_clause, "where": where_clause, "select": select_clause},
            tier,
        )
    )
    concept_terms = " ".join(node["term"] for node in semantic_nodes if node.get("kind") == "Concept")
    program = (
        "(CodeQLQuery (FCIRVersion {}) (ProgramId {}) (Language java) (RuleId {}) "
        "(CWE CWE_{:03d}) (Tier {}) (Kind {}) (Imports {}) (From {}) {} {} (Concepts {}))"
    ).format(
        _symbol(FCIR_VERSION, "version"),
        _symbol(program_id, "program"),
        _symbol(rule_id, "rule"),
        cwe,
        _symbol(tier, "tier"),
        _symbol(kind, "kind"),
        import_terms,
        variables,
        where,
        select,
        concept_terms,
    )
    semantic_nodes[0]["term"] = program
    return (
        program,
        {
            "program_id": program_id,
            "kind": "CodeQLPackQuery",
            "name": str(path),
            "language": "java",
            "cwe": cwe,
            "rule_id": rule_id,
            "tier": tier,
            "experimental": tier == "experimental",
            "source_hash": _hash_text(text),
            "imports": imports,
            "clauses": {"from": from_clause, "where": where_clause, "select": select_clause},
            "program": program,
            "semantic_nodes": semantic_nodes,
            "term_index": _term_index(semantic_nodes),
        },
        imports,
    )


def _library_to_program(path, program_id):
    text = path.read_text()
    configs = []
    semantic_nodes = []
    for name, signature, body in MODULE_RE.findall(text):
        config_term = _config_to_term(name, signature, body)
        configs.append(config_term)
        semantic_nodes.append(
            {
                "id": "{}:config:{}".format(program_id, name),
                "kind": "ConfigModule",
                "role": "FlowConfig",
                "name": name,
                "target": signature,
                "term": config_term,
                "source_hash": _hash_text(body),
                "source": {"path": str(path), "span": None},
            }
        )
    semantic_nodes.extend(semantic_concepts_for_codeql_library(path, text, program_id))
    flows = []
    for flow_name, framework, kind, config_name in FLOW_ALIAS_RE.findall(text):
        flow_term = "(Flow {} {} {} {})".format(
            _symbol(framework, "framework"),
            _symbol(kind, "flowkind"),
            _symbol(config_name, "config"),
            _symbol(flow_name, "flow"),
        )
        flows.append(flow_term)
        semantic_nodes.append(
            {
                "id": "{}:flow:{}".format(program_id, flow_name),
                "kind": "Flow",
                "role": kind,
                "name": flow_name,
                "target": config_name,
                "term": flow_term,
                "source_hash": "",
                "source": {"path": str(path), "span": None},
            }
        )
    predicates = []
    for predicate_name, params, body in PREDICATE_RE.findall(text):
        if predicate_name in {"isSource", "isSink", "isBarrier", "isAdditionalFlowStep"}:
            continue
        predicate_term = "(HelperPredicate {} (Params {}) {})".format(
            _symbol(predicate_name, "predicate"),
            _params_to_term(params),
            _body_features_to_term(body),
        )
        predicates.append(predicate_term)
        semantic_nodes.append(
            {
                "id": "{}:predicate:{}".format(program_id, predicate_name),
                "kind": "HelperPredicate",
                "role": "Helper",
                "name": predicate_name,
                "target": "",
                "term": predicate_term,
                "source_hash": _hash_text(body),
                "source": {"path": str(path), "span": None},
            }
        )

    concepts = " ".join(node["term"] for node in semantic_nodes if node.get("kind") == "Concept")
    program = "(CodeQLLibrary (FCIRVersion {}) (ProgramId {}) (Library {}) (Configs {}) (Flows {}) (Predicates {}) (Concepts {}))".format(
        _symbol(FCIR_VERSION, "version"),
        _symbol(program_id, "program"),
        _symbol(_library_name(path), "library"),
        " ".join(configs),
        " ".join(flows),
        " ".join(predicates),
        concepts,
    )
    semantic_nodes.insert(
        0,
        {
            "id": "{}:library".format(program_id),
            "kind": "CodeQLLibrary",
            "role": "Library",
            "name": _library_name(path),
            "target": "",
            "term": program,
            "source_hash": _hash_text(text),
            "source": {"path": str(path), "span": None},
        },
    )
    return (
        program,
        {
            "program_id": program_id,
            "kind": "CodeQLPackLibrary",
            "name": str(path),
            "language": "java",
            "source_hash": _hash_text(text),
            "program": program,
            "semantic_nodes": semantic_nodes,
            "term_index": _term_index(semantic_nodes),
        },
    )


def _config_to_term(name, signature, body):
    roles = []
    for predicate_name, role_name in [
        ("isSource", "Source"),
        ("isSink", "Sink"),
        ("isBarrier", "Barrier"),
        ("isAdditionalFlowStep", "AdditionalFlowStep"),
    ]:
        predicate_body = _predicate_body(body, predicate_name)
        if not predicate_body:
            continue
        roles.append(
            "({} {})".format(
                role_name,
                " ".join("(Target {})".format(_symbol(target, "target")) for target in _semantic_targets(predicate_body)),
            )
        )
    return "(ConfigModule {} {} (Roles {}))".format(
        _symbol(name, "config"), _symbol(signature, "sig"), " ".join(roles)
    )


def _predicate_body(text, predicate_name):
    pattern = re.compile(
        r"(?:private\s+|cached\s+|deprecated\s+|query\s+)*predicate\s+{}\s*\([^)]*\)\s*\{{(.*?)\}}".format(
            re.escape(predicate_name)
        ),
        re.DOTALL | re.MULTILINE,
    )
    match = pattern.search(text)
    return match.group(1) if match else ""


def _semantic_targets(body):
    targets = set(re.findall(r"\binstanceof\s+([A-Za-z_]\w*)", body))
    targets.update(re.findall(r"\bany\(([A-Za-z_]\w*)\s+\w+\)", body))
    targets.update(re.findall(r"\b(sinkNode|sourceNode|barrierNode)\s*\([^,]+,\s*\"([^\"]+)\"", body))
    flattened = []
    for target in targets:
        if isinstance(target, tuple):
            flattened.append("{}_{}".format(target[0], target[1]))
        else:
            flattened.append(target)
    return sorted(flattened) or [_hash_token(body, "Body")]


def _body_features_to_term(body):
    features = []
    for flow, source, sink in re.findall(r"(\w+)::flowPath\((\w+),\s*(\w+)\)", body):
        features.append("(FlowPath {} {} {})".format(_symbol(flow, "flow"), _symbol(source, "var"), _symbol(sink, "var")))
    for call in sorted(set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", body))):
        if call not in {"exists", "any", "predicate"}:
            features.append("(Call {})".format(_symbol(call, "call")))
    return "(BodyFeatures {})".format(" ".join(features) or "(BodyHash {})".format(_hash_token(body, "Body")))


def _variables_to_term(from_clause):
    variables = []
    for item in _split_top_level_char(from_clause, ","):
        pieces = item.strip().rsplit(" ", 1)
        if len(pieces) == 2:
            variables.append("(VarDecl {} {})".format(_symbol(pieces[0], "type"), _symbol(pieces[1], "var")))
    return "(Vars {})".format(" ".join(variables))


def _params_to_term(params):
    return " ".join(
        "(Param {} {})".format(_symbol(item.rsplit(" ", 1)[0], "type"), _symbol(item.rsplit(" ", 1)[1], "param"))
        for item in _split_top_level_char(params, ",")
        if item.strip() and len(item.strip().rsplit(" ", 1)) == 2
    )


def _clause_to_term(label, clause):
    calls = []
    for call, args in re.findall(r"\b([A-Za-z_]\w*)\s*\(([^()]*)\)", clause):
        calls.append(
            "(PredicateCall {} (Args {}))".format(
                _symbol(call, "call"),
                " ".join("(Arg {})".format(_symbol(arg.strip(), "arg")) for arg in args.split(",") if arg.strip()),
            )
        )
    for flow, source, sink in re.findall(r"(\w+)::flowPath\((\w+),\s*(\w+)\)", clause):
        calls.append("(FlowPath {} {} {})".format(_symbol(flow, "flow"), _symbol(source, "var"), _symbol(sink, "var")))
    if not calls:
        calls.append("(ClauseHash {})".format(_hash_token(clause, "Clause")))
    return "({} {})".format(label, " ".join(calls))


def _select_to_term(select_clause):
    return "(Select {})".format(
        " ".join(
            "(SelectItem {})".format(_symbol(item, "select"))
            for item in _split_top_level_char(select_clause, ",")
            if item.strip()
        )
    )


def _section_between(text, start, end):
    match = re.search(r"(?ms)^\s*{}\s+(.*?)^\s*{}\s+".format(start, end), text)
    return _clean_clause(match.group(1)) if match else ""


def _section_after(text, start):
    match = re.search(r"(?ms)^\s*{}\s+(.+?)\s*$".format(start), text)
    return _clean_clause(match.group(1)) if match else ""


def _clean_clause(text):
    return " ".join(line.strip() for line in text.strip().splitlines() if line.strip())


def _split_top_level_char(text, separator):
    parts = []
    start = 0
    depth = 0
    quote = None
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == separator:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def _resolve_library(java_queries_root, query_dir, import_name):
    if import_name.endswith("::PathGraph"):
        return None
    local_name = import_name.rsplit(".", 1)[-1]
    if "." not in import_name:
        local_path = Path(query_dir) / "{}.qll".format(local_name)
        if local_path.exists():
            return local_path
        matches = sorted(java_queries_root.glob("**/{}.qll".format(local_name)))
        return matches[-1] if matches else None
    if not import_name.startswith("semmle.code.java.security."):
        return None
    matches = sorted(
        (java_queries_root / ".codeql" / "libraries").glob(
            "codeql/java-all/*/semmle/code/java/security/{}.qll".format(local_name)
        )
    )
    return matches[-1] if matches else None


def _support_libraries(java_queries_root):
    libraries = []
    for name in SUPPORT_LIBRARY_NAMES:
        matches = sorted(
            (java_queries_root / ".codeql" / "libraries").glob(
                "codeql/java-all/*/semmle/code/java/**/{}.qll".format(name)
            )
        )
        if matches:
            libraries.append(matches[-1])
    return libraries


def _library_name(path):
    return Path(path).stem


def _hash_text(text):
    return _hash_token(text, "SRC")


def _term_index(semantic_nodes):
    return [
        {
            "term": node["term"],
            "semantic_node_id": node["id"],
            "kind": node["kind"],
            "role": node.get("role", ""),
            "target": node.get("target", ""),
        }
        for node in semantic_nodes
    ]

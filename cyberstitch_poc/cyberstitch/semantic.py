import hashlib
import json
import re
from pathlib import Path


CONCEPT_VERSION = "semantic-concepts-v1"

GENERIC_CODEQL_TYPES = {
    "Callable",
    "Class",
    "DataFlow::Node",
    "Expr",
    "Field",
    "Method",
    "MethodAccess",
    "MethodCall",
    "Node",
    "Type",
    "Variable",
}

ROLE_TO_CONCEPT = {
    "Source": "SourceKind",
    "Sink": "ModeledSinkType",
    "Barrier": "BarrierKind",
    "AdditionalFlowStep": "AdditionalFlowStep",
}

SEMANTIC_TEMPLATE_SCHEMAS = {
    "SourceKind": "java_remote_source_kind_template_v1",
    "ThreatModel": "java_remote_source_kind_template_v1",
    "SinkKind": "java_modeled_sink_helper_v1",
    "ModeledSinkType": "java_modeled_sink_helper_v1",
    "MethodCallSink": "java_modeled_sink_helper_v1",
    "BarrierKind": "java_barrier_predicate_helper_v1",
    "AdditionalFlowStep": "java_additional_flow_step_template_v1",
    "HelperPredicate": "java_codeql_helper_predicate_template_v1",
    "FlowConfigTemplate": "java_flow_config_template_v1",
    "PathQueryShape": "java_path_query_scaffold_template_v1",
    "ProblemQueryShape": "java_problem_query_shape_template_v1",
}

USEFUL_CONCEPTS = {
    "SourceKind",
    "ThreatModel",
    "SinkKind",
    "ModeledSinkType",
    "MethodCallSink",
    "BarrierKind",
    "AdditionalFlowStep",
    "HelperPredicate",
    "FlowConfigTemplate",
}


def semantic_concepts_for_query(query, program_id):
    """Extract typed semantic concepts from the supported SQIR query subset."""
    cwe = _cwe_from_metadata(query.metadata)
    rule_id = query.metadata.get("id", "")
    concepts = []
    predicate_targets = {}

    def add(kind, role, target, name="", attributes=None, source_hash="", source_path=None):
        concept = _concept_node(
            program_id=program_id,
            sequence=len(concepts),
            kind=kind,
            role=role,
            target=target,
            name=name or target,
            language=query.language,
            cwe=cwe,
            rule_id=rule_id,
            query_kind=query.metadata.get("kind", ""),
            attributes=attributes or {},
            source_hash=source_hash,
            source_path=source_path or query.source_path,
        )
        concepts.append(concept)
        return concept

    for flow in query.flow_modules:
        add(
            "FlowConfigTemplate",
            "Flow",
            flow.expression,
            name=flow.name,
            attributes={
                "framework": flow.framework,
                "kind": flow.kind,
                "config": flow.config,
            },
        )

    for module in query.config_modules:
        module_targets = {}
        for predicate in module.predicates:
            extracted = _predicate_concepts(predicate)
            predicate_targets[predicate.name] = [item["target"] for item in extracted]
            module_targets[predicate.role] = module_targets.get(predicate.role, []) + [
                item["target"] for item in extracted
            ]
            for item in extracted:
                add(
                    item["kind"],
                    predicate.role,
                    item["target"],
                    name=item.get("name", predicate.name),
                    attributes={
                        **item.get("attributes", {}),
                        "config": module.name,
                        "predicate": predicate.name,
                        "signature": module.signature,
                    },
                    source_hash=predicate.source_hash,
                )

        add(
            "FlowConfigTemplate",
            "FlowConfig",
            module.signature,
            name=module.name,
            attributes={
                "source_targets": "|".join(sorted(set(module_targets.get("Source", [])))),
                "sink_targets": "|".join(sorted(set(module_targets.get("Sink", [])))),
                "barrier_targets": "|".join(sorted(set(module_targets.get("Barrier", [])))),
                "additional_flow_step_targets": "|".join(
                    sorted(set(module_targets.get("AdditionalFlowStep", [])))
                ),
            },
        )

    add(
        "PathQueryShape",
        "PathProblem",
        query.path_query.flow_module,
        name="path-query",
        attributes={
            "source_var": query.path_query.source_var,
            "sink_var": query.path_query.sink_var,
            "select": query.path_query.select.get("kind", ""),
            "message_hash": _stable_hash(query.path_query.message)[:16],
        },
        source_hash=_stable_hash(query.path_query.message),
    )
    return concepts


def semantic_concepts_for_codeql_query(path, metadata, cwe, program_id, imports, clauses, tier):
    kind = metadata.get("kind", "unknown")
    concept_kind = "PathQueryShape" if kind == "path-problem" else "ProblemQueryShape"
    rule_id = metadata.get("id", Path(path).stem)
    concepts = [
        _concept_node(
            program_id,
            0,
            concept_kind,
            kind,
            rule_id,
            name=Path(path).name,
            language="java",
            cwe=cwe,
            rule_id=rule_id,
            query_kind=kind,
            attributes={
                "tier": tier,
                "imports": "|".join(imports),
                "where_helpers": "|".join(_predicate_names(clauses.get("where", ""))),
                "uses_flow_path": str("flowPath" in clauses.get("where", "")),
            },
            source_hash=_stable_hash(json.dumps(clauses, sort_keys=True)),
            source_path=str(path),
        )
    ]
    for name in _predicate_names(clauses.get("where", "")):
        if name in {"flowPath"}:
            continue
        concepts.append(
            _concept_node(
                program_id,
                len(concepts),
                "HelperPredicate",
                "HelperUse",
                name,
                name=name,
                language="java",
                cwe=cwe,
                rule_id=rule_id,
                query_kind=kind,
                attributes={"tier": tier, "clause": "where"},
                source_hash=_stable_hash(clauses.get("where", "")),
                source_path=str(path),
            )
        )
    return concepts


def semantic_concepts_for_codeql_library(path, text, program_id):
    path = Path(path)
    concepts = []
    cwe = _cwe_for_library(path.name)
    rule_id = path.stem

    def add(kind, role, target, name="", attributes=None, source_hash=""):
        concepts.append(
            _concept_node(
                program_id,
                len(concepts),
                kind,
                role,
                target,
                name=name or target,
                language="java",
                cwe=cwe,
                rule_id=rule_id,
                query_kind="library",
                attributes=attributes or {},
                source_hash=source_hash or _stable_hash(target),
                source_path=str(path),
            )
        )

    for module_name, signature, body in _module_blocks(text):
        role_targets = {}
        for predicate_name, role in [
            ("isSource", "Source"),
            ("isSink", "Sink"),
            ("isBarrier", "Barrier"),
            ("isAdditionalFlowStep", "AdditionalFlowStep"),
        ]:
            predicate_body = _predicate_body(body, predicate_name)
            if not predicate_body:
                continue
            targets = _targets_from_ql_body(predicate_body, role)
            role_targets[role] = targets
            for kind, target, attributes in targets:
                add(
                    kind,
                    role,
                    target,
                    name=predicate_name,
                    attributes={
                        **attributes,
                        "config": module_name,
                        "signature": signature,
                        "predicate": predicate_name,
                    },
                    source_hash=_stable_hash(predicate_body),
                )
        add(
            "FlowConfigTemplate",
            "FlowConfig",
            signature,
            name=module_name,
            attributes={
                "source_targets": "|".join(_target_values(role_targets.get("Source", []))),
                "sink_targets": "|".join(_target_values(role_targets.get("Sink", []))),
                "barrier_targets": "|".join(_target_values(role_targets.get("Barrier", []))),
                "additional_flow_step_targets": "|".join(
                    _target_values(role_targets.get("AdditionalFlowStep", []))
                ),
            },
            source_hash=_stable_hash(body),
        )

    for class_name, base_text in _class_extends(text):
        bases = [item.strip() for item in re.split(r",|instanceof", base_text) if item.strip()]
        for base in bases:
            if base == "RemoteFlowSource":
                add(
                    "SourceKind",
                    "Source",
                    class_name,
                    name=class_name,
                    attributes={"extends": base, "source_family": "RemoteFlowSource"},
                )
            elif base.endswith("Sink") or base in {"ApiSinkNode"}:
                add(
                    "ModeledSinkType",
                    "Sink",
                    class_name,
                    name=class_name,
                    attributes={"extends": base},
                )
            elif base.endswith("TaintStep"):
                add(
                    "AdditionalFlowStep",
                    "AdditionalFlowStep",
                    class_name,
                    name=class_name,
                    attributes={"extends": base},
                )

    for node_kind, label in re.findall(r"\b(sourceNode|sinkNode|barrierNode)\s*\([^,]+,\s*\"([^\"]+)\"", text):
        concept_kind = {
            "sourceNode": "SourceKind",
            "sinkNode": "SinkKind",
            "barrierNode": "BarrierKind",
        }[node_kind]
        role = {
            "sourceNode": "Source",
            "sinkNode": "Sink",
            "barrierNode": "Barrier",
        }[node_kind]
        add(
            concept_kind,
            role,
            "{}:{}".format(node_kind, label),
            attributes={"model_kind": label},
        )

    for source_type in sorted(set(re.findall(r"getSourceType\(\)\s*\{\s*result\s*=\s*\"([^\"]+)\"", text))):
        add(
            "SourceKind",
            "Source",
            "RemoteFlowSource.getSourceType:{}".format(source_type),
            attributes={"source_type": source_type, "source_family": "RemoteFlowSource"},
        )

    for predicate_name, params, body in _predicate_blocks(text):
        if predicate_name in {"isSource", "isSink", "isBarrier", "isAdditionalFlowStep"}:
            continue
        add(
            "HelperPredicate",
            "Helper",
            predicate_name,
            name=predicate_name,
            attributes={
                "params": _clean(params),
                "calls": "|".join(_predicate_names(body)),
                "uses_flow_path": str("flowPath" in body),
            },
            source_hash=_stable_hash(body),
        )
    return concepts


def mine_semantic_candidates(provenance_paths, output_path):
    """Emit deterministic concept-backed abstraction candidates.

    This augments STITCH with concepts that are semantically useful even when
    compression does not invent a rewriteable helper.
    """
    from .abstractions import (
        CANDIDATE_VERSION,
        codeql_helper_from_mapping,
        semantic_hash_for,
        term_index,
    )

    provenance = _merge_provenance(provenance_paths)
    index = term_index(provenance)
    candidates = []
    seen = set()

    for matches in index.values():
        predicate_matches = [
            match
            for match in matches
            if match.get("kind") == "Predicate"
            and match.get("role") in {"Source", "Sink", "Barrier"}
            and match.get("language") == "java"
        ]
        if len(predicate_matches) < 2:
            continue
        mapped = dict(predicate_matches[0])
        mapped["_matches"] = predicate_matches
        candidate = codeql_helper_from_mapping(
            {"name": "semantic_mine"},
            mapped,
            provenance,
            origin="semantic-mine",
            description="Deterministically mined complete Java {} predicate semantics.".format(
                mapped.get("role", "").lower()
            ),
        )
        candidate["mapping_status"] = "semantic-mine-exact-predicate"
        candidate["semantic_usefulness"] = "semantic"
        key = (candidate["schema"], candidate["semantic_hash"])
        if key not in seen:
            seen.add(key)
            candidates.append(candidate)

    concept_groups = {}
    for program in provenance.get("programs", []):
        for node in program.get("semantic_nodes", []):
            if node.get("kind") != "Concept":
                continue
            concept_kind = node.get("concept_kind") or node.get("role", "")
            if concept_kind not in USEFUL_CONCEPTS:
                continue
            key = (
                concept_kind,
                node.get("target", ""),
                node.get("cwe"),
                node.get("language", "java"),
            )
            concept_groups.setdefault(key, []).append((program, node))

    for (concept_kind, target, cwe, language), uses in sorted(
        concept_groups.items(),
        key=lambda item: tuple("" if value is None else str(value) for value in item[0]),
    ):
        official_backing = any(
            item[0].get("kind") in {"CodeQLPackLibrary", "CodeQLPackQuery"}
            for item in uses
        )
        if len(uses) < 2 and not official_backing:
            continue
        schema = SEMANTIC_TEMPLATE_SCHEMAS.get(concept_kind, "java_semantic_concept_template_v1")
        semantic_hash = semantic_hash_for(
            schema,
            {
                "concept_kind": concept_kind,
                "target": target,
                "cwe": cwe,
                "use_sites": sorted(_concept_use_site_key(program, node) for program, node in uses),
            },
        )
        name = "{}_{}".format(_candidate_slug(concept_kind, target), semantic_hash[:8])
        candidate = {
            "candidate_version": CANDIDATE_VERSION,
            "name": name,
            "kind": "semantic_template",
            "origin": "semantic-mine",
            "schema": schema,
            "language": language,
            "display_name": name,
            "description": _concept_description(concept_kind, target),
            "body": _concept_body(concept_kind, target, uses),
            "use_sites": [
                {
                    "query": Path(program.get("name", "")).name,
                    "predicate": node.get("attributes", {}).get("predicate", node.get("name", "")),
                    "semantic_node_id": node.get("id", ""),
                    "concept_kind": concept_kind,
                    "target": target,
                    "official_codeql": program.get("kind") in {"CodeQLPackLibrary", "CodeQLPackQuery"},
                }
                for program, node in uses
            ],
            "rewrite_eligible": False,
            "semantic_hash": semantic_hash,
            "semantic_role": concept_kind,
            "semantic_target": target,
            "semantic_usefulness": "semantic",
            "semantic_validation": {
                "ok": True,
                "reasons": [],
                "evidence": {
                    "num_uses": len(uses),
                    "official_codeql_backing": official_backing,
                    "concept_kind": concept_kind,
                    "cwe": cwe,
                },
            },
            "mapping_status": "semantic-concept-template",
        }
        key = (candidate["schema"], candidate["semantic_hash"])
        if key not in seen:
            seen.add(key)
            candidates.append(candidate)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = {
        "format": "cyberstitch-candidates-v2",
        "source": "semantic-mine",
        "provenance_files": [str(path) for path in provenance_paths],
        "concepts": sum(
            1
            for program in provenance.get("programs", [])
            for node in program.get("semantic_nodes", [])
            if node.get("kind") == "Concept"
        ),
        "candidates": candidates,
    }
    output_path.write_text(json.dumps(result, indent=2))
    return result


def merge_candidate_files(paths, output_path):
    candidates = []
    sources = []
    seen = set()
    for path in paths:
        path = Path(path)
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        sources.append(data.get("source", str(path)))
        for candidate in data.get("candidates", []):
            keys = [
                ("semantic", candidate.get("schema", ""), candidate.get("semantic_hash", "")),
                ("name", candidate.get("name", "")),
                (
                    "predicate",
                    candidate.get("helper_module", ""),
                    candidate.get("predicate", ""),
                ),
            ]
            keys = [key for key in keys if any(key[1:])]
            if any(key in seen for key in keys):
                continue
            seen.update(keys)
            candidates.append(candidate)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged = {
        "format": "cyberstitch-candidates-v2",
        "source": "merged",
        "sources": sources,
        "candidates": candidates,
    }
    output_path.write_text(json.dumps(merged, indent=2))
    return merged


def _predicate_concepts(predicate):
    expression = predicate.expression
    concepts = []
    if predicate.role == "Source":
        for type_name in _exists_types(expression):
            concept_kind = "ThreatModel" if type_name == "ActiveThreatModelSource" else "SourceKind"
            concepts.append({"kind": concept_kind, "target": type_name})
        for label in _node_labels(expression, "sourceNode"):
            concepts.append({"kind": "SourceKind", "target": "sourceNode:{}".format(label)})
    elif predicate.role == "Sink":
        for label in _node_labels(expression, "sinkNode"):
            concepts.append({"kind": "SinkKind", "target": "sinkNode:{}".format(label)})
        for type_name in _exists_types(expression):
            if type_name not in GENERIC_CODEQL_TYPES:
                concepts.append({"kind": "ModeledSinkType", "target": type_name})
        for qname in _qualified_names(expression):
            concepts.append({"kind": "MethodCallSink", "target": qname})
        method_names = sorted(set(_method_has_names(expression)))
        if method_names:
            concepts.append(
                {
                    "kind": "MethodCallSink",
                    "target": "method-names:{}".format("|".join(method_names)),
                    "attributes": {"method_names": "|".join(method_names)},
                }
            )
    elif predicate.role == "Barrier":
        for label in _node_labels(expression, "barrierNode"):
            concepts.append({"kind": "BarrierKind", "target": "barrierNode:{}".format(label)})
        for type_name in _exists_types(expression):
            if type_name not in GENERIC_CODEQL_TYPES:
                concepts.append({"kind": "BarrierKind", "target": type_name})
    else:
        for call in _predicate_calls(expression):
            concepts.append({"kind": "HelperPredicate", "target": call})
    return _dedupe_concepts(concepts)


def _targets_from_ql_body(body, role):
    targets = []
    concept_kind = ROLE_TO_CONCEPT.get(role, "HelperPredicate")
    for type_name in sorted(set(re.findall(r"\binstanceof\s+([A-Za-z_]\w*)", body))):
        if type_name in GENERIC_CODEQL_TYPES:
            continue
        kind = "ThreatModel" if type_name == "ActiveThreatModelSource" else concept_kind
        targets.append((kind, type_name, {}))
    for type_name in sorted(set(re.findall(r"\bany\(([A-Za-z_]\w*)\s+\w+\)", body))):
        if type_name in GENERIC_CODEQL_TYPES:
            continue
        targets.append((concept_kind, type_name, {}))
    for node_kind, label in re.findall(r"\b(sourceNode|sinkNode|barrierNode)\s*\([^,]+,\s*\"([^\"]+)\"", body):
        kind = {
            "sourceNode": "SourceKind",
            "sinkNode": "SinkKind",
            "barrierNode": "BarrierKind",
        }[node_kind]
        targets.append((kind, "{}:{}".format(node_kind, label), {"model_kind": label}))
    for call in _predicate_names(body):
        if call in {"exists", "any", "predicate", "none"}:
            continue
        if role == "AdditionalFlowStep" and call == "step":
            continue
        targets.append(("HelperPredicate", call, {"role_context": role}))
    return _dedupe_target_tuples(targets) or [(concept_kind, _hash_token(body, "Body"), {})]


def _concept_node(
    program_id,
    sequence,
    kind,
    role,
    target,
    name,
    language,
    cwe,
    rule_id,
    query_kind,
    attributes,
    source_hash,
    source_path,
):
    payload = {
        "kind": kind,
        "role": role,
        "target": target,
        "name": name,
        "language": language,
        "cwe": cwe,
        "rule_id": rule_id,
        "query_kind": query_kind,
        "attributes": attributes,
    }
    concept_hash = _stable_hash(json.dumps(payload, sort_keys=True, default=str))
    term = _concept_term(kind, role, target, language, cwe, rule_id, query_kind, attributes)
    return {
        "id": "{}:concept:{}:{}".format(program_id, sequence, _symbol(kind, "concept")),
        "kind": "Concept",
        "concept_kind": kind,
        "role": kind,
        "semantic_role": role,
        "name": name,
        "target": target,
        "language": language,
        "cwe": cwe,
        "rule_id": rule_id,
        "query_kind": query_kind,
        "attributes": attributes,
        "term": term,
        "source_hash": source_hash or concept_hash,
        "concept_hash": concept_hash,
        "source": {"path": source_path, "span": None},
    }


def _concept_term(kind, role, target, language, cwe, rule_id, query_kind, attributes):
    attr_terms = " ".join(
        "(Attr {} {})".format(_symbol(key, "attr"), _symbol(value, "value"))
        for key, value in sorted((attributes or {}).items())
        if value not in {None, ""}
    )
    cwe_text = " (CWE CWE_{:03d})".format(int(cwe)) if cwe else ""
    return (
        "(Concept {} (Role {}) (Target {}) (Language {}){} (RuleId {}) "
        "(QueryKind {}) (Attributes {}))"
    ).format(
        _symbol(kind, "concept"),
        _symbol(role, "role"),
        _symbol(target, "target"),
        _symbol(language, "lang"),
        cwe_text,
        _symbol(rule_id, "rule"),
        _symbol(query_kind, "kind"),
        attr_terms,
    )


def _merge_provenance(paths):
    programs = []
    for path in paths:
        path = Path(path)
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        programs.extend(data.get("programs", []))
    return {"format": "cyberstitch-merged-provenance", "programs": programs}


def _concept_use_site_key(program, node):
    return "{}:{}:{}".format(program.get("name", ""), node.get("id", ""), node.get("target", ""))


def _concept_description(concept_kind, target):
    return "Recognizes Java CodeQL {} semantics for {}.".format(concept_kind, target)


def _concept_body(concept_kind, target, uses):
    use_terms = " ".join(
        "(Use {} {})".format(_symbol(Path(program.get("name", "")).name, "query"), _symbol(node.get("id", ""), "node"))
        for program, node in uses
    )
    return "(SemanticConcept {} (Target {}) (Uses {}))".format(
        _symbol(concept_kind, "concept"),
        _symbol(target, "target"),
        use_terms,
    )


def _candidate_slug(concept_kind, target):
    base = "{}_{}".format(concept_kind, target)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", base)
    text = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")
    text = re.sub(r"_+", "_", text).lower()
    return "java_{}".format(text or "semantic_concept")


def _module_blocks(text):
    return re.findall(
        r"^\s*(?:private\s+|deprecated\s+)*module\s+(\w+)\s+implements\s+([\w:]+)\s*\{(.*?)^\s*\}",
        text,
        re.DOTALL | re.MULTILINE,
    )


def _predicate_blocks(text):
    return re.findall(
        r"^\s*(?:private\s+|cached\s+|deprecated\s+|query\s+)*predicate\s+(\w+)\s*\((.*?)\)\s*\{(.*?)^\s*\}",
        text,
        re.DOTALL | re.MULTILINE,
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


def _class_extends(text):
    return re.findall(
        r"^\s*(?:private\s+|abstract\s+|deprecated\s+)*class\s+(\w+)\s+extends\s+([^{]+)\{",
        text,
        re.MULTILINE,
    )


def _expr_children(node):
    children = []
    for value in node.values():
        if isinstance(value, dict) and "kind" in value:
            children.append(value)
        elif isinstance(value, list):
            children.extend(item for item in value if isinstance(item, dict) and "kind" in item)
    return children


def _exists_types(node):
    types = []
    if node.get("kind") == "exists":
        for variable in node.get("vars", []):
            if variable.get("type"):
                types.append(variable["type"])
    for child in _expr_children(node):
        types.extend(_exists_types(child))
    return types


def _node_labels(node, call_name):
    labels = []
    if node.get("kind") == "predicate_call" and node.get("name") == call_name:
        labels.extend(arg.get("value", "") for arg in node.get("args", []) if arg.get("kind") == "string")
    for child in _expr_children(node):
        labels.extend(_node_labels(child, call_name))
    return labels


def _qualified_names(node):
    names = []
    if node.get("kind") == "qualified_name_check":
        names.append(".".join(node.get("name_parts", [])))
    for child in _expr_children(node):
        names.extend(_qualified_names(child))
    return names


def _method_has_names(node):
    names = []
    if node.get("kind") == "method_call" and node.get("method") == "hasName":
        names.extend(arg.get("value", "") for arg in node.get("args", []) if arg.get("kind") == "string")
    for child in _expr_children(node):
        names.extend(_method_has_names(child))
    return names


def _predicate_calls(node):
    calls = []
    if node.get("kind") == "predicate_call":
        calls.append(node.get("name", ""))
    for child in _expr_children(node):
        calls.extend(_predicate_calls(child))
    return [item for item in calls if item]


def _predicate_names(text):
    return sorted(set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", text)))


def _target_values(targets):
    return sorted({item[1] for item in targets})


def _dedupe_concepts(concepts):
    seen = set()
    result = []
    for concept in concepts:
        key = (concept.get("kind"), concept.get("target"))
        if key in seen:
            continue
        seen.add(key)
        result.append(concept)
    return result


def _dedupe_target_tuples(targets):
    seen = set()
    result = []
    for kind, target, attributes in targets:
        key = (kind, target)
        if key in seen:
            continue
        seen.add(key)
        result.append((kind, target, attributes))
    return result


def _cwe_from_metadata(metadata):
    text = " ".join([metadata.get("id", ""), metadata.get("tags", "")])
    match = re.search(r"cwe[-/](\d+)|cwe-(\d+)", text, re.IGNORECASE)
    if match:
        return int(next(group for group in match.groups() if group))
    return None


def _cwe_for_library(name):
    if name in {"CommandLineQuery.qll", "ExternalProcess.qll", "CommandArguments.qll", "TaintedEnvironmentVariableQuery.qll"}:
        return 78
    if name in {"QueryInjection.qll", "SqlInjectionQuery.qll"}:
        return 89
    return None


def _clean(text):
    return " ".join(line.strip() for line in str(text).strip().splitlines() if line.strip())


def _symbol(value, prefix="sym"):
    text = str(value)
    text = re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_")
    text = re.sub(r"_+", "_", text)
    if not text:
        text = prefix
    if text[0].isdigit():
        text = "{}_{}".format(prefix, text)
    return text


def _stable_hash(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _hash_token(value, prefix="H"):
    return "{}_{}".format(prefix, _stable_hash(value)[:16])

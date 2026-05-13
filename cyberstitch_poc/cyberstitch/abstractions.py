import hashlib
import json
import re
from pathlib import Path

from .fcir import parse_sexpr
from .parser import format_expression


CANDIDATE_VERSION = "cyberstitch-candidate-v2"

REWRITE_SCHEMAS = {
    "legacy_codeql_helper_v1",
    "java_barrier_predicate_helper_v1",
    "java_source_predicate_helper_v1",
    "java_sink_predicate_helper_v1",
    "javascript_source_predicate_helper_v1",
    "javascript_sink_predicate_helper_v1",
}

TEMPLATE_SCHEMAS = {
    "java_remote_source_parameterized_sink_template_v1",
    "java_path_query_scaffold_template_v1",
    "java_additional_flow_step_template_v1",
    "java_barrier_predicate_helper_v1",
    "java_codeql_helper_predicate_template_v1",
    "java_flow_config_template_v1",
    "java_modeled_sink_helper_v1",
    "java_problem_query_shape_template_v1",
    "java_remote_source_kind_template_v1",
}


def load_provenance(path):
    if not path:
        return {}
    path = Path(path)
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def term_index(provenance):
    index = {}
    for program in provenance.get("programs", []):
        for item in program.get("term_index", []):
            key = normalize_term(item.get("term", ""))
            index.setdefault(key, []).append({
                **item,
                "program_id": program.get("program_id"),
                "language": program.get("language"),
                "program_name": program.get("name"),
                "rule_id": program.get("rule_id"),
                "program": program,
            })
    return index


def exact_semantic_match(body, index):
    matches = index.get(normalize_term(body), [])
    if not matches:
        return None
    mapped = dict(matches[0])
    mapped["_matches"] = matches
    return mapped


def candidates_from_stitch_item(stitch_item, provenance, index):
    body = stitch_item.get("body", "")
    mapped = exact_semantic_match(body, index)
    if mapped and mapped.get("kind") == "Predicate" and mapped.get("role") in {"Source", "Sink", "Barrier"}:
        return [codeql_helper_from_mapping(stitch_item, mapped, provenance, origin="stitch")]

    source_helpers = generalized_source_type_helpers(stitch_item, provenance, index)
    if source_helpers:
        return source_helpers

    template = parameterized_remote_source_sink_template(stitch_item, provenance, index)
    if template:
        candidates = [template]
        source_mapping = template.get("_source_mapping")
        if source_mapping:
            helper = codeql_helper_from_mapping(
                stitch_item,
                source_mapping,
                provenance,
                origin="stitch",
                derived_from=template["name"],
            )
            helper["description"] = (
                "Recognizes Java remote flow sources shared by STITCH's "
                "parameterized source/sink template."
            )
            helper["semantic_validation"]["evidence"]["derived_from_template"] = template["name"]
            candidates.append(helper)
        for candidate in candidates:
            candidate.pop("_source_mapping", None)
        return candidates

    sink_helper = argument0_method_name_sink_helper(stitch_item, provenance, index)
    if sink_helper:
        return [sink_helper]

    path_template = path_query_scaffold_template(stitch_item, provenance, index)
    if path_template:
        return [path_template]

    return [unmapped_stitch_candidate(stitch_item, "unsupported STITCH invention shape")]


def generalized_source_type_helpers(stitch_item, provenance, index):
    try:
        node = parse_sexpr(stitch_item.get("body", ""))
    except Exception:
        return None
    source_node = _single_source_predicate_template(node)
    if not source_node:
        return None

    by_target = {}
    for concrete in _concrete_use_terms(stitch_item):
        concrete_node = _single_predicate_from_concrete(concrete, "isSource")
        if not concrete_node:
            continue
        mapped = exact_semantic_match(sexpr_to_string(concrete_node), index)
        if not mapped or mapped.get("language") != "java" or mapped.get("role") != "Source":
            continue
        if len(mapped.get("_matches", [mapped])) < 2:
            continue
        by_target.setdefault(mapped.get("target", ""), mapped)

    helpers = []
    for target in sorted(by_target):
        mapped = by_target[target]
        helper = codeql_helper_from_mapping(
            stitch_item,
            mapped,
            provenance,
            origin="stitch",
            derived_from=stitch_item.get("name", "stitch_source_template"),
            description=(
                "Recognizes Java {} source semantics lifted from a STITCH "
                "generalized source-type template."
            ).format(target),
        )
        helper["mapping_status"] = "stitch-generalized-source-template"
        helper["semantic_validation"]["evidence"]["generalized_template"] = stitch_item.get("name", "")
        helpers.append(helper)
    return helpers or None


def argument0_method_name_sink_helper(stitch_item, provenance, index):
    if not _is_argument0_method_name_stitch_body(stitch_item.get("body", "")):
        return None
    stitch_method_names = sorted(set(_method_names_from_stitch_uses(stitch_item)))
    if not stitch_method_names:
        return None

    for matches in index.values():
        predicate_matches = [
            match for match in matches
            if match.get("kind") == "Predicate"
            and match.get("role") == "Sink"
            and match.get("language") == "java"
        ]
        if len(predicate_matches) < 2:
            continue
        mapped = dict(predicate_matches[0])
        mapped["_matches"] = predicate_matches
        predicate = sqir_predicate_for_mapping(mapped)
        if not predicate:
            continue
        method_names = _argument0_method_names(predicate.get("expression", {}))
        if method_names != stitch_method_names:
            continue
        return _argument0_method_name_sink_candidate(
            stitch_item,
            mapped,
            provenance,
            method_names,
        )
    return None


def path_query_scaffold_template(stitch_item, provenance, index):
    try:
        node = parse_sexpr(stitch_item.get("body", ""))
    except Exception:
        return None
    if not _is_path_query_scaffold_body(node):
        return None

    mappings = []
    seen = set()
    for concrete in _concrete_use_terms(stitch_item):
        mapped = exact_semantic_match(concrete, index)
        if not mapped or mapped.get("kind") != "PathQuery" or mapped.get("language") != "java":
            continue
        key = mapped.get("semantic_node_id")
        if key in seen:
            continue
        seen.add(key)
        mappings.append(mapped)
    if len(mappings) < 2:
        return None

    semantic_hash = semantic_hash_for(
        "java_path_query_scaffold_template_v1",
        {
            "body": normalize_term(stitch_item.get("body", "")),
            "num_uses": len(mappings),
        },
    )
    return {
        "candidate_version": CANDIDATE_VERSION,
        "name": "java_path_query_scaffold_template_{}".format(semantic_hash[:8]),
        "kind": "semantic_template",
        "origin": "stitch",
        "schema": "java_path_query_scaffold_template_v1",
        "language": "java",
        "display_name": "java_path_query_scaffold_template_{}".format(semantic_hash[:8]),
        "description": (
            "Recognizes the Java path-problem flowPath/select scaffold. It is "
            "not rewrite eligible because CodeQL path queries require the "
            "special PathGraph, PathNode, flowPath, and select shape."
        ),
        "body": stitch_item.get("body", ""),
        "use_sites": [
            {
                "query": Path(item.get("program_name", "")).name,
                "predicate": "path-query",
                "semantic_node_id": item.get("semantic_node_id", ""),
            }
            for item in mappings
        ],
        "rewrite_eligible": False,
        "semantic_hash": semantic_hash,
        "semantic_role": "PathProblemTemplate",
        "semantic_target": "CodeQL path-problem flowPath/select scaffold",
        "typed_holes": [
            {"id": "#0", "type": "MessageHashHole", "role": "PathQueryMessage"},
            {"id": "#1", "type": "PathQueryPrefixHole", "role": "PathQueryHeader"},
        ],
        "semantic_validation": {
            "ok": True,
            "reasons": [],
            "evidence": {
                "num_uses": len(mappings),
                "semantic_node_ids": [item.get("semantic_node_id", "") for item in mappings],
            },
        },
        "mapping_status": "semantic-template",
        "stitch": stitch_item,
    }


def parameterized_remote_source_sink_template(stitch_item, provenance, index):
    try:
        node = parse_sexpr(stitch_item.get("body", ""))
    except Exception:
        return None
    if not _is_list(node, "Predicates"):
        return None
    predicates = [item for item in node[1:] if _is_list(item, "Predicate")]
    if len(predicates) != 2:
        return None
    source_node = _find_predicate_node(predicates, "isSource")
    sink_node = _find_predicate_node(predicates, "isSink")
    if not source_node or not sink_node:
        return None
    if contains_hole(source_node):
        return None
    if not contains_hole(sink_node):
        return None

    source_term = sexpr_to_string(source_node)
    source_mapping = exact_semantic_match(source_term, index)
    if not source_mapping or source_mapping.get("role") != "Source":
        return None
    if source_mapping.get("language") != "java" or source_mapping.get("target") != "RemoteFlowSource":
        return None

    concrete_uses = []
    for use in stitch_item.get("uses", []):
        for concrete in use.values():
            parsed = _parse_concrete_predicates(concrete, index)
            if parsed:
                concrete_uses.append(parsed)
    if len(concrete_uses) < 2:
        return None
    if any(item["source_mapping"].get("semantic_node_id") not in {
        match.get("semantic_node_id") for match in source_mapping.get("_matches", [source_mapping])
    } for item in concrete_uses):
        return None
    if any(item["sink_mapping"].get("role") != "Sink" for item in concrete_uses):
        return None

    semantic_hash = semantic_hash_for(
        "java_remote_source_parameterized_sink_template_v1",
        {
            "source": source_mapping.get("target"),
            "sink_targets": sorted({item["sink_mapping"].get("target", "") for item in concrete_uses}),
            "holes": ["ExprHole", "HashHole", "RoleTargetHole"],
        },
    )
    target_summary = sorted({item["sink_mapping"].get("target", "") for item in concrete_uses})
    name = "java_remote_source_parameterized_sink_template_{}".format(semantic_hash[:8])
    return {
        "candidate_version": CANDIDATE_VERSION,
        "name": name,
        "kind": "semantic_template",
        "origin": "stitch",
        "schema": "java_remote_source_parameterized_sink_template_v1",
        "language": "java",
        "display_name": name,
        "description": "Shared RemoteFlowSource source predicate with a parameterized sink predicate.",
        "body": stitch_item.get("body", ""),
        "use_sites": [
            {
                "query": Path(item["sink_mapping"].get("program_name", "")).name,
                "predicate": item["sink_mapping"].get("name", "isSink"),
                "semantic_node_id": item["sink_mapping"].get("semantic_node_id", ""),
            }
            for item in concrete_uses
        ],
        "rewrite_eligible": False,
        "semantic_hash": semantic_hash,
        "semantic_role": "FlowConfigTemplate",
        "semantic_target": "RemoteFlowSource -> {}".format(", ".join(target_summary)),
        "typed_holes": [
            {"id": "#0", "type": "ExprHole", "role": "SinkPredicateBody"},
            {"id": "#1", "type": "HashHole", "role": "PredicateMetadata", "semantic": False},
            {"id": "#2", "type": "RoleTargetHole", "role": "SinkTarget"},
        ],
        "semantic_validation": {
            "ok": True,
            "reasons": [],
            "evidence": {
                "source_target": source_mapping.get("target"),
                "sink_targets": target_summary,
                "num_uses": len(concrete_uses),
            },
        },
        "mapping_status": "semantic-template",
        "stitch": stitch_item,
        "_source_mapping": source_mapping,
    }


def _parse_concrete_predicates(concrete, index):
    try:
        node = parse_sexpr(concrete)
    except Exception:
        return None
    if not _is_list(node, "Predicates"):
        return None
    predicates = [item for item in node[1:] if _is_list(item, "Predicate")]
    source_node = _find_predicate_node(predicates, "isSource")
    sink_node = _find_predicate_node(predicates, "isSink")
    if not source_node or not sink_node:
        return None
    source_mapping = exact_semantic_match(sexpr_to_string(source_node), index)
    sink_mapping = exact_semantic_match(sexpr_to_string(sink_node), index)
    if not source_mapping or not sink_mapping:
        return None
    return {"source_mapping": source_mapping, "sink_mapping": sink_mapping}


def codeql_helper_from_mapping(
    stitch_item,
    mapped,
    provenance,
    origin="stitch",
    derived_from=None,
    display_name=None,
    description=None,
):
    schema = schema_for_predicate(mapped)
    predicate_name = helper_predicate_name(mapped)
    body = codeql_body_for_mapping(predicate_name, mapped)
    semantic_hash = semantic_hash_for(
        schema,
        {
            "role": mapped.get("role", ""),
            "target": mapped.get("target", ""),
            "term": normalize_term(mapped.get("term", "")),
        },
    )
    name = helper_candidate_name(mapped, semantic_hash)
    evidence = {
        "semantic_node_id": mapped.get("semantic_node_id", ""),
        "role": mapped.get("role", ""),
        "target": mapped.get("target", ""),
        "num_exact_matches": len(mapped.get("_matches", [mapped])),
    }
    if derived_from:
        evidence["derived_from"] = derived_from
    return {
        "candidate_version": CANDIDATE_VERSION,
        "name": name,
        "kind": "codeql_helper",
        "origin": origin,
        "schema": schema,
        "language": mapped.get("language", "unknown"),
        "helper_module": helper_module(mapped.get("language", "unknown")),
        "predicate": predicate_name,
        "display_name": display_name or name,
        "description": description or description_for_mapping(mapped),
        "body": body,
        "use_sites": use_sites_for_program(mapped, provenance),
        "rewrite_eligible": schema in REWRITE_SCHEMAS,
        "semantic_hash": semantic_hash,
        "semantic_role": mapped.get("role", ""),
        "semantic_target": mapped.get("target", ""),
        "semantic_validation": {"ok": True, "reasons": [], "evidence": evidence},
        "mapping_status": "exact-term",
        "stitch": stitch_item,
    }


def candidate_from_llm_proposal(proposal, provenance):
    index = term_index(provenance)
    schema = proposal.get("schema", "")
    node_ids = proposal.get("semantic_node_ids") or []
    if schema in {"java_source_predicate_helper_v1", "java_sink_predicate_helper_v1"}:
        mapping = mapping_for_semantic_node_id(provenance, index, node_ids[0] if node_ids else "")
        if not mapping:
            return invalid_llm_candidate(proposal, "unknown semantic node id")
        expected_role = "Source" if "source" in schema else "Sink"
        if mapping.get("role") != expected_role or mapping.get("language") != "java":
            return invalid_llm_candidate(proposal, "semantic node does not match requested schema")
        candidate = codeql_helper_from_mapping(
            {"name": proposal.get("display_name") or schema},
            mapping,
            provenance,
            origin="llm",
            display_name=proposal.get("display_name"),
            description=proposal.get("description"),
        )
        candidate["llm_proposal"] = proposal
        candidate["rationale"] = proposal.get("rationale", "")
        return candidate
    if schema == "java_remote_source_parameterized_sink_template_v1":
        return {
            "candidate_version": CANDIDATE_VERSION,
            "name": "llm_java_remote_source_parameterized_sink_template_{}".format(
                semantic_hash_for(schema, proposal)[:8]
            ),
            "kind": "semantic_template",
            "origin": "llm",
            "schema": schema,
            "language": "java",
            "display_name": proposal.get("display_name", ""),
            "description": proposal.get("description", ""),
            "body": "",
            "use_sites": [],
            "rewrite_eligible": False,
            "semantic_hash": semantic_hash_for(schema, proposal),
            "semantic_role": "FlowConfigTemplate",
            "semantic_target": "",
            "semantic_validation": {
                "ok": bool(node_ids),
                "reasons": [] if node_ids else ["missing semantic node ids"],
                "evidence": {"semantic_node_ids": node_ids},
            },
            "mapping_status": "llm-schema-proposal",
            "llm_proposal": proposal,
            "rationale": proposal.get("rationale", ""),
        }
    return invalid_llm_candidate(proposal, "unsupported LLM abstraction schema")


def invalid_llm_candidate(proposal, reason):
    return {
        "candidate_version": CANDIDATE_VERSION,
        "name": proposal.get("display_name") or "invalid_llm_candidate",
        "kind": "llm_schema_proposal",
        "origin": "llm",
        "schema": proposal.get("schema", ""),
        "language": "unknown",
        "body": "",
        "use_sites": [],
        "rewrite_eligible": False,
        "semantic_hash": semantic_hash_for("invalid_llm_candidate", proposal),
        "semantic_validation": {"ok": False, "reasons": [reason], "evidence": {}},
        "mapping_status": "invalid",
        "llm_proposal": proposal,
    }


def mapping_for_semantic_node_id(provenance, index, semantic_node_id):
    for program in provenance.get("programs", []):
        for item in program.get("term_index", []):
            if item.get("semantic_node_id") != semantic_node_id:
                continue
            matches = index.get(normalize_term(item.get("term", "")), [])
            if not matches:
                return None
            mapped = dict(matches[0])
            mapped["_matches"] = matches
            return mapped
    return None


def normalize_candidate(candidate):
    candidate = dict(candidate)
    if candidate.get("candidate_version") == CANDIDATE_VERSION:
        candidate.setdefault("origin", "unknown")
        candidate.setdefault("schema", "")
        candidate.setdefault("rewrite_eligible", candidate.get("kind") == "codeql_helper")
        candidate.setdefault("semantic_validation", {"ok": False, "reasons": ["missing semantic validation"], "evidence": {}})
        candidate.setdefault("semantic_hash", semantic_hash_for(candidate.get("schema", ""), candidate))
        return candidate

    body = candidate.get("body", "")
    language = candidate.get("language", "unknown")
    role = "Source" if candidate.get("predicate", "").lower().endswith("source") else "Helper"
    candidate.update(
        {
            "candidate_version": CANDIDATE_VERSION,
            "origin": candidate.get("origin", "fixture"),
            "schema": candidate.get("schema", "legacy_codeql_helper_v1"),
            "rewrite_eligible": candidate.get("kind") == "codeql_helper",
            "semantic_hash": semantic_hash_for(
                "legacy_codeql_helper_v1",
                {
                    "language": language,
                    "body": body,
                    "use_sites": candidate.get("use_sites", []),
                },
            ),
            "semantic_role": candidate.get("semantic_role", role),
            "semantic_target": candidate.get("semantic_target", ""),
            "semantic_validation": {
                "ok": True,
                "reasons": [],
                "evidence": {"source": "legacy-compatible candidate"},
            },
        }
    )
    return candidate


def unmapped_stitch_candidate(stitch_item, reason):
    body = stitch_item.get("body", "")
    return {
        "candidate_version": CANDIDATE_VERSION,
        "name": stitch_item.get("name", "unmapped_stitch_invention"),
        "kind": "stitch_invention",
        "origin": "stitch",
        "schema": "unsupported_stitch_invention",
        "language": "unknown",
        "body": body,
        "use_sites": [],
        "rewrite_eligible": False,
        "semantic_hash": semantic_hash_for("unsupported_stitch_invention", body),
        "semantic_validation": {"ok": False, "reasons": [reason], "evidence": {}},
        "mapping_status": "unmapped",
        "stitch": stitch_item,
    }


def schema_for_predicate(mapped):
    language = mapped.get("language", "unknown")
    role = mapped.get("role", "")
    if language == "java" and role == "Source":
        return "java_source_predicate_helper_v1"
    if language == "java" and role == "Sink":
        return "java_sink_predicate_helper_v1"
    if language == "java" and role == "Barrier":
        return "java_barrier_predicate_helper_v1"
    if language == "javascript" and role == "Source":
        return "javascript_source_predicate_helper_v1"
    if language == "javascript" and role == "Sink":
        return "javascript_sink_predicate_helper_v1"
    return "legacy_codeql_helper_v1"


def helper_module(language):
    if language == "java":
        return "CyberStitchJavaHelpers"
    return "CyberStitchHelpers"


def helper_candidate_name(mapped, semantic_hash):
    language = mapped.get("language", "unknown")
    role = mapped.get("role", "").lower() or "helper"
    target = target_slug(mapped.get("target", ""))
    if language == "java" and mapped.get("role") == "Source":
        if target == "remote_flow_source":
            return "java_remote_flow_source"
        if target.endswith("_source"):
            return "java_{}".format(target)
        if target:
            return "java_{}_source".format(target)
    if target:
        return "{}_{}_{}".format(language, target, role)
    return "{}_{}_{}".format(language, role, semantic_hash[:8])


def helper_predicate_name(mapped):
    role = mapped.get("role", "")
    target = target_slug(mapped.get("target", ""))
    if mapped.get("language") == "java" and role == "Source" and target == "remote_flow_source":
        return "isRemoteFlowSource"
    if role == "Source" and target.endswith("_source"):
        return safe_predicate_name("is{}".format(_camel_stem(target)))
    if role == "Sink" and target.endswith("_sink"):
        return safe_predicate_name("is{}".format(_camel_stem(target)))
    if role == "Barrier":
        return safe_predicate_name("is{}Barrier".format(_camel_stem(target)))
    stem = "".join(part.capitalize() for part in target.split("_") if part)
    if not stem:
        stem = "".join(part.capitalize() for part in mapped.get("name", "helper").split("_") if part)
    suffix = "Sink" if role == "Sink" else "Source" if role == "Source" else "Helper"
    return safe_predicate_name("is{}{}".format(stem, suffix))


def description_for_mapping(mapped):
    role = mapped.get("role", "").lower() or "helper"
    target = mapped.get("target", "") or mapped.get("name", "")
    return "Recognizes {} {} semantics lifted from SQIR/FCIR.".format(target, role).strip()


def target_slug(target):
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(target))
    text = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")
    text = re.sub(r"_+", "_", text).lower()
    return text


def _camel_stem(slug):
    return "".join(part.capitalize() for part in str(slug).split("_") if part)


def safe_predicate_name(name):
    text = "".join(char if char.isalnum() or char == "_" else "_" for char in str(name))
    text = text.strip("_") or "fn_0"
    if text[0].isdigit():
        text = "fn_{}".format(text)
    return text


def codeql_body_for_mapping(predicate_name, mapped):
    predicate = sqir_predicate_for_mapping(mapped)
    if not predicate:
        return "predicate {}() {{ none() }}".format(predicate_name)
    params = ", ".join(
        "{} {}".format(param["type"], param["name"])
        for param in predicate.get("params", [])
    )
    return "predicate {}({}) {{\n  {}\n}}".format(
        predicate_name,
        params,
        format_expression(predicate["expression"]),
    )


def sqir_predicate_for_mapping(mapped):
    program = mapped.get("program", {})
    sqir = program.get("sqir") or {}
    semantic_id = mapped.get("semantic_node_id", "")
    parts = semantic_id.split(":")
    if len(parts) < 4 or parts[1] != "predicate":
        return None
    config_name, predicate_name = parts[2], parts[3]
    for module in sqir.get("config_modules", []):
        if module.get("name") != config_name:
            continue
        for predicate in module.get("predicates", []):
            if predicate.get("name") == predicate_name:
                return predicate
    return None


def use_sites_for_program(mapped, provenance):
    sites = []
    for match in mapped.get("_matches", [mapped]):
        program = match.get("program", {})
        name = Path(program.get("name", "")).name
        for node in program.get("semantic_nodes", []):
            if node.get("id") == match.get("semantic_node_id"):
                sites.append(
                    {
                        "query": name,
                        "predicate": node.get("name", ""),
                        "semantic_node_id": node.get("id", ""),
                    }
                )
    return sites


def normalize_term(term):
    text = " ".join(str(term).split())
    text = re.sub(r"\(Args\s*\)", "Args", text)
    return text


def semantic_hash_for(schema, payload):
    text = json.dumps({"schema": schema, "payload": payload}, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_list(node, label):
    return isinstance(node, list) and bool(node) and node[0] == label


def _find_predicate_node(predicates, name):
    for predicate in predicates:
        if len(predicate) > 1 and predicate[1] == name:
            return predicate
    return None


def contains_hole(node):
    if isinstance(node, str):
        return node.startswith("#")
    if isinstance(node, list):
        return any(contains_hole(item) for item in node)
    return False


def sexpr_to_string(node):
    if isinstance(node, list):
        return "({})".format(" ".join(sexpr_to_string(item) for item in node))
    return str(node)


def _concrete_use_terms(stitch_item):
    for use in stitch_item.get("uses", []):
        for concrete in use.values():
            yield concrete


def _single_source_predicate_template(node):
    if not _is_list(node, "Predicates"):
        return None
    predicates = [item for item in node[1:] if _is_list(item, "Predicate")]
    if len(predicates) != 1:
        return None
    source = _find_predicate_node(predicates, "isSource")
    if not source or not contains_hole(source):
        return None
    return source


def _single_predicate_from_concrete(concrete, name):
    try:
        node = parse_sexpr(concrete)
    except Exception:
        return None
    if _is_list(node, "Predicate") and len(node) > 1 and node[1] == name:
        return node
    if _is_list(node, "Predicates"):
        predicates = [item for item in node[1:] if _is_list(item, "Predicate")]
        if len(predicates) == 1:
            return _find_predicate_node(predicates, name)
    return None


def _is_argument0_method_name_stitch_body(body):
    try:
        node = parse_sexpr(body)
    except Exception:
        return False
    pattern = _argument0_method_name_pattern(node)
    return bool(pattern and pattern.get("method_name") == "#0")


def _method_names_from_stitch_uses(stitch_item):
    names = []
    for concrete in _concrete_use_terms(stitch_item):
        try:
            node = parse_sexpr(concrete)
        except Exception:
            continue
        pattern = _argument0_method_name_pattern(node)
        if pattern and pattern.get("method_name"):
            names.append(pattern["method_name"])
    return names


def _argument0_method_names(expression):
    node = expression
    if node.get("kind") == "exists":
        node = node.get("body", {})
    terms = node.get("terms", []) if node.get("kind") == "or" else [node]
    names = []
    binding = None
    for term in terms:
        pattern = _argument0_method_name_expr_pattern(term)
        if not pattern:
            return []
        current = (pattern["call_var"], pattern["sink_var"], pattern["argument_index"])
        if binding is None:
            binding = current
        elif binding != current:
            return []
        names.append(pattern["method_name"])
    return sorted(set(names))


def _argument0_method_name_expr_pattern(node):
    if node.get("kind") != "and":
        return None
    method_name = None
    has_name_call_var = None
    eq_call_var = None
    sink_var = None
    argument_index = None
    for term in node.get("terms", []):
        has_name = _method_has_name_expr(term)
        if has_name:
            method_name = has_name["method_name"]
            has_name_call_var = has_name["call_var"]
            continue
        eq = _sink_argument_eq_expr(term)
        if eq:
            sink_var = eq["sink_var"]
            argument_index = eq["argument_index"]
            eq_call_var = eq["call_var"]
    if has_name_call_var and eq_call_var and has_name_call_var != eq_call_var:
        return None
    call_var = has_name_call_var or eq_call_var
    if method_name and call_var and sink_var and argument_index == 0:
        return {
            "method_name": method_name,
            "call_var": call_var,
            "sink_var": sink_var,
            "argument_index": argument_index,
        }
    return None


def _argument0_method_name_pattern(node):
    if not _is_list(node, "And"):
        return None
    method_name = None
    for term in node[1:]:
        if _sexpr_method_has_name(term):
            method_name = _sexpr_method_has_name(term)
        elif not _sexpr_sink_argument0_eq(term):
            return None
    if method_name:
        return {"method_name": method_name}
    return None


def _method_has_name_expr(node):
    if (
        node.get("kind") == "method_call"
        and node.get("method") == "hasName"
        and len(node.get("args", [])) == 1
        and node["args"][0].get("kind") == "string"
    ):
        receiver = node.get("receiver", {})
        if receiver.get("kind") == "method_call" and receiver.get("method") == "getMethod":
            call = receiver.get("receiver", {})
            if call.get("kind") == "var":
                return {"method_name": node["args"][0]["value"], "call_var": call["name"]}
    return None


def _sink_argument_eq_expr(node):
    if node.get("kind") != "eq":
        return None
    return (
        _sink_argument_pair(node.get("left", {}), node.get("right", {}))
        or _sink_argument_pair(node.get("right", {}), node.get("left", {}))
    )


def _sink_argument_pair(sink_side, arg_side):
    if not (
        sink_side.get("kind") == "method_call"
        and sink_side.get("method") == "asExpr"
        and sink_side.get("receiver", {}).get("kind") == "var"
    ):
        return None
    if not (
        arg_side.get("kind") == "argument_selection"
        and arg_side.get("receiver", {}).get("kind") == "var"
    ):
        return None
    return {
        "sink_var": sink_side["receiver"]["name"],
        "call_var": arg_side["receiver"]["name"],
        "argument_index": arg_side.get("index"),
    }


def _sexpr_method_has_name(node):
    if not _is_list(node, "MethodCall") or len(node) < 4:
        return None
    if node[2] != "hasName":
        return None
    args = node[3]
    if not _is_list(args, "Args") or len(args) != 2:
        return None
    string_node = args[1]
    if _is_list(string_node, "String") and len(string_node) == 2:
        return string_node[1]
    return None


def _sexpr_sink_argument0_eq(node):
    if not _is_list(node, "Eq") or len(node) != 3:
        return False
    return _sexpr_sink_argument0_pair(node[1], node[2]) or _sexpr_sink_argument0_pair(node[2], node[1])


def _sexpr_sink_argument0_pair(sink_side, arg_side):
    return (
        _is_list(sink_side, "MethodCall")
        and len(sink_side) >= 3
        and sink_side[2] == "asExpr"
        and _is_list(arg_side, "ArgumentSelection")
        and len(arg_side) == 3
        and str(arg_side[2]) == "0"
    )


def _argument0_method_name_sink_candidate(stitch_item, mapped, provenance, method_names):
    predicate = sqir_predicate_for_mapping(mapped)
    params = ", ".join(
        "{} {}".format(param["type"], param["name"])
        for param in predicate.get("params", [])
    )
    if method_names == ["execute", "executeQuery", "executeUpdate"]:
        name = "java_sql_statement_execution_sink"
        predicate_name = "isSqlStatementExecutionSink"
        semantic_target = "method-names:execute|executeQuery|executeUpdate"
        description = (
            "Recognizes Java SQL statement execution sink semantics for first "
            "arguments to execute, executeQuery, and executeUpdate."
        )
    else:
        method_slug = "_".join(target_slug(name) for name in method_names)
        name = "java_method_{}_argument0_sink".format(method_slug)
        predicate_name = safe_predicate_name("is{}Argument0Sink".format(_camel_stem(method_slug)))
        semantic_target = "method-names:{}".format("|".join(method_names))
        description = "Recognizes Java first-argument method sink semantics."

    body = "predicate {}({}) {{\n  {}\n}}".format(
        predicate_name,
        params,
        format_expression(predicate["expression"]),
    )
    semantic_hash = semantic_hash_for(
        "java_sink_predicate_helper_v1",
        {
            "role": "Sink",
            "target": semantic_target,
            "method_names": method_names,
            "term": normalize_term(mapped.get("term", "")),
        },
    )
    return {
        "candidate_version": CANDIDATE_VERSION,
        "name": name,
        "kind": "codeql_helper",
        "origin": "stitch",
        "schema": "java_sink_predicate_helper_v1",
        "language": "java",
        "helper_module": helper_module("java"),
        "predicate": predicate_name,
        "display_name": name,
        "description": description,
        "body": body,
        "use_sites": use_sites_for_program(mapped, provenance),
        "rewrite_eligible": True,
        "semantic_hash": semantic_hash,
        "semantic_role": "Sink",
        "semantic_target": semantic_target,
        "semantic_validation": {
            "ok": True,
            "reasons": [],
            "evidence": {
                "method_names": method_names,
                "argument_index": 0,
                "num_exact_matches": len(mapped.get("_matches", [mapped])),
                "derived_from_subexpression": stitch_item.get("name", ""),
            },
        },
        "mapping_status": "stitch-lifted-subexpression",
        "stitch": stitch_item,
    }


def _is_path_query_scaffold_body(node):
    if not isinstance(node, list) or len(node) != 3:
        return False
    if not isinstance(node[0], str) or not node[0].startswith("#"):
        return False
    return _is_list(node[1], "FlowPath") and _is_list(node[2], "Select")

import json
from pathlib import Path

from .abstractions import REWRITE_SCHEMAS, TEMPLATE_SCHEMAS, normalize_candidate
from .manifest import validate_manifest
from .sqir import query_from_dict


def validate_candidates(candidate_path, output_path, language=None):
    with open(candidate_path) as handle:
        data = json.load(handle)

    decisions = []
    for candidate in data.get("candidates", []):
        candidate = normalize_candidate(candidate)
        if language and candidate.get("language", language) != language:
            continue
        reasons = validation_reasons(candidate)
        lilo_reasons = lilo_validation_reasons(candidate)

        decisions.append(
            {
                "candidate": candidate,
                "accepted": not reasons,
                "reasons": reasons,
                "accepted_for_lilo": not lilo_reasons,
                "lilo_reasons": lilo_reasons,
            }
        )
    decisions = apply_lilo_inventory_cap(decisions)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"decisions": decisions}, indent=2))
    return decisions


def validation_reasons(candidate):
    reasons = []
    if not candidate.get("name"):
        reasons.append("missing name")
    semantic_validation = candidate.get("semantic_validation") or {}
    if not semantic_validation.get("ok", False):
        semantic_reasons = semantic_validation.get("reasons") or ["semantic validation failed"]
        reasons.extend("semantic: {}".format(reason) for reason in semantic_reasons)
    if candidate.get("kind") != "codeql_helper":
        reasons.append("unsupported kind")
    if not candidate.get("rewrite_eligible", candidate.get("kind") == "codeql_helper"):
        reasons.append("not rewrite eligible")
    if candidate.get("schema") and candidate.get("schema") not in REWRITE_SCHEMAS:
        reasons.append("unsupported rewrite schema")
    if len(candidate.get("use_sites", [])) < 2:
        reasons.append("requires at least two use sites")
    if "predicate" not in candidate.get("body", ""):
        reasons.append("helper body must be a CodeQL predicate")
    syntax = candidate.get("codeql_syntax_validation")
    if isinstance(syntax, dict) and not syntax.get("ok", False):
        reasons.append("CodeQL syntax validation failed")
    return reasons


STRUCTURAL_TEMPLATE_SCHEMAS = {
    "java_flow_config_template_v1",
    "java_path_query_scaffold_template_v1",
    "java_problem_query_shape_template_v1",
}

LILO_INVENTORY_CAP = 50


def lilo_validation_reasons(candidate):
    reasons = []
    if not candidate.get("name"):
        reasons.append("missing name")
    semantic_validation = candidate.get("semantic_validation") or {}
    if not semantic_validation.get("ok", False):
        semantic_reasons = semantic_validation.get("reasons") or ["semantic validation failed"]
        reasons.extend("semantic: {}".format(reason) for reason in semantic_reasons)
    if candidate.get("language") != "java":
        reasons.append("only Java CodeQL candidates are in scope")
    if candidate.get("kind") not in {"codeql_helper", "semantic_template"}:
        reasons.append("unsupported LILO candidate kind")
    schema = candidate.get("schema", "")
    if schema not in REWRITE_SCHEMAS and schema not in TEMPLATE_SCHEMAS:
        reasons.append("unsupported LILO schema")
    if schema in STRUCTURAL_TEMPLATE_SCHEMAS:
        reasons.append("structural syntax-compression template")
    evidence = semantic_validation.get("evidence") or {}
    official_backing = bool(evidence.get("official_codeql_backing"))
    if len(candidate.get("use_sites", [])) < 2 and not official_backing:
        reasons.append("requires at least two use sites or official CodeQL backing")
    syntax = candidate.get("codeql_syntax_validation")
    if isinstance(syntax, dict) and not syntax.get("ok", False):
        reasons.append("CodeQL syntax validation failed")
    return reasons


def apply_lilo_inventory_cap(decisions, cap=LILO_INVENTORY_CAP):
    eligible = [
        index for index, item in enumerate(decisions)
        if item.get("accepted_for_lilo")
    ]
    if len(eligible) <= cap:
        return decisions
    keep = set(sorted(eligible, key=lambda index: _lilo_rank(decisions[index]))[:cap])
    for index in eligible:
        if index in keep:
            continue
        decisions[index]["accepted_for_lilo"] = False
        reasons = list(decisions[index].get("lilo_reasons", []))
        reasons.append("outside bounded LILO inventory cap")
        decisions[index]["lilo_reasons"] = reasons
    return decisions


def _lilo_rank(decision):
    candidate = decision["candidate"]
    role_priority = {
        "Source": 0,
        "Sink": 0,
        "Barrier": 0,
        "ModeledSinkType": 1,
        "SinkKind": 1,
        "MethodCallSink": 1,
        "BarrierKind": 2,
        "SourceKind": 3,
        "ThreatModel": 3,
        "AdditionalFlowStep": 4,
        "HelperPredicate": 5,
    }.get(candidate.get("semantic_role", ""), 9)
    validation = candidate.get("semantic_validation") or {}
    evidence = validation.get("evidence") or {}
    official = 0 if evidence.get("official_codeql_backing") else 1
    return (
        0 if decision.get("accepted") else 1,
        0 if candidate.get("kind") == "codeql_helper" else 1,
        role_priority,
        -len(candidate.get("use_sites", [])),
        official,
        candidate.get("name", ""),
    )


def refresh_decisions(decisions):
    refreshed = []
    for item in decisions:
        candidate = normalize_candidate(item["candidate"])
        reasons = validation_reasons(candidate)
        lilo_reasons = lilo_validation_reasons(candidate)
        refreshed.append(
            {
                "candidate": candidate,
                "accepted": not reasons,
                "reasons": reasons,
                "accepted_for_lilo": not lilo_reasons,
                "lilo_reasons": lilo_reasons,
            }
        )
    return apply_lilo_inventory_cap(refreshed)


def validate_sqir_files(sqir_paths):
    errors = []
    checked = 0
    for path in sqir_paths:
        checked += 1
        try:
            with open(path) as handle:
                query_from_dict(json.load(handle)).validate()
        except Exception as exc:
            errors.append("{}: {}: {}".format(path, type(exc).__name__, exc))
    return {"ok": not errors, "checked": checked, "errors": errors}


def validate_pipeline(config, candidate_path=None, decisions_path=None):
    manifest = validate_manifest(
        config.curated_subset_manifest, config.owasp_root, config.selected_cwes
    )
    sqir_root = config.results_dir / "sqir" / config.language
    if not sqir_root.exists():
        sqir_root = config.results_dir / "sqir"
    sqir = validate_sqir_files(sorted(sqir_root.rglob("*.json")))
    candidates = {"decisions": []}
    if candidate_path and Path(candidate_path).exists():
        decisions = validate_candidates(
            candidate_path,
            decisions_path or config.results_dir / "validation" / "decisions.json",
            language=config.language if config.language != "all" else None,
        )
        candidates = {
            "decisions": len(decisions),
            "accepted": sum(1 for item in decisions if item["accepted"]),
            "accepted_for_lilo": sum(1 for item in decisions if item.get("accepted_for_lilo")),
            "rejected": sum(1 for item in decisions if not item["accepted"]),
        }
    return {
        "ok": manifest["ok"] and sqir["ok"],
        "manifest": manifest,
        "sqir": sqir,
        "candidates": candidates,
    }

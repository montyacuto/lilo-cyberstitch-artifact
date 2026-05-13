import json
import re
from pathlib import Path

from .manifest import case_for_uri, manifest_cases


def normalize_sarif(path, cases=None):
    with open(path) as handle:
        data = json.load(handle)
    cases = cases or []
    normalized = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or result.get("rule", {}).get("id")
            message = result.get("message", {}).get("text", "")
            locations = result.get("locations", [])
            if locations:
                physical = locations[0].get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                uri = artifact.get("uri", "")
                line = region.get("startLine", 0)
            else:
                uri = ""
                line = 0
            case = case_for_uri(cases, uri) if cases else None
            test_id = case["test_id"] if case else _infer_test_id(uri, message)
            normalized.append(
                {
                    "rule_id": rule_id,
                    "file": uri,
                    "line": line,
                    "test_id": test_id,
                    "cwe": int(case["cwe"]) if case else _infer_cwe(rule_id, message),
                    "message": message,
                }
            )
    return normalized


def result_keys(path, cases=None):
    return {
        (
            item["rule_id"],
            item["file"],
            item["line"],
            item["test_id"],
            item["cwe"],
            item["message"],
        )
        for item in normalize_sarif(path, cases=cases)
    }


def compare_sarif(original_path, rewritten_path, manifest_path=None):
    cases = manifest_cases(manifest_path) if manifest_path else []
    original = result_keys(original_path, cases=cases)
    rewritten = result_keys(rewritten_path, cases=cases)
    return {
        "equivalent": original == rewritten,
        "missing": sorted(original - rewritten),
        "extra": sorted(rewritten - original),
    }


def score_sarif(sarif_path, manifest_path, output_path=None):
    cases = manifest_cases(manifest_path)
    results = normalize_sarif(sarif_path, cases=cases)
    hits = {}
    for result in results:
        if result["test_id"]:
            hits.setdefault(result["test_id"], []).append(result)

    totals = {}
    case_rows = []
    for case in cases:
        cwe = int(case["cwe"])
        bucket = totals.setdefault(cwe, {"TP": 0, "FN": 0, "TN": 0, "FP": 0})
        expected_rule_ids = set(case.get("expected_rule_ids", []))
        case_hits = [
            hit
            for hit in hits.get(case["test_id"], [])
            if not expected_rule_ids or hit["rule_id"] in expected_rule_ids
        ]
        found = bool(case_hits)
        if case["expected_vulnerable"] and found:
            verdict = "TP"
        elif case["expected_vulnerable"] and not found:
            verdict = "FN"
        elif not case["expected_vulnerable"] and found:
            verdict = "FP"
        else:
            verdict = "TN"
        bucket[verdict] += 1
        case_rows.append(
            {
                "test_id": case["test_id"],
                "cwe": cwe,
                "category": case["category"],
                "expected_vulnerable": case["expected_vulnerable"],
                "found": found,
                "verdict": verdict,
                "results": case_hits,
            }
        )

    scored = {
        "sarif": str(sarif_path),
        "manifest": str(manifest_path),
        "totals": totals,
        "cases": case_rows,
    }
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(scored, indent=2))
    return scored


def _infer_test_id(uri, message):
    text = "{} {}".format(uri, message)
    match = re.search(r"BenchmarkTest\d+", text)
    return match.group(0) if match else None


def _infer_cwe(rule_id, message):
    text = "{} {}".format(rule_id or "", message or "")
    match = re.search(r"cwe[-/](\d+)|cwe-(\d+)", text, re.IGNORECASE)
    if match:
        return int(next(group for group in match.groups() if group))
    return None

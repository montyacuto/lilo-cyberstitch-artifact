import json
from pathlib import Path

from .codeql import check_query_syntax
from .rewrite import rewrite_queries
from .validate import refresh_decisions


def run_codeql_check(
    config,
    decisions_path=None,
    query_dir=None,
    rewritten_dir=None,
    output_path=None,
    target_language=None,
    final_only=False,
):
    decisions_path = Path(decisions_path or config.results_dir / "validation" / "decisions.json")
    query_dir = Path(query_dir or config.query_dir)
    rewritten_dir = Path(rewritten_dir or config.results_dir / "rewritten")
    output_path = Path(output_path or config.results_dir / "validation" / "codeql-check.json")
    target_language = target_language or config.language

    data = json.loads(decisions_path.read_text())
    decisions = refresh_decisions(data.get("decisions", []))
    check_root = config.results_dir / "codeql-check"
    candidate_root = check_root / "candidates"
    candidate_root.mkdir(parents=True, exist_ok=True)

    candidate_results = []
    if not final_only:
        for index, decision in enumerate(decisions):
            candidate = decision["candidate"]
            if not decision["accepted"]:
                continue
            if target_language != "all" and candidate.get("language") != target_language:
                continue
            candidate_name = _safe_dir_name(candidate.get("name") or "candidate_{}".format(index))
            candidate_dir = candidate_root / "{:03d}-{}".format(index, candidate_name)
            single_decision_path = candidate_dir / "decisions.json"
            single_decision_path.parent.mkdir(parents=True, exist_ok=True)
            single_decision_path.write_text(json.dumps({"decisions": [decision]}, indent=2))
            rewrite_result = rewrite_queries(
                single_decision_path,
                query_dir,
                candidate_dir / "rewritten",
                target_language=target_language,
            )
            syntax_result = check_query_syntax(
                config,
                query_path=Path(rewrite_result["queries"]),
                output_path=candidate_dir / "codeql-check.json",
                language=target_language,
            )
            candidate["codeql_syntax_validation"] = {
                "ok": syntax_result["ok"],
                "queries": syntax_result["queries"],
                "stdout": syntax_result["stdout"],
                "stderr": syntax_result["stderr"],
            }
            candidate_results.append(
                {
                    "candidate": candidate.get("name", ""),
                    "ok": syntax_result["ok"],
                    "queries": syntax_result["queries"],
                }
            )

    decisions = refresh_decisions(decisions)
    decisions_path.write_text(json.dumps({"decisions": decisions}, indent=2))

    rewrite_result = rewrite_queries(
        decisions_path,
        query_dir,
        rewritten_dir,
        target_language=target_language,
    )
    final_result = check_query_syntax(
        config,
        query_path=Path(rewrite_result["queries"]),
        output_path=check_root / "final-codeql-check.json",
        language=target_language,
    )
    ok = final_result["ok"] and all(item["ok"] for item in candidate_results)
    result = {
        "ok": ok,
        "decisions": str(decisions_path),
        "final_only": bool(final_only),
        "rewritten": rewrite_result,
        "candidate_results": candidate_results,
        "final": {
            "ok": final_result["ok"],
            "queries": final_result["queries"],
            "stdout": final_result["stdout"],
            "stderr": final_result["stderr"],
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2))
    return result


def _safe_dir_name(name):
    text = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in str(name))
    return text.strip("_") or "candidate"

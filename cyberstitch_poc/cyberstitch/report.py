import json
from pathlib import Path

from .codeql import doctor
from .manifest import load_manifest


def write_report(config, output_path):
    results_dir = Path(config.results_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(config.curated_subset_manifest)
    doctor_result = doctor(config)

    lines = ["# CyberSTITCH CodeQL/OWASP PoC Report", ""]
    lines.append("Language: `{}`".format(config.language))
    lines.append("OWASP root: `{}`".format(config.owasp_root))
    lines.append("Curated manifest: `{}`".format(config.curated_subset_manifest))
    lines.append("")

    lines.append("## Tooling")
    for name, status in doctor_result["tools"].items():
        state = "available" if status["available"] else "missing"
        version = status.get("version") or ""
        lines.append("- `{}`: {} {}".format(name, state, version))
    if doctor_result["actions"]:
        lines.append("")
        lines.append("Actions:")
        for action in doctor_result["actions"]:
            lines.append("- {}".format(action))
    lines.append("")

    lines.append("## Curated Cases")
    for case in manifest.get("cases", []):
        label = "vulnerable" if case["expected_vulnerable"] else "safe"
        lines.append(
            "- `{}` CWE-{} {} `{}`: {}".format(
                case["test_id"],
                case["cwe"],
                label,
                case["category"],
                case["rationale"],
            )
        )
    lines.append("")

    validation_path = results_dir / "validation" / "decisions.json"
    if validation_path.exists():
        decisions = json.loads(validation_path.read_text())["decisions"]
        accepted = [item for item in decisions if item["accepted"]]
        accepted_for_lilo = [item for item in decisions if item.get("accepted_for_lilo")]
        lilo_only = [
            item for item in decisions
            if item.get("accepted_for_lilo") and not item["accepted"]
        ]
        rejected = [item for item in decisions if not item["accepted"]]
        rejected_for_lilo = [item for item in decisions if not item.get("accepted_for_lilo")]
        lines.append("## Abstractions")
        lines.append("Accepted rewrite helpers: {}".format(len(accepted)))
        lines.append("Accepted LILO candidates: {}".format(len(accepted_for_lilo)))
        lines.append("LILO-only semantic candidates: {}".format(len(lilo_only)))
        lines.append("Rejected for rewrite: {}".format(len(rejected)))
        lines.append("Rejected for LILO inventory: {}".format(len(rejected_for_lilo)))
        final_syntax = _final_syntax_result(results_dir)
        if final_syntax is not None:
            lines.append("Final rewritten query syntax: `{}`".format(final_syntax.get("ok", False)))
        lines.append("")
        lines.append("Rewrite helpers:")
        for item in accepted:
            candidate = item["candidate"]
            syntax = candidate.get("codeql_syntax_validation") or {}
            lines.append("- `{}` `{}`: {} use sites, CodeQL syntax `{}`".format(
                candidate["name"],
                candidate.get("schema", "legacy"),
                len(candidate.get("use_sites", [])),
                syntax.get("ok", "not-run"),
            ))
        if lilo_only:
            lines.append("")
            lines.append("LILO-only semantic candidates:")
            for item in lilo_only:
                candidate = item["candidate"]
                lines.append("- `{}` `{}` role=`{}` target=`{}`".format(
                    candidate.get("name", ""),
                    candidate.get("schema", "legacy"),
                    candidate.get("semantic_role", ""),
                    candidate.get("semantic_target", ""),
                ))
        if rejected:
            lines.append("")
            lines.append("Rewrite rejection reasons:")
            for item in rejected:
                candidate = item["candidate"]
                lines.append("- `{}`: `{}`".format(candidate.get("name", ""), item.get("reasons", [])))
        if rejected_for_lilo:
            lines.append("")
            lines.append("LILO inventory rejection reasons:")
            for item in rejected_for_lilo:
                candidate = item["candidate"]
                lines.append("- `{}`: `{}`".format(candidate.get("name", ""), item.get("lilo_reasons", [])))
        lines.append("")
    else:
        lines.append("## Abstractions")
        lines.append("Validation has not been run.")
        lines.append("")

    semantic_path = results_dir / "semantic" / "candidates.json"
    if semantic_path.exists():
        semantic = json.loads(semantic_path.read_text())
        semantic_candidates = semantic.get("candidates", [])
        rewrite_eligible = [item for item in semantic_candidates if item.get("rewrite_eligible")]
        semantic_only = [item for item in semantic_candidates if not item.get("rewrite_eligible")]
        lines.append("## Semantic Concept Mining")
        lines.append("Extracted concepts: `{}`".format(semantic.get("concepts", 0)))
        lines.append("Mined candidates: `{}`".format(len(semantic_candidates)))
        lines.append("Rewrite eligible: `{}`".format(len(rewrite_eligible)))
        lines.append("Semantic-only: `{}`".format(len(semantic_only)))
        for candidate in semantic_candidates:
            usefulness = candidate.get("semantic_usefulness", "semantic")
            lines.append(
                "- `{}` `{}` role=`{}` target=`{}` rewrite=`{}` usefulness=`{}`".format(
                    candidate.get("name", ""),
                    candidate.get("schema", ""),
                    candidate.get("semantic_role", ""),
                    candidate.get("semantic_target", ""),
                    candidate.get("rewrite_eligible", False),
                    usefulness,
                )
            )
        lines.append("")

    score_dir = results_dir / "score"
    if score_dir.exists():
        lines.append("## Scores")
        for score_path in sorted(score_dir.glob("*.json")):
            score = json.loads(score_path.read_text())
            lines.append("- `{}`: `{}`".format(score_path.name, score["totals"]))
        lines.append("")

    seed_summary_path = results_dir / "seed-discovery" / "summary.json"
    if seed_summary_path.exists():
        seed_summary = json.loads(seed_summary_path.read_text())
        lines.append("## Seed Query Discovery")
        lines.append("Java query pack: `{}`".format(seed_summary.get("java_queries_root", "")))
        lines.append("Include experimental: `{}`".format(seed_summary.get("include_experimental", False)))
        lines.append("Selection policy: `{}`".format(seed_summary.get("selection_policy", "")))
        lines.append("Resolved specs: `{}`".format(len(seed_summary.get("specs", []))))
        lines.append("Resolved queries: `{}`".format(len(seed_summary.get("queries", []))))
        lines.append("Selected seeds: `{}`".format(len(seed_summary.get("selected_seeds", []))))
        if seed_summary.get("score"):
            lines.append("Discovery score: `{}`".format(seed_summary["score"].get("totals", {})))
        for query in seed_summary.get("selected_seeds", []):
            lines.append(
                "- `{}` CWE-{} `{}` alerts=`{}` experimental=`{}`".format(
                    query.get("rule_id", ""),
                    query.get("cwe", ""),
                    query.get("relative_query_path", ""),
                    query.get("alert_count", 0),
                    query.get("experimental", False),
                )
            )
        lines.append("")

    lines.append("## Bundle Policy")
    policy_path = results_dir / "bundle-policy.json"
    if policy_path.exists():
        policy = json.loads(policy_path.read_text())
        lines.append("Policy: `{}`".format(policy.get("policy", "opt-in only")))
        lines.append("Bundle mode: `{}`".format(policy.get("bundle_mode", "none")))
        lines.append("Bundle created: `{}`".format(policy.get("bundle_created", False)))
        if policy.get("bundle_path"):
            lines.append("Restricted bundle: `{}`".format(policy["bundle_path"]))
    else:
        lines.append("Policy: `opt-in only`")
        lines.append("Bundle mode: `none`")
        lines.append("Bundle created: `False`")
    lines.append(
        "CodeQL database bundles are restricted/source-containing troubleshooting artifacts "
        "and are excluded from package output by default."
    )
    lines.append("")

    lines.append("## Commands")
    lines.append("```bash")
    lines.append("python -m cyberstitch.cli doctor")
    lines.append("python -m cyberstitch.cli sqir")
    lines.append("python -m cyberstitch.cli roundtrip")
    lines.append("python -m cyberstitch.cli fcir")
    lines.append("# Optional official pack FCIR mining corpus:")
    lines.append("# python -m cyberstitch.cli codeql-pack-fcir --include-experimental")
    lines.append("python -m cyberstitch.cli stitch --mode offline")
    lines.append("python -m cyberstitch.cli semantic-mine --merge")
    lines.append("# Optional schema-only LILO LLM proposals:")
    lines.append("# python -m cyberstitch.cli llm-propose --merge")
    lines.append("python -m cyberstitch.cli validate")
    lines.append("python -m cyberstitch.cli rewrite")
    lines.append("python -m cyberstitch.cli codeql-check")
    lines.append("python -m cyberstitch.cli db-create")
    lines.append("# Optional official CodeQL seed discovery after db-create:")
    lines.append("# python -m cyberstitch.cli codeql-discover --database results/codeql-dbs/java")
    lines.append("python -m cyberstitch.cli analyze --queries original")
    lines.append("python -m cyberstitch.cli score --sarif results/sarif/original.sarif")
    lines.append("# Optional restricted troubleshooting bundle only:")
    lines.append("# python -m cyberstitch.cli db-bundle --output results/bundles/java-codeql-debug-artifacts.zip")
    lines.append("```")
    lines.append("")

    output_path.write_text("\n".join(lines))
    return str(output_path)


def _final_syntax_result(results_dir):
    for path in [
        results_dir / "validation" / "final-rewritten-codeql-check.json",
        results_dir / "codeql-check" / "final-codeql-check.json",
    ]:
        if not path.exists():
            continue
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            return {"ok": False}
    return None

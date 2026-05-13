import json
import re
from collections import Counter
from pathlib import Path

from .codeql import require_codeql, run_codeql_result
from .codeql_pack import find_java_queries_pack
from .manifest import manifest_cases
from .sarif import normalize_sarif


OFFICIAL_QUERY_SPECS = {
    78: "codeql/java-queries:Security/CWE/CWE-078",
    89: "codeql/java-queries:Security/CWE/CWE-089",
}

EXPERIMENTAL_QUERY_SPECS = {
    78: "codeql/java-queries:experimental/Security/CWE/CWE-078",
    89: "codeql/java-queries:experimental/Security/CWE/CWE-089",
}

METADATA_RE = re.compile(r"^\s*\*\s*@([A-Za-z0-9_.-]+)\s+(.*?)\s*$", re.MULTILINE)


def discover_seed_queries(
    config,
    database_dir=None,
    output_dir=None,
    cwes=(78, 89),
    include_experimental=False,
    specs=None,
    analyze=True,
    threads=0,
    selection_policy="all",
):
    require_codeql(config)
    output_dir = Path(output_dir or config.results_dir / "seed-discovery")
    output_dir.mkdir(parents=True, exist_ok=True)
    database_dir = Path(database_dir or config.codeql_database_dir / config.language)
    java_queries_root = find_java_queries_pack(_default_pack_root(config))

    spec_items = _spec_items(cwes, include_experimental, specs)
    resolved_specs = []
    all_queries = []
    all_results = []
    sarif_paths = []
    for item in spec_items:
        spec_dir = output_dir / _slug(item["name"])
        spec_dir.mkdir(parents=True, exist_ok=True)
        resolved = _resolve_spec(config, item["spec"], spec_dir)
        compiled = _compile_spec(config, item["spec"], spec_dir)
        queries = [
            _query_metadata(Path(path), java_queries_root, item)
            for path in resolved.get("queries", [])
        ]
        query_compile = _compile_status_by_query(compiled)
        for query in queries:
            query["compile_ok"] = query_compile.get(query["query_path"], compiled["ok"])

        analysis = {"ok": False, "skipped": True, "sarif": None, "error": None}
        results = []
        if analyze:
            if not database_dir.exists():
                raise FileNotFoundError("CodeQL database not found: {}".format(database_dir))
            analysis = _analyze_spec(
                config,
                database_dir,
                item["spec"],
                spec_dir,
                threads=threads,
            )
            if analysis["ok"]:
                sarif_paths.append(analysis["sarif"])
                cases = manifest_cases(config.curated_subset_manifest)
                results = normalize_sarif(analysis["sarif"], cases=cases)
                all_results.extend(results)
                _write_json(spec_dir / "score.json", _score_results(results, cases, cwe=item["cwe"]))

        counts = Counter(result.get("rule_id") for result in results if result.get("rule_id"))
        for query in queries:
            query["alert_count"] = counts.get(query["rule_id"], 0)
            query["selected"] = _selected(query, selection_policy, include_experimental)
            query["selection_policy"] = selection_policy
            all_queries.append(query)

        spec_summary = {
            **item,
            "resolved": resolved,
            "compile": compiled,
            "analysis": analysis,
            "queries": queries,
            "rule_alert_counts": dict(sorted(counts.items())),
        }
        _write_json(spec_dir / "summary.json", spec_summary)
        resolved_specs.append(spec_summary)

    cases = manifest_cases(config.curated_subset_manifest)
    selected = [query for query in all_queries if query["selected"]]
    summary = {
        "format": "cyberstitch-codeql-seed-discovery",
        "version": 1,
        "language": config.language,
        "codeql": _codeql_version(config),
        "java_queries_root": str(java_queries_root),
        "database": str(database_dir),
        "manifest": str(config.curated_subset_manifest),
        "include_experimental": include_experimental,
        "selection_policy": selection_policy,
        "specs": _compact_specs(resolved_specs),
        "queries": all_queries,
        "selected_seeds": selected,
        "sarif": sarif_paths,
        "score": _score_results(all_results, cases) if analyze else None,
    }
    _write_json(output_dir / "summary.json", summary)
    _write_json(output_dir / "selected-seeds.json", {"selected_seeds": selected})
    return summary


def score_results_without_expected_rule_ids(sarif_path, manifest_path, cwe=None):
    cases = manifest_cases(manifest_path)
    results = normalize_sarif(sarif_path, cases=cases)
    return _score_results(results, cases, cwe=cwe)


def _spec_items(cwes, include_experimental, specs):
    if specs:
        items = []
        for spec in specs:
            cwe = _infer_cwe(spec)
            experimental = "/experimental/" in spec or ":experimental/" in spec
            items.append(
                {
                    "name": "{}-cwe{:03d}".format("experimental" if experimental else "custom", cwe or 0),
                    "spec": spec,
                    "cwe": cwe,
                    "tier": "experimental" if experimental else "custom",
                    "experimental": experimental,
                }
            )
        return items

    items = []
    for cwe in [int(item) for item in cwes]:
        if cwe in OFFICIAL_QUERY_SPECS:
            items.append(
                {
                    "name": "official-cwe{:03d}".format(cwe),
                    "spec": OFFICIAL_QUERY_SPECS[cwe],
                    "cwe": cwe,
                    "tier": "official",
                    "experimental": False,
                }
            )
        if include_experimental and cwe in EXPERIMENTAL_QUERY_SPECS:
            items.append(
                {
                    "name": "experimental-cwe{:03d}".format(cwe),
                    "spec": EXPERIMENTAL_QUERY_SPECS[cwe],
                    "cwe": cwe,
                    "tier": "experimental",
                    "experimental": True,
                }
            )
    return items


def _resolve_spec(config, spec, output_dir):
    completed = run_codeql_result(
        ["resolve", "queries", "--format=json", "--", spec],
        config=config,
    )
    data = _json_array_from_output(completed.stdout)
    result = {
        "ok": completed.returncode == 0,
        "spec": spec,
        "queries": data or [],
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": [require_codeql(config), "resolve", "queries", "--format=json", "--", spec],
    }
    _write_json(output_dir / "resolved.json", result)
    return result


def _compile_spec(config, spec, output_dir):
    common_cache = output_dir / "codeql-cache" / "common"
    compile_cache = output_dir / "codeql-cache" / "compile"
    common_cache.mkdir(parents=True, exist_ok=True)
    compile_cache.mkdir(parents=True, exist_ok=True)
    args = [
        "query",
        "compile",
        "--check-only",
        "--keep-going",
        "--format=json",
        "--common-caches={}".format(common_cache),
        "--compilation-cache={}".format(compile_cache),
        "--",
        spec,
    ]
    completed = run_codeql_result(args, config=config)
    data = _json_array_from_output(completed.stdout)
    result = {
        "ok": completed.returncode == 0 and all(item.get("success", False) for item in data or []),
        "spec": spec,
        "queries": data or [],
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": [require_codeql(config)] + args,
    }
    _write_json(output_dir / "compile.json", result)
    return result


def _analyze_spec(config, database_dir, spec, output_dir, threads=0):
    common_cache = output_dir / "codeql-cache" / "analysis-common"
    compile_cache = output_dir / "codeql-cache" / "analysis-compile"
    common_cache.mkdir(parents=True, exist_ok=True)
    compile_cache.mkdir(parents=True, exist_ok=True)
    sarif_path = output_dir / "results.sarif"
    args = [
        "database",
        "analyze",
        "--common-caches={}".format(common_cache),
        "--compilation-cache={}".format(compile_cache),
        "--rerun",
        str(database_dir),
        spec,
        "--format=sarifv2.1.0",
        "--output={}".format(sarif_path),
        "--threads={}".format(threads),
    ]
    completed = run_codeql_result(args, config=config)
    result = {
        "ok": completed.returncode == 0,
        "skipped": False,
        "sarif": str(sarif_path) if sarif_path.exists() else None,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": [require_codeql(config)] + args,
    }
    _write_json(output_dir / "analysis.json", result)
    return result


def _query_metadata(path, java_queries_root, spec_item):
    text = path.read_text()
    metadata = {key: value for key, value in METADATA_RE.findall(text)}
    cwe = spec_item.get("cwe") or _infer_cwe(text) or _infer_cwe(str(path))
    relative = _relative_to(path, java_queries_root)
    rule_id = metadata.get("id", path.stem)
    return {
        "rule_id": rule_id,
        "query_path": str(path),
        "relative_query_path": relative,
        "cwe": cwe,
        "kind": metadata.get("kind", ""),
        "precision": metadata.get("precision", ""),
        "name": metadata.get("name", ""),
        "tier": spec_item["tier"],
        "spec": spec_item["spec"],
        "experimental": spec_item["experimental"] or "/experimental/" in relative,
        "source_hash": _hash_text(text),
    }


def _score_results(results, cases, cwe=None):
    cases = [case for case in cases if cwe is None or int(case["cwe"]) == int(cwe)]
    hits = {}
    for result in results:
        if result.get("test_id"):
            hits.setdefault(result["test_id"], []).append(result)
    totals = {}
    rows = []
    for case in cases:
        case_cwe = int(case["cwe"])
        bucket = totals.setdefault(case_cwe, {"TP": 0, "FN": 0, "TN": 0, "FP": 0})
        found = bool(hits.get(case["test_id"]))
        if case["expected_vulnerable"] and found:
            verdict = "TP"
        elif case["expected_vulnerable"] and not found:
            verdict = "FN"
        elif not case["expected_vulnerable"] and found:
            verdict = "FP"
        else:
            verdict = "TN"
        bucket[verdict] += 1
        rows.append(
            {
                "test_id": case["test_id"],
                "cwe": case_cwe,
                "expected_vulnerable": case["expected_vulnerable"],
                "found": found,
                "verdict": verdict,
                "result_count": len(hits.get(case["test_id"], [])),
            }
        )
    return {"totals": totals, "cases": rows}


def _selected(query, selection_policy, include_experimental):
    if not query.get("compile_ok"):
        return False
    if query.get("experimental") and not include_experimental:
        return False
    if selection_policy == "firing":
        return query.get("alert_count", 0) > 0
    return True


def _compile_status_by_query(compiled):
    statuses = {}
    for item in compiled.get("queries", []):
        path = item.get("query")
        if path:
            statuses[str(Path(path))] = bool(item.get("success"))
    return statuses


def _compact_specs(specs):
    compact = []
    for spec in specs:
        compact.append(
            {
                "name": spec["name"],
                "spec": spec["spec"],
                "cwe": spec["cwe"],
                "tier": spec["tier"],
                "experimental": spec["experimental"],
                "resolved_queries": len(spec["queries"]),
                "compile_ok": spec["compile"]["ok"],
                "analysis_ok": spec["analysis"]["ok"],
                "rule_alert_counts": spec["rule_alert_counts"],
            }
        )
    return compact


def _json_array_from_output(text):
    text = text or ""
    end = text.rfind("]")
    if end < 0:
        return []
    for start, char in enumerate(text):
        if char != "[":
            continue
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            continue
    return []


def _codeql_version(config):
    completed = run_codeql_result(["version"], config=config)
    return "\n".join(
        line.strip()
        for line in "{}\n{}".format(completed.stdout, completed.stderr).splitlines()
        if line.strip() and "[warning][perf,memops]" not in line
    )


def _default_pack_root(config):
    local_codeql = config.root.parent / "codeql"
    if local_codeql.exists():
        return local_codeql
    if config.codeql_binary:
        return config.codeql_binary.parent
    return config.root


def _relative_to(path, root):
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _infer_cwe(text):
    match = re.search(r"CWE[-_/]0*(\d+)|cwe[-_/]0*(\d+)", str(text), re.IGNORECASE)
    if not match:
        return None
    return int(next(group for group in match.groups() if group))


def _slug(value):
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value)).strip("-")
    return text or "spec"


def _hash_text(text):
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")

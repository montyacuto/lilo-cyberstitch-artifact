#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


SUPPORTED_MANIFEST_CASES = {
    (78, "cmdi"): {
        "rule_id": "java/cyberstitch/owasp-cwe078-command",
        "rationale": (
            "Full expected-results expansion for CWE-78 command injection; used "
            "to evaluate CodeQL scoring and CyberSTITCH semantic equivalence."
        ),
        "abstraction_target": "RemoteFlowSource plus Runtime.exec argument sink",
        "label": "CWE-78 command injection",
    },
    (89, "sqli"): {
        "rule_id": "java/cyberstitch/owasp-cwe089-sql",
        "rationale": (
            "Full expected-results expansion for CWE-89 SQL injection; used "
            "to evaluate CodeQL scoring and CyberSTITCH semantic equivalence."
        ),
        "abstraction_target": "RemoteFlowSource plus java.sql.Statement execution sink",
        "label": "CWE-89 SQL injection",
    },
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Inspect OWASP Benchmark expectedresults CSV files for candidate curation."
    )
    parser.add_argument("csv", type=Path)
    parser.add_argument("--cwe", type=int, action="append", default=[])
    parser.add_argument("--category", action="append", default=[])
    parser.add_argument("--vulnerable", choices=["true", "false"], default=None)
    parser.add_argument("--limit", type=int, default=50, help="Maximum rows to select. Use 0 for all.")
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=None,
        help="Write selected rows as a CyberSTITCH OWASP manifest.",
    )
    parser.add_argument(
        "--manifest-root",
        type=Path,
        default=None,
        help="BenchmarkJava root used to check source paths for manifest generation.",
    )
    parser.add_argument(
        "--balanced",
        action="store_true",
        help="For manifest generation, select half vulnerable and half safe cases.",
    )
    parser.add_argument(
        "--source",
        default="https://github.com/OWASP-Benchmark/BenchmarkJava",
        help="Benchmark source URL recorded in generated manifests.",
    )
    parser.add_argument(
        "--commit",
        default="b06d6efaebd577a327514364951916e7df3290b4",
        help="Benchmark commit recorded in generated manifests.",
    )
    args = parser.parse_args(argv)

    categories = {item.lower() for item in args.category}
    cwes = set(args.cwe)
    want_vulnerable = None
    if args.vulnerable is not None:
        want_vulnerable = args.vulnerable == "true"

    rows = []
    with args.csv.open(newline="") as handle:
        lines = [
            _normalize_header(line)
            for line in handle
            if line.strip() and not line.lstrip().startswith("# Benchmark")
        ]
        for row in csv.DictReader(lines):
            normalized = {
                str(key).strip().lower(): str(value or "").strip()
                for key, value in row.items()
                if key is not None
            }
            cwe = int(normalized.get("cwe") or 0)
            category = normalized.get("category", "").lower()
            vulnerable = _bool(
                normalized.get("real vulnerability")
                or normalized.get("vulnerable")
                or normalized.get("expected_vulnerable")
            )
            if cwes and cwe not in cwes:
                continue
            if categories and category not in categories:
                continue
            if want_vulnerable is not None and vulnerable is not want_vulnerable:
                continue
            rows.append({"raw": row, "normalized": normalized, "vulnerable": vulnerable})
            if not args.manifest_output and args.limit > 0 and len(rows) >= args.limit:
                break

    selected = _select_rows(rows, args.limit, balanced=args.balanced)
    if args.manifest_output:
        if not args.manifest_root:
            parser.error("--manifest-output requires --manifest-root")
        manifest = _build_manifest(
            selected,
            csv_path=args.csv,
            manifest_root=args.manifest_root,
            source=args.source,
            commit=args.commit,
            balanced=args.balanced,
        )
        args.manifest_output.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_output.write_text(json.dumps(manifest, indent=2) + "\n")

    print(json.dumps({"count": len(selected), "rows": [item["raw"] for item in selected]}, indent=2))
    return 0


def _select_rows(rows, limit, balanced=False):
    if limit <= 0:
        return rows
    if not balanced:
        return rows[:limit]
    vulnerable = [row for row in rows if row["vulnerable"]]
    safe = [row for row in rows if not row["vulnerable"]]
    each = limit // 2
    selected = vulnerable[:each] + safe[: each + (limit % 2)]
    return sorted(selected, key=lambda item: item["normalized"].get("test name", ""))


def _build_manifest(rows, csv_path, manifest_root, source, commit, balanced):
    cases = []
    for row in rows:
        normalized = row["normalized"]
        test_id = normalized["test name"]
        cwe = int(normalized["cwe"])
        category = normalized["category"]
        support = SUPPORTED_MANIFEST_CASES.get((cwe, category))
        if not support:
            raise SystemExit(
                "manifest generation supports only CWE-78 cmdi and CWE-89 sqli cases; "
                "found {} cwe={} category={}".format(test_id, cwe, category)
            )
        vulnerable = row["vulnerable"]
        file_path = "src/main/java/org/owasp/benchmark/testcode/{}.java".format(test_id)
        source_path = manifest_root / file_path
        if not source_path.exists():
            raise SystemExit("missing source file for {}: {}".format(test_id, source_path))
        cases.append(
            {
                "test_id": test_id,
                "file": file_path,
                "cwe": cwe,
                "category": category,
                "expected_vulnerable": vulnerable,
                "expected_rule_ids": [support["rule_id"]],
                "rationale": support["rationale"],
                "abstraction_target": support["abstraction_target"],
            }
        )
    selection_parts = []
    for key in sorted(SUPPORTED_MANIFEST_CASES):
        cwe, category = key
        matching = [case for case in cases if case["cwe"] == cwe and case["category"] == category]
        if not matching:
            continue
        vulnerable_count = len([case for case in matching if case["expected_vulnerable"]])
        safe_count = len(matching) - vulnerable_count
        selection_parts.append(
            "{}: {} cases ({} vulnerable, {} safe)".format(
                SUPPORTED_MANIFEST_CASES[key]["label"],
                len(matching),
                vulnerable_count,
                safe_count,
            )
        )
    return {
        "schema_version": "cyberstitch-owasp-curated-subset-v1",
        "benchmark": {
            "name": "OWASP Benchmark Java",
            "release": "Benchmark v1.2",
            "source": source,
            "commit": commit,
            "expected_results": Path(csv_path).name,
        },
        "selection_policy": (
            "Mechanical expansion selected from expectedresults order; not a "
            "hand-curated abstraction corpus. Total cases: {}. {}."
        ).format(len(cases), "; ".join(selection_parts)),
        "cases": cases,
    }


def _bool(value):
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def _normalize_header(line):
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return stripped[1:].lstrip()
    return line


if __name__ == "__main__":
    raise SystemExit(main())

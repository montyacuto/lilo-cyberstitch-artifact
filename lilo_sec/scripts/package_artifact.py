#!/usr/bin/env python3
"""Verify and stage the combined LILO/CyberSTITCH artifact package."""

from __future__ import print_function

import argparse
import datetime as _dt
import fnmatch
import json
import os
import shutil
import sys
from pathlib import Path


LILO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = LILO_ROOT.parent


EXCLUDE_DIR_NAMES = set(
    [
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".conda",
        ".opam",
        ".cache",
        "_build",
        "_opam",
        "codeql-dbs",
        "codeql-cache",
        "m2-repository",
        "bundles",
        "BenchmarkJava",
        "target",
    ]
)

EXCLUDE_FILE_PATTERNS = [
    ".git",
    ".DS_Store",
    "*.pyc",
    "*.pyo",
    "*.zip",
    "*.tar",
    "*.tar.gz",
]


def item(path, scope, reason, required=True, target=None):
    return {
        "path": path,
        "target": target or path,
        "scope": scope,
        "reason": reason,
        "required": required,
    }


PACKAGE_ITEMS = [
    item("README.md", "all", "Combined artifact README."),
    item("LICENSE.txt", "all", "Top-level artifact license."),
    item("run_artifact.sh", "all", "Root artifact runner source."),
    item("run_artifact.sh", "all", "Packaged one-command artifact runner.", target="artifact"),
    item("lilo", "all", "Compatibility wrapper for the combined artifact menu."),
    item("package_stage", "all", "Package verification and staging manifests.", required=False),
    item("env/locks", "lilo", "Pinned dependency lock records."),
    item("results/lilo/run_logs/artifact_demo_lilo_seed111_init", "lilo", "Paper-faithful seed-111 init command logs."),
    item("results/lilo/run_logs/artifact_demo_lilo_seed111_batch32_full_battery", "lilo", "Batch-32 full battery command logs."),
    item("results/lilo/run_logs/artifact_demo_lilo_logo_seed111_batch96_instruct_4gb_partial", "lilo", "Longest increased-cap LOGO partial run logs."),
    item("results/lilo/run_logs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment1/run.log", "lilo", "Batch-96 REGEX first segment embedded run log."),
    item("results/lilo/run_logs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment2/run.log", "lilo", "Batch-96 REGEX continuation embedded run log."),
    item("results/lilo/monitors/artifact_demo_lilo_seed111_init", "lilo", "Init monitor evidence."),
    item("results/lilo/monitors/artifact_demo_lilo_seed111_batch32_full_battery", "lilo", "Full battery monitor evidence."),
    item("results/lilo/llm_caches/artifact_demo_lilo_seed111_batch32_replay_cache", "lilo", "Primary batch-32 replay cache."),
    item("results/lilo/llm_caches/batch96_regex_cache_note.md", "lilo", "Batch-96 REGEX cache status note."),
    item("lilo_sec/README.md", "lilo", "LILO source README."),
    item("lilo_sec/REPRODUCTION_STATUS.md", "lilo", "LILO reproduction status note."),
    item("lilo_sec/environment.yml", "lilo", "Pinned conda environment seed file."),
    item("lilo_sec/laps_requirements.txt", "lilo", "Legacy Python requirements record."),
    item("lilo_sec/.gitignore", "lilo", "LILO repository ignore rules."),
    item("lilo_sec/.gitmodules", "lilo", "LILO submodule metadata."),
    item("lilo_sec/Dockerfile", "lilo", "Original Docker reference environment.", required=False),
    item("lilo_sec/litellm_config.example.yaml", "lilo", "LiteLLM example configuration."),
    item("lilo_sec/litellm_config.gpt35.yaml", "lilo", "LiteLLM GPT-3.5 compatibility configuration."),
    item("lilo_sec/litellm_config.initial_lilo.yaml", "lilo", "LiteLLM initial LILO compatibility configuration."),
    item("lilo_sec/run_experiment.py", "lilo", "LILO experiment entrypoint."),
    item("lilo_sec/run_iterative_experiment.py", "lilo", "Iterative LILO experiment entrypoint."),
    item("lilo_sec/precompute_embeddings.py", "lilo", "Embedding precomputation helper."),
    item("lilo_sec/run_library_evaluation.py", "lilo", "Library evaluation helper."),
    item("lilo_sec/evaluate_compression_model_scoring.py", "lilo", "Compression-model scoring helper."),
    item("lilo_sec/scripts", "lilo", "Artifact runner and LILO helper scripts."),
    item("lilo_sec/src", "lilo", "LILO reproduction source modifications."),
    item("lilo_sec/data", "lilo", "LILO benchmark task data and embeddings."),
    item("lilo_sec/dreamcoder", "lilo", "Bundled DreamCoder source and binaries."),
    item("lilo_sec/ocaml", "lilo", "OCaml solver source and binaries."),
    item("lilo_sec/experiments", "lilo", "Original experiment definitions."),
    item("lilo_sec/experiments_iterative/templates", "lilo", "LILO iterative experiment templates."),
    item("lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_seed111_init", "lilo", "Paper-faithful init output."),
    item("lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_seed111_batch32_full_battery", "lilo", "Batch-32 full battery output."),
    item("lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment1", "lilo", "Batch-96 REGEX first segment output."),
    item("lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment2", "lilo", "Batch-96 REGEX continuation output."),
    item("lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_logo_seed111_batch96_instruct_4gb_partial", "lilo", "Longest increased-cap LOGO partial output."),
    item("cyberstitch_poc/README.md", "cyberstitch", "CyberSTITCH README."),
    item("cyberstitch_poc/Makefile", "cyberstitch", "CyberSTITCH developer commands."),
    item("cyberstitch_poc/pyproject.toml", "cyberstitch", "CyberSTITCH Python metadata."),
    item("cyberstitch_poc/cyberstitch.yml", "cyberstitch", "CyberSTITCH configuration."),
    item("cyberstitch_poc/cyberstitch", "cyberstitch", "CyberSTITCH implementation."),
    item("cyberstitch_poc/queries", "cyberstitch", "Baseline CyberSTITCH CodeQL queries."),
    item("cyberstitch_poc/query_profiles", "cyberstitch", "CyberSTITCH query profiles and seed manifests."),
    item("cyberstitch_poc/fixtures", "cyberstitch", "Fixture-backed LILO/AutoDoc inputs."),
    item("cyberstitch_poc/scripts", "cyberstitch", "CyberSTITCH experiment runner scripts."),
    item("cyberstitch_poc/tests", "cyberstitch", "CyberSTITCH tests."),
    item("cyberstitch_poc/benchmarks/owasp_curated_subset.json", "cyberstitch", "Curated fixture manifest."),
    item("cyberstitch_poc/benchmarks/owasp_curated_subset_benchmarkjava.json", "cyberstitch", "BenchmarkJava curated manifest."),
    item("cyberstitch_poc/benchmarks/owasp_cmdi_100_benchmarkjava.json", "cyberstitch", "BenchmarkJava command injection manifest."),
    item("cyberstitch_poc/benchmarks/owasp_cmdi_sqli_all_benchmarkjava.json", "cyberstitch", "BenchmarkJava CMDI/SQLI manifest."),
    item("cyberstitch_poc/benchmarks/owasp_cmdi_sqli_all_benchmarkjava_official_expanded.json", "cyberstitch", "Companion-pack BenchmarkJava manifest."),
    item("cyberstitch_poc/benchmarks/owasp-fixture", "cyberstitch", "Checked-in fixture source corpus."),
    item("cyberstitch_poc/benchmarks/js", "cyberstitch", "Checked-in JS fixture corpus."),
    item("cyberstitch_poc/results/artifact_demo_cyberstitch_combined_pack_final", "cyberstitch", "Deterministic combined-pack final run."),
    item("cyberstitch_poc/results/artifact_demo_cyberstitch_companion_pack_final", "cyberstitch", "Deterministic companion-pack final run."),
    item("cyberstitch_poc/results/artifact_demo_cyberstitch_bounded_pack_final", "cyberstitch", "Deterministic bounded-pack final run."),
    item("cyberstitch_poc/results/artifact_demo_cyberstitch_combined_pack_fixture_lilo", "cyberstitch", "Fixture-backed LILO-loop artifact run."),
    item("cyberstitch_poc/results/artifact_demo_cyberstitch_combined_pack_live_api", "cyberstitch", "Live API partitioned combined-pack record run."),
    item("cyberstitch_poc/results/artifact_demo_cyberstitch_companion_pack_live_api", "cyberstitch", "Live API partitioned companion-pack record run."),
    item("cyberstitch_poc/results/artifact_demo_cyberstitch_bounded_pack_live_api", "cyberstitch", "Live API partitioned bounded-pack record run."),
    item("cyberstitch_poc/results/lilo-llm-cache/artifact_demo_cyberstitch_combined_pack_live_api", "cyberstitch", "Live API combined-pack completion cache."),
    item("cyberstitch_poc/results/lilo-llm-cache/artifact_demo_cyberstitch_companion_pack_live_api", "cyberstitch", "Live API companion-pack completion cache."),
    item("cyberstitch_poc/results/lilo-llm-cache/artifact_demo_cyberstitch_bounded_pack_live_api", "cyberstitch", "Live API bounded-pack completion cache."),
]


def selected_items(scope):
    if scope == "all":
        return PACKAGE_ITEMS
    return [entry for entry in PACKAGE_ITEMS if entry["scope"] in (scope, "all")]


def resolve_entry_path(entry):
    source = PROJECT_ROOT / entry.get("source_path", entry["path"])
    if source.exists():
        return source
    target = PROJECT_ROOT / entry.get("target", entry["path"])
    return target


def relpath(path):
    return path.relative_to(PROJECT_ROOT).as_posix()


def path_kind(path):
    if path.is_dir():
        return "dir"
    if path.is_file():
        return "file"
    if path.exists():
        return "other"
    return "missing"


def quick_size(path):
    if path.is_file():
        return path.stat().st_size
    return None


def excluded_child_reasons(path):
    findings = []
    if not path.is_dir():
        return findings
    for root, dirs, files in os.walk(str(path)):
        root_path = Path(root)
        kept_dirs = []
        for dirname in dirs:
            child = root_path / dirname
            if dirname in EXCLUDE_DIR_NAMES:
                findings.append("{}: excluded directory `{}`".format(relpath(child), dirname))
            else:
                kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for filename in files:
            for pattern in EXCLUDE_FILE_PATTERNS:
                if fnmatch.fnmatch(filename, pattern):
                    findings.append(
                        "{}: excluded file pattern `{}`".format(
                            relpath(root_path / filename), pattern
                        )
                    )
                    break
    return findings


def build_manifest(scope):
    entries = []
    missing = []
    warnings = []
    for entry in selected_items(scope):
        path = resolve_entry_path(entry)
        exists = path.exists()
        if not exists and entry["required"]:
            missing.append(entry.get("target", entry["path"]))
        if exists:
            warnings.extend(excluded_child_reasons(path))
        entries.append(
            {
                "path": entry.get("target", entry["path"]),
                "source_path": entry["path"],
                "target": entry["target"],
                "scope": entry["scope"],
                "reason": entry["reason"],
                "required": entry["required"],
                "exists": exists,
                "kind": path_kind(path),
                "file_size_bytes": quick_size(path),
            }
        )
    return {
        "created": _dt.datetime.now().isoformat(timespec="seconds"),
        "project_root": str(PROJECT_ROOT),
        "scope": scope,
        "entries": entries,
        "missing_required": missing,
        "excluded_children": warnings,
        "exclude_dir_names": sorted(EXCLUDE_DIR_NAMES),
        "exclude_file_patterns": EXCLUDE_FILE_PATTERNS,
    }


def public_manifest(manifest):
    public = dict(manifest)
    public["project_root"] = "<artifact-root>"
    public["entries"] = []
    for entry in manifest["entries"]:
        public_entry = dict(entry)
        public_entry.pop("source_path", None)
        public["entries"].append(public_entry)
    return public


def write_manifest_files(manifest, prefix):
    out_dir = PROJECT_ROOT / "package_stage"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "{}.json".format(prefix)
    md_path = out_dir / "{}.md".format(prefix)
    report_manifest = public_manifest(manifest)
    json_path.write_text(json.dumps(report_manifest, indent=2, sort_keys=True) + "\n")
    lines = [
        "# Artifact Package Manifest",
        "",
        "Created: `{}`".format(report_manifest["created"]),
        "Scope: `{}`".format(report_manifest["scope"]),
        "Project root: `{}`".format(report_manifest["project_root"]),
        "",
        "## Inputs",
    ]
    for entry in report_manifest["entries"]:
        status = "ok" if entry["exists"] else "missing"
        target = entry.get("target", entry["path"])
        target_note = " -> `{}`".format(target) if target != entry["path"] else ""
        lines.append(
            "- {} `{}`{} ({}) - {}".format(
                status, entry["path"], target_note, entry["scope"], entry["reason"]
            )
        )
    lines.append("")
    lines.append("## Missing Required")
    if report_manifest["missing_required"]:
        for path in report_manifest["missing_required"]:
            lines.append("- `{}`".format(path))
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Excluded Children Present")
    if report_manifest["excluded_children"]:
        for finding in report_manifest["excluded_children"][:200]:
            lines.append("- {}".format(finding))
        if len(report_manifest["excluded_children"]) > 200:
            lines.append("- ... {} more".format(len(report_manifest["excluded_children"]) - 200))
    else:
        lines.append("- none")
    lines.append("")
    md_path.write_text("\n".join(lines))
    return json_path, md_path


def copy_selected(manifest, destination):
    raw_dest = Path(destination)
    dest = raw_dest if raw_dest.is_absolute() else PROJECT_ROOT / raw_dest
    dest = dest.resolve()
    if dest.exists():
        raise RuntimeError("destination already exists: {}".format(dest))
    dest.mkdir(parents=True)
    for entry in manifest["entries"]:
        if not entry["exists"]:
            continue
        src = resolve_entry_path(entry)
        target = dest / entry.get("target", entry["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(str(src), str(target), ignore=copy_ignore)
        elif src.is_file():
            shutil.copy2(str(src), str(target))
    return dest


def copy_ignore(directory, names):
    ignored = []
    for name in names:
        path = Path(directory) / name
        if name in EXCLUDE_DIR_NAMES:
            ignored.append(name)
            continue
        for pattern in EXCLUDE_FILE_PATTERNS:
            if fnmatch.fnmatch(name, pattern):
                ignored.append(name)
                break
    return ignored


def verify(args):
    manifest = build_manifest(args.scope)
    json_path, md_path = write_manifest_files(manifest, "package_verify")
    print("Package verification report: {}".format(md_path))
    print("Package verification JSON: {}".format(json_path))
    print("Inputs checked: {}".format(len(manifest["entries"])))
    print("Missing required: {}".format(len(manifest["missing_required"])))
    print("Excluded children present: {}".format(len(manifest["excluded_children"])))
    if manifest["missing_required"]:
        for path in manifest["missing_required"]:
            print("missing: {}".format(path), file=sys.stderr)
        return 1
    return 0


def stage(args):
    manifest = build_manifest(args.scope)
    json_path, md_path = write_manifest_files(manifest, "package_manifest")
    print("Package manifest: {}".format(md_path))
    print("Package manifest JSON: {}".format(json_path))
    if manifest["missing_required"]:
        print("Refusing to stage with missing required inputs.", file=sys.stderr)
        for path in manifest["missing_required"]:
            print("missing: {}".format(path), file=sys.stderr)
        return 1
    if args.copy:
        if not args.destination:
            print("--copy requires --destination", file=sys.stderr)
            return 2
        try:
            dest = copy_selected(manifest, args.destination)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print("Copied selected package inputs to: {}".format(dest))
    else:
        print("No files copied. Pass --copy --destination <path> to stage a tree.")
    return 0


def report(args):
    if not args.plans_only:
        print("Combined artifact commands:")
        print("  ./artifact menu")
        print("  ./artifact verify")
        print("  ./artifact smoke")
        print("  ./artifact package-verify")
        print("  ./artifact package-stage")
        print("")
    print("Publication-facing package files:")
    print("  {}".format(PROJECT_ROOT / "README.md"))
    print("  {}".format(PROJECT_ROOT / "lilo_sec" / "README.md"))
    print("  {}".format(PROJECT_ROOT / "cyberstitch_poc" / "README.md"))
    if not args.plans_only:
        print("")
        print("Package-facing results:")
        print("  {}".format(PROJECT_ROOT / "lilo_sec" / "experiments_iterative" / "outputs"))
        print("  {}".format(PROJECT_ROOT / "cyberstitch_poc" / "results"))
        print("  {}".format(PROJECT_ROOT / "results" / "lilo"))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Combined artifact package verifier/stager.")
    sub = parser.add_subparsers(dest="command")
    verify_p = sub.add_parser("verify")
    verify_p.add_argument("--scope", choices=["all", "lilo", "cyberstitch"], default="all")
    stage_p = sub.add_parser("stage")
    stage_p.add_argument("--scope", choices=["all", "lilo", "cyberstitch"], default="all")
    stage_p.add_argument("--destination")
    stage_p.add_argument("--copy", action="store_true")
    report_p = sub.add_parser("report")
    report_p.add_argument("--plans-only", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "verify":
        return verify(args)
    if args.command == "stage":
        return stage(args)
    if args.command == "report":
        return report(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

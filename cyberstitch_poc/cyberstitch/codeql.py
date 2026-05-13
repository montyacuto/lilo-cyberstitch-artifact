import json
import shutil
import subprocess
from pathlib import Path

from .manifest import validate_manifest


def find_codeql(config=None):
    if config and config.codeql_binary:
        candidate = Path(config.codeql_binary)
        if candidate.exists() and candidate.is_file():
            return str(candidate)
    if config:
        candidate = Path(config.root).parent / "codeql" / "codeql"
        if candidate.exists() and candidate.is_file():
            return str(candidate)
    return shutil.which("codeql")


def require_codeql(config=None):
    codeql = find_codeql(config)
    if not codeql:
        raise RuntimeError(
            "CodeQL CLI is not installed or not configured. Set CYBERSTITCH_CODEQL=/path/to/codeql "
            "or add codeql to PATH; user-local installs are supported."
        )
    return codeql


def doctor(config):
    manifest = validate_manifest(
        config.curated_subset_manifest, config.owasp_root, config.selected_cwes
    )
    tools = {
        "java": _tool_status(["java", "-version"]),
        "mvn": _tool_status(["mvn", "-version"]),
        "codeql": _tool_status([find_codeql(config) or "codeql", "version"]),
    }
    actions = []
    if not tools["codeql"]["available"]:
        actions.append(
            "Install CodeQL CLI user-locally and set CYBERSTITCH_CODEQL=/absolute/path/to/codeql."
        )
    if not tools["java"]["available"]:
        actions.append("Install a JDK and ensure java is on PATH.")
    if not manifest["ok"]:
        actions.append("Fix the curated manifest or set CYBERSTITCH_OWASP_ROOT to a valid OWASP root.")
    return {
        "language": config.language,
        "owasp_root": str(config.owasp_root),
        "curated_subset_manifest": str(config.curated_subset_manifest),
        "selected_cwes": config.selected_cwes,
        "codeql_build_mode": config.codeql_build_mode,
        "codeql_build_command": config.codeql_build_command,
        "tools": tools,
        "manifest": manifest,
        "actions": actions,
    }


def create_database(
    config,
    source_root=None,
    database_dir=None,
    overwrite=False,
    build_mode=None,
    build_command=None,
):
    codeql = require_codeql(config)
    source_root = Path(source_root or config.owasp_root)
    database_dir = Path(database_dir or config.codeql_database_dir / config.language)
    database_dir.parent.mkdir(parents=True, exist_ok=True)
    if database_dir.exists() and not overwrite:
        return {"database": str(database_dir), "created": False, "reason": "already exists"}
    build_mode = build_mode or config.codeql_build_mode or "none"
    build_command = build_command or config.codeql_build_command
    args = [
        "database",
        "create",
        str(database_dir),
        "--language={}".format(config.language),
        "--source-root={}".format(source_root),
    ]
    if overwrite:
        args.append("--overwrite")
    if build_command:
        args.append("--command={}".format(build_command))
    elif build_mode:
        args.append("--build-mode={}".format(build_mode))
    run_codeql(args, config=config)
    return {
        "database": str(database_dir),
        "created": True,
        "source_root": str(source_root),
        "build_mode": "manual" if build_command else build_mode,
        "build_command": build_command,
    }


def analyze_database(config, query_path=None, database_dir=None, output_path=None):
    codeql = require_codeql(config)
    database_dir = Path(database_dir or config.codeql_database_dir / config.language)
    query_path = Path(query_path or config.query_dir)
    _ensure_query_pack(query_path, config.language)
    output_path = Path(output_path or config.sarif_dir / "analysis.sarif")
    common_cache_dir = config.results_dir / "codeql-cache" / "common"
    cache_dir = config.results_dir / "codeql-cache" / "compilation"
    common_cache_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    args = [
        "database",
        "analyze",
        "--common-caches={}".format(common_cache_dir),
        "--compilation-cache={}".format(cache_dir),
        "--no-default-compilation-cache",
        "--rerun",
        str(database_dir),
        str(query_path),
        "--format=sarif-latest",
        "--output={}".format(output_path),
    ]
    run_codeql(args, config=config)
    return {"sarif": str(output_path), "database": str(database_dir), "queries": str(query_path)}


def check_query_syntax(config, query_path=None, output_path=None, language=None):
    require_codeql(config)
    query_path = Path(query_path or config.query_dir)
    language = language or config.language
    compile_path = query_path / language if query_path.is_dir() and (query_path / language).exists() else query_path
    pack_path = compile_path if compile_path.is_dir() else compile_path.parent
    _ensure_query_pack(pack_path, language)
    common_cache_dir = config.results_dir / "codeql-cache" / "syntax-common"
    cache_dir = config.results_dir / "codeql-cache" / "syntax-compilation"
    common_cache_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    args = [
        "query",
        "compile",
        "--check-only",
        "--format=json",
        "--common-caches={}".format(common_cache_dir),
        "--compilation-cache={}".format(cache_dir),
        "--no-default-compilation-cache",
        "--",
        str(compile_path),
    ]
    completed = run_codeql_result(args, config=config)
    result = {
        "ok": completed.returncode == 0,
        "queries": str(compile_path),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": [require_codeql(config)] + args,
    }
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2))
    return result


def bundle_database(config, database_dir=None, output_path=None, include_diagnostics=True):
    require_codeql(config)
    database_dir = Path(database_dir or config.codeql_database_dir / config.language)
    output_path = Path(
        output_path
        or config.results_dir / "bundles" / "{}-codeql-debug-artifacts.zip".format(config.language)
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    args = ["database", "bundle", "--output={}".format(output_path)]
    if include_diagnostics:
        args.extend(["--include-diagnostics", "--include-logs", "--include-results"])
    args.extend(["--", str(database_dir)])
    run_codeql(args, config=config)
    return {
        "bundle": str(output_path),
        "database": str(database_dir),
        "bundle_profile": "debug" if include_diagnostics else "minimal",
        "includes_troubleshooting_artifacts": include_diagnostics,
        "contains_source_code": True,
        "package_by_default": False,
        "restricted_reason": (
            "CodeQL database bundles contain the analyzed source code; share only "
            "with recipients authorized to access that source."
        ),
    }


def run_codeql(args, config=None):
    completed = run_codeql_result(args, config=config)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout


def run_codeql_result(args, config=None):
    codeql = require_codeql(config)
    return subprocess.run(
        [codeql] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )


def write_doctor(config, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = doctor(config)
    output_path.write_text(json.dumps(result, indent=2))
    return result


def _tool_status(command):
    binary = command[0]
    if not binary or not shutil.which(binary) and "/" not in binary:
        return {"available": False, "path": None, "version": None}
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
    except FileNotFoundError:
        return {"available": False, "path": None, "version": None}
    output = _tool_output_lines(completed)
    return {
        "available": completed.returncode == 0,
        "path": shutil.which(binary) or binary,
        "version": output[0] if output else "",
    }


def _tool_output_lines(completed):
    raw = "{}\n{}".format(completed.stdout or "", completed.stderr or "")
    lines = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if "[warning][perf,memops]" in line:
            continue
        lines.append(line)
    return lines


def _ensure_query_pack(query_path, language):
    query_path = Path(query_path)
    if not query_path.is_dir() or (query_path / "qlpack.yml").exists():
        return
    dependencies = {
        "java": "codeql/java-all",
        "javascript": "codeql/javascript-all",
    }
    dependency = dependencies.get(language)
    if not dependency:
        return
    query_path.mkdir(parents=True, exist_ok=True)
    query_path.joinpath("qlpack.yml").write_text(
        "name: cyberstitch/generated-{}-queries\n"
        "version: 0.0.1\n"
        "dependencies:\n"
        "  {}: \"*\"\n".format(language, dependency)
    )

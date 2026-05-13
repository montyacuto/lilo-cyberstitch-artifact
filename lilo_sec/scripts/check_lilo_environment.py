#!/usr/bin/env python3
"""
Report whether the current machine can run the LILO reproduction stack.

This script is intentionally conservative: it checks for the pieces that fail
early in local setup without importing the full DreamCoder/LILO stack.
"""

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from importlib import metadata as importlib_metadata
except ImportError:
    import importlib_metadata


ROOT = Path(__file__).resolve().parents[1]
LOCAL_CONDA_ENV = ROOT / ".conda" / "envs" / "lilo"
LOCAL_OPAM_BIN = ROOT / "dreamcoder" / "solvers" / "_opam" / "bin"

PYTHON_MODULES = [
    "cairo",
    "cairocffi",
    "class_registry",
    "dill",
    "frozendict",
    "nltk",
    "numpy",
    "openai",
    "pathos",
    "pregex",
    "sexpdata",
    "stitch_core",
    "torch",
    "transformers",
]

PYTHON_PACKAGE_VERSION_REQUIREMENTS = {
    "stitch_core": "0.1.25",
}

COMMANDS = [
    "aws",
    "cargo",
    "codeql",
    "conda",
    "docker",
    "dune",
    "jbuilder",
    "ocaml",
    "opam",
    "rustc",
    "unzip",
]

PKG_CONFIG_LIBRARIES = ["cairo", "libzmq"]

LINUX_REQUIRED_BINARIES = [
    ROOT / "dreamcoder" / "compression",
    ROOT / "dreamcoder" / "helmholtz",
    ROOT / "dreamcoder" / "solver",
]


def local_tool_env():
    env = os.environ.copy()

    path_entries = []
    if LOCAL_OPAM_BIN.exists():
        path_entries.append(str(LOCAL_OPAM_BIN))
    if (LOCAL_CONDA_ENV / "bin").exists():
        path_entries.append(str(LOCAL_CONDA_ENV / "bin"))
    if env.get("PATH"):
        path_entries.append(env["PATH"])
    env["PATH"] = os.pathsep.join(path_entries)

    pkg_config_entries = [
        LOCAL_CONDA_ENV / "lib" / "pkgconfig",
        LOCAL_CONDA_ENV / "share" / "pkgconfig",
    ]
    existing_pkg_config_path = env.get("PKG_CONFIG_PATH")
    env["PKG_CONFIG_PATH"] = os.pathsep.join(
        [str(path) for path in pkg_config_entries if path.exists()]
        + ([existing_pkg_config_path] if existing_pkg_config_path else [])
    )

    if (LOCAL_CONDA_ENV / "lib").exists():
        existing_ld_path = env.get("LD_LIBRARY_PATH")
        env["LD_LIBRARY_PATH"] = os.pathsep.join(
            [str(LOCAL_CONDA_ENV / "lib")]
            + ([existing_ld_path] if existing_ld_path else [])
        )

    return env


def run(command, cwd=ROOT, env=None):
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=20,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except Exception as e:
        return {"ok": False, "error": "{}: {}".format(type(e).__name__, e)}


def command_version(command):
    env = local_tool_env()
    path = shutil.which(command, path=env.get("PATH"))
    if path is None:
        return {"path": None, "ok": False}
    version_flag = "--version"
    if command == "ocaml":
        version_flag = "-version"
    result = run([path, version_flag], env=env)
    return {
        "path": path,
        "ok": result["ok"],
        "version": result.get("stdout") or result.get("stderr"),
    }


def module_status(name):
    return importlib.util.find_spec(name) is not None


def package_version(name):
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return None


def binary_format(path):
    if not path.exists():
        return {"exists": False, "format": None, "linux_elf": False}
    result = run(["file", str(path)])
    description = result.get("stdout", "")
    return {
        "exists": True,
        "format": description,
        "linux_elf": "ELF" in description,
    }


def pkg_config_status(name):
    env = local_tool_env()
    pkg_config = env.get("PKG_CONFIG")
    if not pkg_config or shutil.which(pkg_config, path=env.get("PATH")) is None:
        pkg_config = shutil.which("pkg-config", path=env.get("PATH"))
    if not pkg_config:
        pkg_config = "/usr/bin/pkg-config" if Path("/usr/bin/pkg-config").exists() else None
    if pkg_config is None:
        return {"ok": False, "version": None, "reason": "pkg-config missing"}
    result = run([pkg_config, "--modversion", name], env=env)
    cflags = run([pkg_config, "--cflags", name], env=env) if result["ok"] else result
    return {
        "ok": result["ok"] and cflags["ok"],
        "version": result.get("stdout"),
        "reason": (result.get("stderr") or cflags.get("stderr")) if not cflags["ok"] else "",
        "pkg_config": pkg_config,
    }


def docker_status():
    env = local_tool_env()
    if shutil.which("docker", path=env.get("PATH")) is None:
        return {"available": False, "usable": False, "reason": "docker not found"}
    result = run(["docker", "ps"], env=env)
    return {
        "available": True,
        "usable": result["ok"],
        "reason": result.get("stderr") if not result["ok"] else "",
    }


def python_core_extensions():
    extensions = ["ssl", "sqlite3", "bz2", "lzma", "ctypes", "readline"]
    status = {}
    for module in extensions:
        status[module] = module_status(module)
    return status


def build_report():
    submodule = run(["git", "submodule", "status", "--recursive"])
    git_dreamcoder_initialized = (
        submodule["ok"]
        and "dreamcoder" in submodule.get("stdout", "")
        and not submodule.get("stdout", "").lstrip().startswith("-")
    )
    packaged_dreamcoder_present = (
        (ROOT / "dreamcoder" / "dreamcoder.py").exists()
        and all(path.exists() for path in LINUX_REQUIRED_BINARIES)
    )
    dreamcoder_initialized = git_dreamcoder_initialized or packaged_dreamcoder_present
    dreamcoder_status = submodule.get("stdout") or submodule.get("stderr")
    if packaged_dreamcoder_present and not git_dreamcoder_initialized:
        dreamcoder_status = "packaged DreamCoder source and Linux binaries present"

    return {
        "root": str(ROOT),
        "platform": platform.platform(),
        "python": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
            "is_3_7": sys.version_info[:2] == (3, 7),
            "core_extensions": python_core_extensions(),
        },
        "python_modules": {name: module_status(name) for name in PYTHON_MODULES},
        "python_package_versions": {
            name: package_version(name)
            for name in PYTHON_PACKAGE_VERSION_REQUIREMENTS
        },
        "commands": {name: command_version(name) for name in COMMANDS},
        "pkg_config": {
            name: pkg_config_status(name) for name in PKG_CONFIG_LIBRARIES
        },
        "docker": docker_status(),
        "dreamcoder_submodule": {
            "initialized": dreamcoder_initialized,
            "status": dreamcoder_status,
        },
        "linux_binaries": {
            str(path.relative_to(ROOT)): binary_format(path)
            for path in LINUX_REQUIRED_BINARIES
        },
    }


def runtime_blockers(report):
    failures = []
    if not report["python"]["is_3_7"]:
        failures.append("current Python is not 3.7")
    missing_core = [
        name
        for name, present in report["python"]["core_extensions"].items()
        if not present
    ]
    if missing_core:
        failures.append("Python core modules missing: {}".format(", ".join(missing_core)))
    missing_modules = [
        name for name, present in report["python_modules"].items() if not present
    ]
    if missing_modules:
        failures.append("Python packages missing: {}".format(", ".join(missing_modules)))
    version_mismatches = [
        "{}=={} required, found {}".format(name, expected, found or "missing")
        for name, expected in PYTHON_PACKAGE_VERSION_REQUIREMENTS.items()
        for found in [report["python_package_versions"].get(name)]
        if found != expected
    ]
    if version_mismatches:
        failures.append(
            "Python package version mismatch: {}".format(
                "; ".join(version_mismatches)
            )
        )
    if not report["dreamcoder_submodule"]["initialized"]:
        failures.append("DreamCoder source/binaries are not available")
    missing_binaries = [
        name
        for name, info in report["linux_binaries"].items()
        if not info["exists"] or not info["linux_elf"]
    ]
    if missing_binaries:
        failures.append(
            "DreamCoder Linux binaries missing or not ELF: {}".format(
                ", ".join(missing_binaries)
            )
        )
    return failures


def build_blockers(report):
    failures = []
    missing_commands = [
        name
        for name in ["cargo", "ocaml", "opam", "rustc", "unzip"]
        if not report["commands"][name]["path"]
    ]
    if missing_commands:
        failures.append("required commands missing: {}".format(", ".join(missing_commands)))
    missing_native = [
        name for name, info in report["pkg_config"].items() if not info["ok"]
    ]
    if missing_native:
        failures.append(
            "native development libraries missing: {}".format(", ".join(missing_native))
        )
    return failures


def print_text(report, failures, build_failures):
    print("LILO environment report")
    print("=======================")
    print("Root: {}".format(report["root"]))
    print("Python: {} ({})".format(report["python"]["version"], report["python"]["executable"]))
    print("DreamCoder submodule initialized: {}".format(report["dreamcoder_submodule"]["initialized"]))
    print("Docker usable: {}".format(report["docker"]["usable"]))
    print("")
    print("Missing Python packages:")
    for name, present in sorted(report["python_modules"].items()):
        if not present:
            print("  - {}".format(name))
    print("")
    print("Pinned Python package versions:")
    for name, expected in sorted(PYTHON_PACKAGE_VERSION_REQUIREMENTS.items()):
        found = report["python_package_versions"].get(name)
        status = "ok" if found == expected else "expected {}".format(expected)
        print("  - {}: {} ({})".format(name, found or "missing", status))
    print("")
    print("Command paths:")
    for name, info in sorted(report["commands"].items()):
        print("  - {}: {}".format(name, info["path"] or "missing"))
    print("")
    print("Native build libraries:")
    for name, info in sorted(report["pkg_config"].items()):
        print(
            "  - {}: {}{}".format(
                name,
                info["version"] or "missing",
                " via {}".format(info["pkg_config"]) if info.get("pkg_config") else "",
            )
        )
    print("")
    if failures:
        print("Blockers:")
        for failure in failures:
            print("  - {}".format(failure))
    else:
        print("No blockers detected by this script.")
    print("")
    if build_failures:
        print("Build-only blockers:")
        for failure in build_failures:
            print("  - {}".format(failure))
        print("Use --require-build-deps to make these fail verification.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--no-fail", action="store_true", help="Always exit 0.")
    parser.add_argument(
        "--require-build-deps",
        action="store_true",
        help="Fail if OCaml/Rust/pkg-config dependencies needed to rebuild bundled binaries are missing.",
    )
    args = parser.parse_args()

    report = build_report()
    failures = runtime_blockers(report)
    build_failures = build_blockers(report)
    if args.require_build_deps:
        failures = failures + build_failures
    if args.json:
        print(
            json.dumps(
                {
                    "report": report,
                    "blockers": failures,
                    "build_only_blockers": build_failures,
                },
                indent=2,
            )
        )
    else:
        print_text(report, failures, build_failures)

    if failures and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

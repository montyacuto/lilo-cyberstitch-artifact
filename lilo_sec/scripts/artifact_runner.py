#!/usr/bin/env python3
"""Combined artifact command runner for LILO and CyberSTITCH."""

from __future__ import print_function

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from artifact_tasks import TASKS, get_task, tasks_for_section


LILO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = LILO_ROOT.parent
OPENAI_ENV = Path.home() / ".config" / "lilo" / "openai.env"


def project_path(relpath):
    return PROJECT_ROOT / relpath


def display_command(task, extra_args=None):
    cwd = project_path(task["cwd"])
    env = task.get("env") or {}
    argv = resolve_argv(task["argv"], os.environ)
    if extra_args:
        argv = argv + list(extra_args)
    pieces = ["cd {}".format(shlex.quote(str(cwd)))]
    for key in sorted(env):
        pieces.append("{}={}".format(key, shlex.quote(env[key])))
    pieces.extend(shlex.quote(str(item)) for item in argv)
    return " ".join(pieces)


def resolve_argv(argv, env):
    resolved = []
    for item in argv:
        if item == "$CYBERSTITCH_PYTHON":
            resolved.append(env.get("CYBERSTITCH_PYTHON", "python3"))
        elif item == "$PYTHON":
            resolved.append(env.get("PYTHON", "python3"))
        else:
            resolved.append(item)
    return resolved


def load_env_file(path, env):
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = shlex.split(line, posix=True)
        except ValueError:
            continue
        if not parts:
            continue
        if parts[0] == "export":
            parts = parts[1:]
        for part in parts:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key and key not in env:
                env[key] = value


def confirm_task(task, assume_yes):
    if task.get("live_api"):
        confirm_vars = ["ARTIFACT_CONFIRM_LIVE_API"]
        if task["section"] == "lilo":
            confirm_vars.append("LILO_CONFIRM_LIVE_LLM")
        if task["section"] == "cyberstitch":
            confirm_vars.append("CYBERSTITCH_CONFIRM_LIVE_LILO")
        confirmed = assume_yes or any(os.environ.get(key) == "YES" for key in confirm_vars)
        if not confirmed:
            print("Refusing live API task without confirmation: {}".format(task["id"]), file=sys.stderr)
            print("Set ARTIFACT_CONFIRM_LIVE_API=YES or pass --yes to run this task.", file=sys.stderr)
            return False
    elif task.get("long_running"):
        confirmed = assume_yes or os.environ.get("ARTIFACT_CONFIRM_LONG_RUN") == "YES"
        if not confirmed and sys.stdin.isatty():
            print("Task may be long-running: {}".format(task["label"]))
            answer = input("Type RUN to continue: ").strip()
            confirmed = answer == "RUN"
        if not confirmed:
            print("Refusing long-running task without confirmation: {}".format(task["id"]), file=sys.stderr)
            print("Set ARTIFACT_CONFIRM_LONG_RUN=YES or pass --yes to run it.", file=sys.stderr)
            return False
    return True


def run_task(task_id, assume_yes=False, print_command=False, extra_args=None):
    task = get_task(task_id)
    if print_command:
        print(display_command(task, extra_args=extra_args))
        return 0
    if not confirm_task(task, assume_yes):
        return 2

    env = os.environ.copy()
    if task.get("live_api"):
        load_env_file(OPENAI_ENV, env)
    for key, value in (task.get("env") or {}).items():
        env[key] = value
    missing = [key for key in task.get("requires", []) if not env.get(key)]
    if missing:
        print(
            "Missing required environment for {}: {}".format(
                task_id, ", ".join(missing)
            ),
            file=sys.stderr,
        )
        if "OPENAI_API_KEY" in missing:
            print("Expected key source: {}".format(OPENAI_ENV), file=sys.stderr)
        return 2

    cwd = project_path(task["cwd"])
    argv = resolve_argv(task["argv"], env)
    if extra_args:
        argv = argv + list(extra_args)
    print("+ {}".format(display_command(task, extra_args=extra_args)), flush=True)
    return subprocess.call(argv, cwd=str(cwd), env=env)


def run_many(task_ids, assume_yes=False):
    for task_id in task_ids:
        status = run_task(task_id, assume_yes=assume_yes)
        if status != 0:
            return status
    return 0


def print_tasks(section=None, as_json=False):
    tasks = tasks_for_section(section) if section else TASKS
    if as_json:
        print(json.dumps(tasks, indent=2, sort_keys=True))
        return 0
    current = None
    for task in tasks:
        if task["section"] != current:
            current = task["section"]
            print("")
            print("{}:".format(current))
        flags = []
        if task.get("live_api"):
            flags.append("live")
        if task.get("long_running"):
            flags.append("long")
        suffix = " [{}]".format(", ".join(flags)) if flags else ""
        estimate = " ({})".format(task["estimate"]) if task.get("estimate") else ""
        print("  {:42} {}{}{}".format(task["id"], task["label"], estimate, suffix))
        print("      {}".format(task["description"]))
    return 0


def reproduce(args):
    profile_to_task = {
        "combined-pack": "cyberstitch-live-combined-pack",
        "official-expanded-pack": "cyberstitch-live-official-expanded-pack",
        "companion-pack": "cyberstitch-live-official-expanded-pack",
        "bounded-java-pack": "cyberstitch-live-bounded-pack",
        "bounded-pack": "cyberstitch-live-bounded-pack",
    }
    deterministic_profile_to_task = {
        "combined-pack": "cyberstitch-run-combined-pack",
        "official-expanded-pack": "cyberstitch-run-official-expanded-pack",
        "companion-pack": "cyberstitch-run-official-expanded-pack",
        "bounded-java-pack": "cyberstitch-run-bounded-pack",
        "bounded-pack": "cyberstitch-run-bounded-pack",
    }

    if args.suite == "lilo":
        if args.mode == "live":
            return run_task("lilo-run-live", assume_yes=args.yes)
        if args.mode == "replay":
            return run_task("lilo-run-replay", assume_yes=args.yes)
        return run_task("lilo-smoke", assume_yes=args.yes)

    if args.suite == "cyberstitch":
        if args.mode == "live":
            task_id = profile_to_task.get(args.profile)
            if not task_id:
                print("Unknown live CyberSTITCH profile: {}".format(args.profile), file=sys.stderr)
                return 2
            return run_task(task_id, assume_yes=args.yes)
        if args.mode == "fixture":
            return run_task("cyberstitch-lilo-loop-smoke", assume_yes=args.yes)
        if args.mode == "replay":
            task_id = deterministic_profile_to_task.get(args.profile)
            if not task_id:
                print("Unknown deterministic CyberSTITCH profile: {}".format(args.profile), file=sys.stderr)
                return 2
            return run_task(task_id, assume_yes=args.yes)

    if args.suite == "all":
        if args.mode == "live":
            return run_many(
                ["lilo-run-live", profile_to_task.get(args.profile, "cyberstitch-live-official-expanded-pack")],
                assume_yes=args.yes,
            )
        return run_many(
            ["lilo-smoke", "cyberstitch-lilo-loop-smoke", "package-verify-all"],
            assume_yes=args.yes,
        )

    print("Unsupported reproduce request.", file=sys.stderr)
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Combined LILO/CyberSTITCH artifact runner."
    )
    sub = parser.add_subparsers(dest="command")

    tasks_p = sub.add_parser("tasks", help="List registered artifact tasks.")
    tasks_p.add_argument("--section", choices=["lilo", "cyberstitch", "package"])
    tasks_p.add_argument("--json", action="store_true")

    run_p = sub.add_parser("run-task", help="Run a registered artifact task.")
    run_p.add_argument("task_id")
    run_p.add_argument("--yes", action="store_true", help="Confirm live/long task execution.")
    run_p.add_argument("--print-command", action="store_true")

    sub.add_parser("verify", help="Run the default non-destructive verification.")
    sub.add_parser("package-smoke", help="Run package-only smoke checks that need no LILO/CyberSTITCH env.")
    sub.add_parser("smoke", help="Run default offline smoke checks after environments are prepared.")
    sub.add_parser("package-plan", help="Print package plan pointers.")
    package_verify = sub.add_parser("package-verify", help="Verify package inputs.")
    package_verify.add_argument("--scope", choices=["all", "lilo", "cyberstitch"], default="all")
    package_stage = sub.add_parser("package-stage", help="Write or copy a package staging manifest.")
    package_stage.add_argument("--scope", choices=["all", "lilo", "cyberstitch"], default="all")
    package_stage.add_argument("--destination")
    package_stage.add_argument("--copy", action="store_true")
    sub.add_parser("report", help="Print package/reproduction report pointers.")

    repro = sub.add_parser("reproduce", help="Run a suite in fixture/replay/live mode.")
    repro.add_argument("--suite", choices=["lilo", "cyberstitch", "all"], default="all")
    repro.add_argument("--mode", choices=["fixture", "replay", "live"], default="fixture")
    repro.add_argument("--profile", default="official-expanded-pack")
    repro.add_argument("--yes", action="store_true")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    if args.command == "tasks":
        return print_tasks(section=args.section, as_json=args.json)
    if args.command == "run-task":
        return run_task(
            args.task_id,
            assume_yes=args.yes,
            print_command=args.print_command,
        )
    if args.command == "verify":
        return run_many(["lilo-verify-env", "cyberstitch-doctor", "package-verify-all"])
    if args.command == "package-smoke":
        return run_task("package-smoke")
    if args.command == "smoke":
        return run_many(["lilo-smoke", "cyberstitch-extension-smoke"])
    if args.command == "package-plan":
        return run_task("artifact-report", extra_args=["--plans-only"])
    if args.command == "package-verify":
        return run_task("package-verify-all", extra_args=["--scope", args.scope])
    if args.command == "package-stage":
        extra = ["--scope", args.scope]
        if args.destination:
            extra.extend(["--destination", args.destination])
        if args.copy:
            extra.append("--copy")
        return run_task("package-stage-manifest", extra_args=extra)
    if args.command == "report":
        return run_task("artifact-report")
    if args.command == "reproduce":
        return reproduce(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Interactive terminal menu for the LILO reproduction artifact.

The menu is intentionally conservative: it estimates and dry-runs by default.
Live LLM runs require an explicit mode switch and confirmation.
"""

import argparse
import os
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from artifact_tasks import get_task, tasks_for_section


LILO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = LILO_ROOT.parent
BASELINE_CPUS = 32
DEFAULT_SEEDS = ["111"]
DEFAULT_INIT_RUN_ID = "cheap_init_all_domains_20260505"

DOMAINS = {
    "re2": {
        "label": "REGEX",
        "default_iterations": 16,
        "default_timeout": 1000,
        "hours_per_seed_at_32": 21.0,
        "basis": "REGEX seed-111 probe through iteration 9, extrapolated to 16 iterations",
    },
    "clevr": {
        "label": "CLEVR",
        "default_iterations": 10,
        "default_timeout": 600,
        "hours_per_seed_at_32": 4.5,
        "basis": "CLEVR steady-state iteration-1 timing, extrapolated to held-out evals",
    },
    "logo": {
        "label": "LOGO",
        "default_iterations": 10,
        "default_timeout": 1800,
        "hours_per_seed_at_32": 8.0,
        "basis": "rough local planning estimate; LOGO has not yet been timed",
    },
}


def available_cpus():
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def fmt_duration(hours):
    if hours < 1.0 / 60.0:
        return "<1 min"
    minutes = int(round(hours * 60))
    days, rem_minutes = divmod(minutes, 60 * 24)
    whole_hours, mins = divmod(rem_minutes, 60)
    parts = []
    if days:
        parts.append("{}d".format(days))
    if whole_hours:
        parts.append("{}h".format(whole_hours))
    if mins or not parts:
        parts.append("{}m".format(mins))
    return " ".join(parts)


def parse_list(raw):
    return [item.strip() for item in raw.replace(",", " ").split() if item.strip()]


def parse_domains(raw):
    values = parse_list(raw.lower())
    if not values or values == ["all"]:
        return list(DOMAINS)
    selected = []
    number_map = {"1": "re2", "2": "clevr", "3": "logo"}
    for value in values:
        domain = number_map.get(value, value)
        if domain not in DOMAINS:
            raise ValueError("unknown benchmark: {}".format(value))
        if domain not in selected:
            selected.append(domain)
    return selected


def parse_seeds(raw):
    seeds = parse_list(raw)
    if not seeds:
        raise ValueError("at least one seed is required")
    for seed in seeds:
        int(seed)
    return seeds


class Plan:
    def __init__(self):
        self.domains = ["re2"]
        self.seeds = list(DEFAULT_SEEDS)
        self.iterations = {
            domain: meta["default_iterations"] for domain, meta in DOMAINS.items()
        }
        self.timeouts = {
            domain: meta["default_timeout"] for domain, meta in DOMAINS.items()
        }
        self.batch_size = min(32, available_cpus())
        self.recognition_steps = 10000
        self.init_run_id = DEFAULT_INIT_RUN_ID
        self.run_id = "menu_lilo_{}".format(datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.dry_run = True
        self.start_litellm = True
        self.llm_cache_mode = "record"
        self.llm_cache_dir = ""

    def effective_cpus(self):
        return max(1, min(available_cpus(), int(self.batch_size)))

    def domain_hours(self, domain):
        meta = DOMAINS[domain]
        iteration_scale = float(self.iterations[domain]) / float(meta["default_iterations"])
        timeout_scale = float(self.timeouts[domain]) / float(meta["default_timeout"])
        recognition_scale = float(self.recognition_steps) / 10000.0

        # Empirical wall-clock observations are a mix of enumeration/search,
        # recognition training, and LLM/API overhead. Keep LLM overhead fixed,
        # and scale the other parts with the exposed knobs.
        work_scale = 0.65 * timeout_scale + 0.20 * recognition_scale + 0.15
        cpu_scale = float(BASELINE_CPUS) / float(self.effective_cpus())
        return (
            meta["hours_per_seed_at_32"]
            * iteration_scale
            * work_scale
            * cpu_scale
            * len(self.seeds)
        )

    def total_hours(self):
        return sum(self.domain_hours(domain) for domain in self.domains)

    def env(self):
        env = os.environ.copy()
        start_litellm = self.start_litellm
        if self.llm_cache_mode == "replay":
            start_litellm = False
        env.update(
            {
                "LILO_FULL_RUN_ID": self.run_id,
                "LILO_FULL_DOMAINS": " ".join(self.domains),
                "LILO_FULL_SEEDS": " ".join(self.seeds),
                "LILO_FULL_BATCH_SIZE": str(self.batch_size),
                "LILO_FULL_RECOGNITION_STEPS": str(self.recognition_steps),
                "LILO_INIT_RUN_ID": self.init_run_id,
                "LILO_START_LITELLM": "1" if start_litellm else "0",
                "LILO_LLM_CACHE_MODE": self.llm_cache_mode,
            }
        )
        if self.llm_cache_dir:
            env["LILO_LLM_CACHE_DIR"] = self.llm_cache_dir
        if self.dry_run:
            env["LILO_DRY_RUN"] = "1"
            env.pop("LILO_CONFIRM_LIVE_LLM", None)
        else:
            env["LILO_DRY_RUN"] = "0"
            if self.llm_cache_mode == "replay":
                env.pop("LILO_CONFIRM_LIVE_LLM", None)
            else:
                env["LILO_CONFIRM_LIVE_LLM"] = "YES"

        for domain in DOMAINS:
            upper = "RE2" if domain == "re2" else domain.upper()
            env["LILO_FULL_{}_ITERATIONS".format(upper)] = str(self.iterations[domain])
            env["LILO_FULL_{}_TIMEOUT".format(upper)] = str(self.timeouts[domain])
        return env

    def shell_command(self):
        keys = [
            "LILO_FULL_RUN_ID",
            "LILO_FULL_DOMAINS",
            "LILO_FULL_SEEDS",
            "LILO_FULL_BATCH_SIZE",
            "LILO_FULL_RECOGNITION_STEPS",
            "LILO_INIT_RUN_ID",
            "LILO_START_LITELLM",
            "LILO_LLM_CACHE_MODE",
            "LILO_LLM_CACHE_DIR",
            "LILO_DRY_RUN",
            "LILO_CONFIRM_LIVE_LLM",
            "LILO_FULL_RE2_ITERATIONS",
            "LILO_FULL_RE2_TIMEOUT",
            "LILO_FULL_CLEVR_ITERATIONS",
            "LILO_FULL_CLEVR_TIMEOUT",
            "LILO_FULL_LOGO_ITERATIONS",
            "LILO_FULL_LOGO_TIMEOUT",
        ]
        env = self.env()
        lines = ["cd {}".format(shlex.quote(str(LILO_ROOT)))]
        for key in keys:
            if key in env:
                lines.append("export {}={}".format(key, shlex.quote(env[key])))
        lines.append("scripts/artifact.sh run-lilo")
        return "\n".join(lines)


def print_estimate(plan):
    cpus = available_cpus()
    effective = plan.effective_cpus()
    if plan.dry_run:
        mode = "dry-run command generation"
    elif plan.llm_cache_mode == "replay":
        mode = "offline LLM replay"
    else:
        mode = "LIVE LLM RUN"
    print()
    print("LILO reproduction plan")
    print("======================")
    print("Run ID: {}".format(plan.run_id))
    print("Mode: {}".format(mode))
    print("Benchmarks: {}".format(", ".join(DOMAINS[d]["label"] for d in plan.domains)))
    print("Seeds: {}".format(" ".join(plan.seeds)))
    print("Batch size: {}".format(plan.batch_size))
    print("Recognition steps: {}".format(plan.recognition_steps))
    print("Initialization run: {}".format(plan.init_run_id))
    print("LLM cache mode: {}".format(plan.llm_cache_mode))
    if plan.llm_cache_dir:
        print("LLM cache dir: {}".format(plan.llm_cache_dir))
    print(
        "Visible CPUs: {}; estimate uses effective parallelism min(CPUs, batch) = {}".format(
            cpus, effective
        )
    )
    print()
    print("{:<8} {:>10} {:>8} {:>10} {:>12}".format("Domain", "Iterations", "Seeds", "Timeout", "Estimate"))
    print("-" * 54)
    for domain in plan.domains:
        print(
            "{:<8} {:>10} {:>8} {:>8}s {:>12}".format(
                DOMAINS[domain]["label"],
                plan.iterations[domain],
                len(plan.seeds),
                plan.timeouts[domain],
                fmt_duration(plan.domain_hours(domain)),
            )
        )
    print("-" * 54)
    print("{:<8} {:>43}".format("Total", fmt_duration(plan.total_hours())))
    print()
    print("Estimate basis:")
    for domain in plan.domains:
        print("- {}: {}".format(DOMAINS[domain]["label"], DOMAINS[domain]["basis"]))
    print("Estimates are approximate and assume sequential runs through LiteLLM/OpenAI.")
    print()


def prompt(default, label):
    suffix = " [{}]".format(default) if default not in (None, "") else ""
    raw = input("{}{}: ".format(label, suffix)).strip()
    return raw if raw else default


def set_benchmarks(plan):
    print()
    print("Benchmarks:")
    print("  1) re2   REGEX")
    print("  2) clevr CLEVR")
    print("  3) logo  LOGO/compositional graphics")
    print("Enter numbers or names separated by spaces, or 'all'.")
    raw = prompt(" ".join(plan.domains), "Selected benchmarks")
    try:
        plan.domains = parse_domains(raw)
    except ValueError as exc:
        print("Invalid benchmark selection: {}".format(exc))


def set_seeds(plan):
    raw = prompt(" ".join(plan.seeds), "Seeds")
    try:
        plan.seeds = parse_seeds(raw)
    except ValueError as exc:
        print("Invalid seeds: {}".format(exc))


def set_iterations(plan):
    print()
    print("Current iterations:")
    for domain in DOMAINS:
        selected = "*" if domain in plan.domains else " "
        print(
            " {} {:<5} {} ({})".format(
                selected,
                domain,
                plan.iterations[domain],
                DOMAINS[domain]["label"],
            )
        )
    print("Enter a single number for all selected benchmarks, or assignments like re2=16 clevr=10.")
    raw = input("Iterations: ").strip()
    if not raw:
        return
    try:
        if raw.isdigit():
            value = int(raw)
            for domain in plan.domains:
                plan.iterations[domain] = value
            return
        for token in parse_list(raw):
            if "=" not in token:
                raise ValueError("expected domain=value, got {}".format(token))
            domain, value = token.split("=", 1)
            domain = domain.lower()
            if domain not in DOMAINS:
                raise ValueError("unknown domain {}".format(domain))
            plan.iterations[domain] = int(value)
    except ValueError as exc:
        print("Invalid iterations: {}".format(exc))


def set_timeouts(plan):
    print()
    print("Current enumeration timeouts:")
    for domain in DOMAINS:
        selected = "*" if domain in plan.domains else " "
        print(
            " {} {:<5} {}s ({})".format(
                selected,
                domain,
                plan.timeouts[domain],
                DOMAINS[domain]["label"],
            )
        )
    print("Enter a single number for all selected benchmarks, or assignments like re2=1000 clevr=600.")
    raw = input("Enumeration timeout seconds: ").strip()
    if not raw:
        return
    try:
        if raw.isdigit():
            value = int(raw)
            for domain in plan.domains:
                plan.timeouts[domain] = value
            return
        for token in parse_list(raw):
            if "=" not in token:
                raise ValueError("expected domain=value, got {}".format(token))
            domain, value = token.split("=", 1)
            domain = domain.lower()
            if domain not in DOMAINS:
                raise ValueError("unknown domain {}".format(domain))
            plan.timeouts[domain] = int(value)
    except ValueError as exc:
        print("Invalid timeout: {}".format(exc))


def set_advanced(plan):
    while True:
        print()
        print("Advanced parameters")
        print("1) Batch size: {}".format(plan.batch_size))
        print("2) Recognition train steps: {}".format(plan.recognition_steps))
        print("3) Enumeration timeouts")
        print("4) Initialization run: {}".format(plan.init_run_id))
        print("5) Run ID: {}".format(plan.run_id))
        print("6) Start LiteLLM automatically: {}".format("yes" if plan.start_litellm else "no"))
        print("7) LLM cache mode: {}".format(plan.llm_cache_mode))
        print("8) LLM cache directory: {}".format(plan.llm_cache_dir or "<run default>"))
        print("0) Back")
        choice = input("Choice: ").strip().lower()
        try:
            if choice == "1":
                plan.batch_size = int(prompt(str(plan.batch_size), "Batch size"))
            elif choice == "2":
                plan.recognition_steps = int(
                    prompt(str(plan.recognition_steps), "Recognition train steps")
                )
            elif choice == "3":
                set_timeouts(plan)
            elif choice == "4":
                plan.init_run_id = prompt(plan.init_run_id, "Initialization run ID")
            elif choice == "5":
                plan.run_id = prompt(plan.run_id, "Run ID")
            elif choice == "6":
                plan.start_litellm = not plan.start_litellm
            elif choice == "7":
                modes = ["off", "record", "replay"]
                plan.llm_cache_mode = modes[
                    (modes.index(plan.llm_cache_mode) + 1) % len(modes)
                ]
            elif choice == "8":
                plan.llm_cache_dir = prompt(
                    plan.llm_cache_dir, "LLM cache directory"
                )
            elif choice in ("0", "q", "quit", "back"):
                return
            else:
                print("Unknown choice.")
        except ValueError as exc:
            print("Invalid value: {}".format(exc))


def run_artifact_command(command, env=None):
    return subprocess.call(["scripts/artifact.sh", command], cwd=str(LILO_ROOT), env=env)


def run_artifact_runner(args, env=None):
    return subprocess.call(
        ["scripts/artifact_runner.py"] + list(args), cwd=str(LILO_ROOT), env=env
    )


def task_flags(task):
    flags = []
    if task.get("live_api"):
        flags.append("live API")
    if task.get("long_running"):
        flags.append("long")
    if task.get("estimate"):
        flags.append(task["estimate"])
    return ", ".join(flags)


def print_task_list(task_ids):
    for index, task_id in enumerate(task_ids, start=1):
        task = get_task(task_id)
        flags = task_flags(task)
        suffix = " [{}]".format(flags) if flags else ""
        print("{:>2}) {}{}".format(index, task["label"], suffix))
        print("    {}".format(task["description"]))


def run_registered_task(task_id):
    task = get_task(task_id)
    print()
    print(task["label"])
    print("-" * len(task["label"]))
    print(task["description"])
    print()
    print("Command:")
    run_artifact_runner(["run-task", task_id, "--print-command"])
    print()
    if task.get("live_api"):
        answer = input("Type LIVE to run this API-backed task, or p to print only: ").strip()
        if answer.lower() == "p":
            return 0
        if answer != "LIVE":
            print("Cancelled.")
            return 1
        return run_artifact_runner(["run-task", task_id, "--yes"])
    if task.get("long_running"):
        answer = input("Type RUN to start this long task, or p to print only: ").strip()
        if answer.lower() == "p":
            return 0
        if answer != "RUN":
            print("Cancelled.")
            return 1
        return run_artifact_runner(["run-task", task_id, "--yes"])
    answer = input("Run now? [Y/n]: ").strip().lower()
    if answer not in ("", "y", "yes"):
        print("Cancelled.")
        return 1
    return run_artifact_runner(["run-task", task_id])


def registered_task_menu(title, task_ids):
    while True:
        print()
        print(title)
        print("=" * len(title))
        print_task_list(task_ids)
        print(" p) Print all commands")
        print(" 0) Back")
        choice = input("Choice: ").strip().lower()
        if choice in ("0", "q", "quit", "back"):
            return 0
        if choice == "p":
            for task_id in task_ids:
                run_artifact_runner(["run-task", task_id, "--print-command"])
            continue
        try:
            index = int(choice)
        except ValueError:
            print("Unknown choice.")
            continue
        if index < 1 or index > len(task_ids):
            print("Unknown choice.")
            continue
        run_registered_task(task_ids[index - 1])


def cyberstitch_menu():
    task_ids = [
        "cyberstitch-doctor",
        "cyberstitch-extension-smoke",
        "cyberstitch-lilo-loop-smoke",
        "cyberstitch-autodoc-eval-smoke",
        "cyberstitch-package-verify",
        "cyberstitch-run-combined-pack",
        "cyberstitch-run-official-expanded-pack",
        "cyberstitch-run-bounded-pack",
        "cyberstitch-live-combined-pack",
        "cyberstitch-live-official-expanded-pack",
        "cyberstitch-live-bounded-pack",
    ]
    return registered_task_menu("CyberSTITCH / CodeQL", task_ids)


def combined_artifact_menu():
    while True:
        print()
        print("Combined Artifact Checks")
        print("========================")
        print("1) Run default verification")
        print("2) Run default offline smoke checks")
        print("3) Verify selected package inputs")
        print("4) Write package staging manifest")
        print("5) Print report pointers")
        print("6) List registered tasks")
        print("0) Back")
        choice = input("Choice: ").strip().lower()
        if choice == "1":
            run_artifact_runner(["verify"])
        elif choice == "2":
            run_artifact_runner(["smoke"])
        elif choice == "3":
            run_registered_task("package-verify-all")
        elif choice == "4":
            run_registered_task("package-stage-manifest")
        elif choice == "5":
            run_registered_task("artifact-report")
        elif choice == "6":
            run_artifact_runner(["tasks"])
        elif choice in ("0", "q", "quit", "back"):
            return 0
        else:
            print("Unknown choice.")


def lilo_support_menu():
    task_ids = [task["id"] for task in tasks_for_section("lilo")]
    return registered_task_menu("LILO Support Tasks", task_ids)


def run_plan(plan):
    print_estimate(plan)
    if plan.dry_run:
        answer = input("Generate dry-run commands now? [Y/n]: ").strip().lower()
        if answer not in ("", "y", "yes"):
            return 1
    else:
        if plan.llm_cache_mode == "replay":
            print(
                "This will run offline from the LLM cache and may run for {}".format(
                    fmt_duration(plan.total_hours())
                )
            )
            answer = input("Type REPLAY to start the offline replay: ").strip()
            expected = "REPLAY"
        else:
            print("This will start live LLM/API calls and may run for {}".format(fmt_duration(plan.total_hours())))
            answer = input("Type RUN to start the live run: ").strip()
            expected = "RUN"
        if answer != expected:
            print("Cancelled.")
            return 1
    return run_artifact_command("run-lilo", env=plan.env())


def lilo_reproduction_menu():
    plan = Plan()
    while True:
        print_estimate(plan)
        print("LILO Reproduction")
        print("1) Select benchmarks")
        print("2) Set seeds")
        print("3) Set iterations")
        print("4) Advanced parameters")
        print("5) Toggle dry-run/live")
        print("6) Show generated shell command")
        print("7) Run selected plan")
        print("8) Verify environment")
        print("9) Run offline smoke test")
        print("10) LILO support tasks")
        print("0) Quit")
        choice = input("Choice: ").strip().lower()
        if choice == "1":
            set_benchmarks(plan)
        elif choice == "2":
            set_seeds(plan)
        elif choice == "3":
            set_iterations(plan)
        elif choice == "4":
            set_advanced(plan)
        elif choice == "5":
            plan.dry_run = not plan.dry_run
        elif choice == "6":
            print()
            print(plan.shell_command())
            print()
        elif choice == "7":
            run_plan(plan)
        elif choice == "8":
            run_artifact_command("verify-env")
        elif choice == "9":
            run_artifact_command("smoke")
        elif choice == "10":
            lilo_support_menu()
        elif choice in ("0", "q", "quit", "exit"):
            return 0
        else:
            print("Unknown choice.")


def interactive():
    while True:
        print()
        print("Combined LILO / CyberSTITCH Artifact")
        print("====================================")
        print("1) LILO reproduction")
        print("2) CyberSTITCH / CodeQL")
        print("3) Combined artifact checks")
        print("4) List all registered tasks")
        print("0) Quit")
        choice = input("Choice: ").strip().lower()
        if choice == "1":
            lilo_reproduction_menu()
        elif choice == "2":
            cyberstitch_menu()
        elif choice == "3":
            combined_artifact_menu()
        elif choice == "4":
            run_artifact_runner(["tasks"])
        elif choice in ("0", "q", "quit", "exit"):
            return 0
        else:
            print("Unknown choice.")


def apply_args_to_plan(args):
    plan = Plan()
    if args.domains:
        plan.domains = parse_domains(" ".join(args.domains))
    if args.seeds:
        plan.seeds = parse_seeds(" ".join(args.seeds))
    if args.iterations is not None:
        for domain in plan.domains:
            plan.iterations[domain] = args.iterations
    for item in args.domain_iterations or []:
        domain, value = item.split("=", 1)
        domain = domain.lower()
        if domain not in DOMAINS:
            raise ValueError("unknown domain in --domain-iterations: {}".format(domain))
        plan.iterations[domain] = int(value)
    if args.timeout is not None:
        for domain in plan.domains:
            plan.timeouts[domain] = args.timeout
    for item in args.domain_timeouts or []:
        domain, value = item.split("=", 1)
        domain = domain.lower()
        if domain not in DOMAINS:
            raise ValueError("unknown domain in --domain-timeouts: {}".format(domain))
        plan.timeouts[domain] = int(value)
    if args.batch_size is not None:
        plan.batch_size = args.batch_size
    if args.recognition_steps is not None:
        plan.recognition_steps = args.recognition_steps
    if args.init_run_id:
        plan.init_run_id = args.init_run_id
    if args.run_id:
        plan.run_id = args.run_id
    if args.no_start_litellm:
        plan.start_litellm = False
    if args.llm_cache_mode:
        plan.llm_cache_mode = args.llm_cache_mode
    if args.llm_cache_dir:
        plan.llm_cache_dir = args.llm_cache_dir
    if args.live:
        plan.dry_run = False
    if args.dry_run:
        plan.dry_run = True
    return plan


def build_parser():
    parser = argparse.ArgumentParser(
        description="Terminal menu and estimator for LILO reproduction runs."
    )
    parser.add_argument("--estimate", action="store_true", help="Print the estimate and exit.")
    parser.add_argument(
        "--print-command", action="store_true", help="Print the generated shell command and exit."
    )
    parser.add_argument("--run", action="store_true", help="Run the selected plan.")
    parser.add_argument("--domains", nargs="+", help="Benchmarks: re2 clevr logo or all.")
    parser.add_argument("--seeds", nargs="+", help="Random seeds, e.g. 111 222 333.")
    parser.add_argument("--iterations", type=int, help="Iteration count for all selected domains.")
    parser.add_argument(
        "--domain-iterations",
        nargs="+",
        help="Domain-specific iteration counts, e.g. re2=16 clevr=10 logo=10.",
    )
    parser.add_argument("--timeout", type=int, help="Enumeration timeout for all selected domains.")
    parser.add_argument(
        "--domain-timeouts",
        nargs="+",
        help="Domain-specific timeouts, e.g. re2=1000 clevr=600 logo=1800.",
    )
    parser.add_argument("--batch-size", type=int, help="Global batch size.")
    parser.add_argument("--recognition-steps", type=int, help="Recognition train steps.")
    parser.add_argument("--init-run-id", help="Initialization checkpoint run ID.")
    parser.add_argument("--run-id", help="Experiment run ID.")
    parser.add_argument("--no-start-litellm", action="store_true", help="Do not auto-start LiteLLM.")
    parser.add_argument(
        "--llm-cache-mode",
        choices=["off", "record", "replay"],
        help="LLM cache mode for completions and embeddings.",
    )
    parser.add_argument("--llm-cache-dir", help="LLM cache directory.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Generate commands only.")
    mode.add_argument("--live", action="store_true", help="Permit live LLM/API run.")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not any((args.estimate, args.print_command, args.run)):
        return interactive()

    try:
        plan = apply_args_to_plan(args)
    except ValueError as exc:
        parser.error(str(exc))

    if args.estimate:
        print_estimate(plan)
    if args.print_command:
        print(plan.shell_command())
    if args.run:
        if args.live:
            return run_plan(plan)
        return run_artifact_command("run-lilo", env=plan.env())
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python
"""Check whether the local checkout is ready for LILO artifact evaluation."""

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INFO_ROOT = ROOT.parent / "Info"
DEFAULT_DOMAINS = ["re2", "clevr", "logo"]
DEFAULT_SEEDS = ["111", "222", "333"]
DEFAULT_INIT_RUN_ID = "cheap_init_all_domains_20260505"
MIN_PROMPTABLE_TRAIN_FRONTIERS = 2


def load_environment_checker():
    path = ROOT / "scripts" / "check_lilo_environment.py"
    spec = importlib.util.spec_from_file_location("check_lilo_environment", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checkpoint_dir(init_run_id, domain, seed):
    return (
        ROOT
        / "experiments_iterative"
        / "outputs"
        / init_run_id
        / "domains"
        / domain
        / "dreamcoder"
        / "seed_{}".format(seed)
        / "dreamcoder_32"
    )


def read_json(path):
    with path.open() as f:
        return json.load(f)


def check_init_checkpoint(init_run_id, domain, seed):
    path = checkpoint_dir(init_run_id, domain, seed)
    required = [
        path / "0" / "frontiers.json",
        path / "0" / "laps_grammar.json",
        path / "0" / "metrics.json",
        path / "config.json",
        path / "run.log",
    ]
    missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
    result = {
        "domain": domain,
        "seed": seed,
        "path": str(path.relative_to(ROOT)),
        "ok": not missing,
        "missing": missing,
        "train_solved": None,
        "test_solved": None,
        "promptable": False,
    }
    frontiers_path = path / "0" / "frontiers.json"
    if frontiers_path.exists():
        frontiers = read_json(frontiers_path)
        solved = frontiers.get("_summary", {}).get("n_tasks_solved", {})
        result["train_solved"] = solved.get("train")
        result["test_solved"] = solved.get("test")
        result["promptable"] = (
            result["train_solved"] is not None
            and result["train_solved"] >= MIN_PROMPTABLE_TRAIN_FRONTIERS
        )
        result["ok"] = result["ok"] and result["promptable"]
    return result


def check_all_init_checkpoints(init_run_id, domains, seeds):
    return [
        check_init_checkpoint(init_run_id, domain, seed)
        for domain in domains
        for seed in seeds
    ]


def check_task_loaders(domains):
    sys.path.insert(0, str(ROOT))
    os.chdir(str(ROOT))
    try:
        import run_experiment  # noqa: F401
        from src.config_builder import get_domain_metadata
        from src.task_loaders import TaskLoaderRegistry
    except Exception as exc:
        return {
            "ok": False,
            "error": "{}: {}".format(type(exc).__name__, exc),
            "domains": {},
        }

    results = {}
    ok = True
    for domain in domains:
        try:
            metadata = get_domain_metadata(domain)
            loader_key = metadata.get("tasks_loader", domain)
            tasks = TaskLoaderRegistry[loader_key].load_tasks()
            train_count = len(tasks.get("train", []))
            test_count = len(tasks.get("test", []))
            expected_train = metadata.get("n_tasks_train")
            expected_test = metadata.get("n_tasks_test")
            domain_ok = train_count == expected_train and test_count == expected_test
            results[domain] = {
                "ok": domain_ok,
                "train": train_count,
                "test": test_count,
                "loader": loader_key,
                "expected_train": expected_train,
                "expected_test": expected_test,
            }
            ok = ok and domain_ok
        except Exception as exc:
            results[domain] = {
                "ok": False,
                "error": "{}: {}".format(type(exc).__name__, exc),
            }
            ok = False
    return {"ok": ok, "domains": results}


def litellm_aliases(config_path):
    if not config_path.exists():
        return []
    text = config_path.read_text()
    return sorted(set(re.findall(r"model_name:\s*['\"]?([^'\"\n]+)", text)))


def check_litellm():
    env_prefix = Path(
        os.environ.get(
            "LILO_LITELLM_ENV_PREFIX", str(ROOT / ".conda" / "envs" / "litellm")
        )
    )
    executable = env_prefix / "bin" / "litellm"
    config_path = ROOT / "litellm_config.initial_lilo.yaml"
    return {
        "ok": executable.exists() and config_path.exists(),
        "executable": str(executable),
        "executable_exists": executable.exists(),
        "config": str(config_path.relative_to(ROOT)),
        "config_exists": config_path.exists(),
        "aliases": litellm_aliases(config_path),
    }


def check_locks():
    lock_dir = INFO_ROOT / "locks"
    if not lock_dir.exists():
        return {"ok": False, "files": [], "path": str(lock_dir)}
    files = sorted(str(path.relative_to(INFO_ROOT)) for path in lock_dir.iterdir())
    return {"ok": bool(files), "files": files, "path": str(lock_dir)}


def check_entrypoint_scripts():
    scripts = [
        "scripts/artifact.sh",
        "scripts/run_artifact_smoke.sh",
        "scripts/run_full_lilo_experiment.sh",
        "scripts/analyze_artifact_results.sh",
        "scripts/validate_experiment_outputs.py",
        "scripts/compute_synthesis_summary_table.py",
        "scripts/compute_table3_stats.py",
    ]
    results = {}
    for script in scripts:
        path = ROOT / script
        results[script] = {"exists": path.exists(), "executable": os.access(str(path), os.X_OK)}
    return results


def build_report(args):
    checker = load_environment_checker()
    env_report = checker.build_report()
    env_blockers = checker.blockers(env_report)
    checkpoints = check_all_init_checkpoints(args.init_run_id, args.domains, args.seeds)
    task_loaders = check_task_loaders(args.domains)
    litellm = check_litellm()
    locks = check_locks()
    entrypoints = check_entrypoint_scripts()

    blockers = list(env_blockers)
    bad_checkpoints = [
        "{} seed {}".format(item["domain"], item["seed"])
        for item in checkpoints
        if not item["ok"]
    ]
    if bad_checkpoints:
        blockers.append(
            "cheap initialization checkpoints missing or not promptable: {}".format(
                ", ".join(bad_checkpoints)
            )
        )
    if not task_loaders["ok"]:
        blockers.append("task loaders did not match expected domain counts")
    if not litellm["ok"]:
        blockers.append("LiteLLM proxy environment or initial alias config missing")
    if not locks["ok"]:
        blockers.append("Info/locks is missing or empty")
    missing_entrypoints = [
        name for name, status in entrypoints.items() if not status["exists"]
    ]
    if missing_entrypoints:
        blockers.append("artifact entrypoint scripts missing: {}".format(", ".join(missing_entrypoints)))

    return {
        "root": str(ROOT),
        "info_root": str(INFO_ROOT),
        "init_run_id": args.init_run_id,
        "domains": args.domains,
        "seeds": args.seeds,
        "environment": env_report,
        "environment_blockers": env_blockers,
        "init_checkpoints": checkpoints,
        "task_loaders": task_loaders,
        "litellm": litellm,
        "locks": locks,
        "entrypoints": entrypoints,
        "blockers": blockers,
    }


def print_text(report):
    print("LILO artifact readiness")
    print("=======================")
    print("Root: {}".format(report["root"]))
    print("Initialization run: {}".format(report["init_run_id"]))
    print("Domains: {}".format(" ".join(report["domains"])))
    print("Seeds: {}".format(" ".join(report["seeds"])))
    print("")
    print("Task loaders:")
    for domain, status in sorted(report["task_loaders"]["domains"].items()):
        if status.get("ok"):
            print(
                "  - {}: loader={}, train={}, test={}".format(
                    domain, status.get("loader"), status["train"], status["test"]
                )
            )
        else:
            print("  - {}: FAILED ({})".format(domain, status.get("error", "count mismatch")))
    print("")
    print("Cheap initialization checkpoints:")
    for item in report["init_checkpoints"]:
        status = "ok" if item["ok"] else "FAILED"
        print(
            "  - {domain} seed {seed}: {status}, train={train_solved}, test={test_solved}".format(
                status=status, **item
            )
        )
    print("")
    print("LiteLLM aliases: {}".format(", ".join(report["litellm"]["aliases"]) or "missing"))
    print("Lock files: {}".format(", ".join(report["locks"]["files"]) or "missing"))
    print("")
    if report["blockers"]:
        print("Blockers:")
        for blocker in report["blockers"]:
            print("  - {}".format(blocker))
    else:
        print("No artifact-readiness blockers detected.")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domains", nargs="+", default=DEFAULT_DOMAINS)
    parser.add_argument("--seeds", nargs="+", default=DEFAULT_SEEDS)
    parser.add_argument("--init-run-id", default=DEFAULT_INIT_RUN_ID)
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    parser.add_argument("--output", default=None, help="Optional JSON report path.")
    parser.add_argument("--no-fail", action="store_true", help="Always exit 0.")
    return parser.parse_args()


def main():
    args = parse_args()
    report = build_report(args)
    if args.output:
        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = Path.cwd() / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_text(report)
    if report["blockers"] and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

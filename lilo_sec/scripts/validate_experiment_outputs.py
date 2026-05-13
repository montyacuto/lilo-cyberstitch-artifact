#!/usr/bin/env python
"""Validate LILO experiment output directories without recomputing results."""

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOMAINS = ["re2", "clevr", "logo"]
DEFAULT_SEEDS = ["111", "222", "333"]
DEFAULT_ERROR_PATTERNS = [
    r"Exception encountered while running experiment",
    r"Traceback",
    r"error_code=",
    r"HTTP/1\.1\" 429",
    r"insufficient_quota",
    r"rate_limit",
    r"Error communicating with OpenAI",
]


def parse_seed(seed):
    try:
        return int(seed)
    except ValueError:
        return seed


def run_dir(args, domain, seed):
    return (
        ROOT
        / args.experiment_dir
        / args.experiment_name
        / "domains"
        / domain
        / args.experiment_type
        / "seed_{}".format(seed)
        / "{}_{}".format(args.experiment_type, args.batch_size)
    )


def read_json(path):
    with path.open() as f:
        return json.load(f)


def scan_log(path, patterns):
    if not path.exists():
        return []
    text = path.read_text(errors="replace")
    matches = []
    for pattern in patterns:
        regex = re.compile(pattern, re.IGNORECASE)
        for match in regex.finditer(text):
            line_number = text.count("\n", 0, match.start()) + 1
            line = text[match.start() : text.find("\n", match.start())]
            matches.append(
                {
                    "pattern": pattern,
                    "line_number": line_number,
                    "line": line[:300],
                }
            )
    return matches


def split_was_evaluated(metrics_path, split):
    if not metrics_path.exists():
        return False
    metrics = read_json(metrics_path)
    for block in metrics.get("loop_block_runtimes", []):
        if block.get("task_split") == split:
            return True
        if split in block.get("task_splits", []):
            return True
    return False


def solved_summary(frontiers_path):
    if not frontiers_path.exists():
        return {}
    frontiers = read_json(frontiers_path)
    summary = frontiers.get("_summary", {}).get("n_tasks_solved", {})
    return {
        "train": summary.get("train"),
        "test": summary.get("test"),
        "n_train_frontiers": len(frontiers.get("train", {})),
        "n_test_frontiers": len(frontiers.get("test", {})),
    }


def validate_one(args, domain, seed, patterns):
    path = run_dir(args, domain, seed)
    result = {
        "domain": domain,
        "seed": seed,
        "path": str(path.relative_to(ROOT)),
        "exists": path.exists(),
        "ok": True,
        "issues": [],
        "log_matches": [],
        "iterations": [],
        "latest_train_iteration": None,
        "latest_train_solved": None,
        "latest_{}_iteration".format(args.evaluated_split): None,
        "latest_{}_solved".format(args.evaluated_split): None,
    }
    if not path.exists():
        result["ok"] = args.allow_missing
        result["issues"].append("run directory missing")
        return result

    for required in ["config.json", "run.log"]:
        if not (path / required).exists():
            result["ok"] = False
            result["issues"].append("{} missing".format(required))

    result["log_matches"] = scan_log(path / "run.log", patterns)
    if result["log_matches"]:
        result["ok"] = False
        result["issues"].append("run.log contains failure patterns")

    iterations = sorted(
        int(child.name)
        for child in path.iterdir()
        if child.is_dir() and child.name.isdigit()
    )
    if not iterations:
        result["ok"] = False
        result["issues"].append("no iteration directories found")
        return result

    evaluated_iterations = []
    for iteration in iterations:
        iteration_path = path / str(iteration)
        frontiers_path = iteration_path / "frontiers.json"
        metrics_path = iteration_path / "metrics.json"
        iteration_result = {
            "iteration": iteration,
            "frontiers_exists": frontiers_path.exists(),
            "metrics_exists": metrics_path.exists(),
            "solved": solved_summary(frontiers_path),
            "evaluated_split": split_was_evaluated(metrics_path, args.evaluated_split),
        }
        if not metrics_path.exists():
            result["issues"].append("iteration {} metrics.json missing".format(iteration))
        if not frontiers_path.exists():
            result["issues"].append("iteration {} frontiers.json missing".format(iteration))
        if iteration_result["evaluated_split"]:
            evaluated_iterations.append(iteration)
        result["iterations"].append(iteration_result)

    complete_iterations = [
        item["iteration"]
        for item in result["iterations"]
        if item["frontiers_exists"]
    ]
    if complete_iterations:
        latest_train = max(complete_iterations)
        latest_train_summary = solved_summary(path / str(latest_train) / "frontiers.json")
        result["latest_train_iteration"] = latest_train
        result["latest_train_solved"] = latest_train_summary.get("train")

    if evaluated_iterations:
        latest_eval = max(evaluated_iterations)
        latest_eval_summary = solved_summary(path / str(latest_eval) / "frontiers.json")
        result["latest_{}_iteration".format(args.evaluated_split)] = latest_eval
        result["latest_{}_solved".format(args.evaluated_split)] = latest_eval_summary.get(
            args.evaluated_split
        )

    if any("missing" in issue for issue in result["issues"]) and not args.allow_missing:
        result["ok"] = False
    return result


def print_text(report):
    print("Experiment output validation")
    print("============================")
    print("Experiment: {}".format(report["experiment_name"]))
    print("Type/batch: {}_{}".format(report["experiment_type"], report["batch_size"]))
    print("Evaluated split: {}".format(report["evaluated_split"]))
    print("")
    for item in report["runs"]:
        status = "ok" if item["ok"] else "FAILED"
        latest_eval_iteration = item.get(
            "latest_{}_iteration".format(report["evaluated_split"])
        )
        latest_eval_solved = item.get("latest_{}_solved".format(report["evaluated_split"]))
        message = (
            "  - {domain} seed {seed}: {status}; train_iter={train_iter}, "
            "train_solved={train_solved}".format(
                domain=item["domain"],
                seed=item["seed"],
                status=status,
                train_iter=item["latest_train_iteration"],
                train_solved=item["latest_train_solved"],
            )
        )
        if report["evaluated_split"] != "train":
            message += (
                ", {split}_iter={eval_iter}, {split}_solved={eval_solved}".format(
                    split=report["evaluated_split"],
                    eval_iter=latest_eval_iteration,
                    eval_solved=latest_eval_solved,
                )
            )
        print(message)
        for issue in item["issues"]:
            print("      issue: {}".format(issue))
        for match in item["log_matches"][:3]:
            print("      log match line {}: {}".format(match["line_number"], match["line"]))
        if len(item["log_matches"]) > 3:
            print("      ... {} additional log matches".format(len(item["log_matches"]) - 3))
    print("")
    if report["ok"]:
        print("No blocking output issues detected.")
    else:
        print("Blocking output issues detected.")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-name", required=True)
    parser.add_argument(
        "--experiment-dir",
        default="experiments_iterative/outputs",
        help="Path below repo root containing experiment outputs.",
    )
    parser.add_argument("--experiment-type", default="lilo")
    parser.add_argument("--batch-size", default="32")
    parser.add_argument("--domains", nargs="+", default=DEFAULT_DOMAINS)
    parser.add_argument("--seeds", nargs="+", default=DEFAULT_SEEDS)
    parser.add_argument("--evaluated-split", default="test", choices=["train", "test"])
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", default=None, help="Optional JSON report path.")
    return parser.parse_args()


def main():
    args = parse_args()
    patterns = DEFAULT_ERROR_PATTERNS
    runs = [
        validate_one(args, domain, seed, patterns)
        for domain in args.domains
        for seed in args.seeds
    ]
    report = {
        "experiment_name": args.experiment_name,
        "experiment_type": args.experiment_type,
        "batch_size": args.batch_size,
        "domains": args.domains,
        "seeds": args.seeds,
        "evaluated_split": args.evaluated_split,
        "allow_missing": args.allow_missing,
        "runs": runs,
        "ok": all(item["ok"] for item in runs),
    }
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
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

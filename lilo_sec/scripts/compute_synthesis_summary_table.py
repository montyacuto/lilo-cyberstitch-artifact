#!/usr/bin/env python
"""
Compute Table 1/2-style synthesis solve-rate summaries.

This wraps the existing SynthesisExperimentAnalyzer from src.analysis_utilities
and applies the same notebook aggregation pattern:

1. Read frontiers through the analysis harness.
2. Keep the latest iteration that actually evaluated the requested split.
3. Aggregate final percent solved with max, mean, and standard deviation.

Unlike SynthesisExperimentAnalyzer.get_synthesis_summary(), this script starts
from get_synthesis_results() so rows with zero solved tasks are retained.
For LILO-style runs this matters because train-only iterations can reset test
frontiers to zero; a held-out table should use the latest completed test
evaluation, not the latest checkpoint directory.
"""

import argparse
import csv
import json
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_CWD = Path.cwd()
DEFAULT_DOMAINS = ["re2", "clevr", "logo"]
DOMAIN_LABELS = {
    "re2": "REGEX",
    "clevr": "CLEVR",
    "logo": "LOGO",
}
DOMAIN_ORDER = ["REGEX", "CLEVR", "LOGO"]

EXPERIMENT_LABELS = {
    "base_dsl": "Base DSL",
    "baseline_dreamcoder": "DreamCoder",
    "dreamcoder": "DreamCoder",
    "gpt_solver": "LLM Solver",
    "llm_solver": "LLM Solver",
    "gpt_solver_search": "LLM Solver (+ Search)",
    "gpt_solver_stitch": "LILO (No Search / AutoDoc)",
    "gpt_solver_stitch_namer": "LILO (No Search)",
    "gpt_solver_stitch_namer_search": "LILO",
    "lilo": "LILO",
    "random": "LILO (Random)",
    "cos_similar": "LILO (Similarity)",
}

PRESETS = {
    "generic": None,
    "table1-online": [
        "baseline_dreamcoder",
        "dreamcoder",
        "gpt_solver",
        "llm_solver",
        "gpt_solver_search",
        "gpt_solver_stitch",
        "gpt_solver_stitch_namer",
        "gpt_solver_stitch_namer_search",
        "lilo",
    ],
    "table1-offline": [
        "base_dsl",
        "baseline_dreamcoder",
        "dreamcoder",
        "gpt_solver",
        "llm_solver",
        "gpt_solver_search",
        "gpt_solver_stitch",
        "gpt_solver_stitch_namer",
        "gpt_solver_stitch_namer_search",
        "lilo",
    ],
    "table2": ["random", "cos_similar"],
}

ROW_ORDER = {
    "table1-online": [
        "DreamCoder",
        "LLM Solver",
        "LLM Solver (+ Search)",
        "LILO (No Search / AutoDoc)",
        "LILO (No Search)",
        "LILO",
    ],
    "table1-offline": [
        "Base DSL",
        "DreamCoder",
        "LLM Solver",
        "LLM Solver (+ Search)",
        "LILO (No Search / AutoDoc)",
        "LILO (No Search)",
        "LILO",
    ],
    "table2": ["LILO (Random)", "LILO (Similarity)"],
}


def configure_imports():
    os.chdir(str(REPO_ROOT))
    sys.path.insert(0, str(REPO_ROOT))
    os.environ.setdefault(
        "MPLCONFIGDIR", str(REPO_ROOT / ".cache" / "matplotlib")
    )


def parse_seed(seed):
    try:
        return int(seed)
    except ValueError:
        return seed


def select_experiment_types(args):
    if args.experiment_types:
        return args.experiment_types
    preset_types = PRESETS[args.preset]
    if preset_types is None:
        return None
    return preset_types


def load_synthesis_results(args):
    from src.analysis_utilities import SynthesisExperimentAnalyzer

    experiment_dir = args.experiment_dir
    if not os.path.isabs(experiment_dir):
        experiment_dir = str(REPO_ROOT / experiment_dir)

    seeds = [parse_seed(seed) for seed in args.seeds] if args.seeds else None
    with redirect_stdout(sys.stderr):
        analyzer = SynthesisExperimentAnalyzer(
            experiment_name=args.experiment_name,
            experiment_dir=experiment_dir,
            domains=args.domains,
            experiment_types=select_experiment_types(args),
            batch_size=args.batch_size,
            seeds=seeds,
            compute_likelihoods=False,
            allow_incomplete_results=args.allow_incomplete_results,
        )
        df = analyzer.get_synthesis_results()
    return analyzer, df


def compute_percent_solved(df):
    from src.config_builder import get_domain_metadata

    rows = []
    for (domain, experiment_type, seed, iteration, split), group in df.groupby(
        ["domain", "experiment_type", "seed", "iteration", "split"],
        sort=False,
    ):
        n_solved = int(group["solved"].sum())
        n_frontiers = int(len(group))
        n_tasks = get_domain_metadata(domain)[f"n_tasks_{split}"]
        rows.append(
            {
                "domain": domain,
                "experiment_type": experiment_type,
                "seed": seed,
                "iteration": int(iteration),
                "split": split,
                "n_solved": n_solved,
                "n_frontiers": n_frontiers,
                "n_tasks": n_tasks,
                "percent_solved": 100.0 * n_solved / n_tasks,
            }
        )
    return pd.DataFrame(rows)


def final_iteration_rows(df_summary):
    final_rows = []
    group_cols = ["domain", "experiment_type", "seed", "split"]
    for _, group in df_summary.groupby(group_cols, sort=False):
        final_iteration = group["iteration"].max()
        final_rows.append(group[group["iteration"] == final_iteration])
    return pd.concat(final_rows, axis=0).reset_index(drop=True)


def metrics_path_for(args, domain, experiment_type, seed, iteration):
    experiment_dir = args.experiment_dir
    if not os.path.isabs(experiment_dir):
        experiment_dir = str(REPO_ROOT / experiment_dir)
    return (
        Path(experiment_dir)
        / "outputs"
        / args.experiment_name
        / "domains"
        / domain
        / experiment_type
        / f"seed_{seed}"
        / f"{experiment_type}_{args.batch_size}"
        / str(iteration)
        / "metrics.json"
    )


def metrics_include_split(metrics_path, split):
    if not metrics_path.exists():
        return False
    with metrics_path.open() as f:
        metrics = json.load(f)
    for block in metrics.get("loop_block_runtimes", []):
        if block.get("task_split") == split:
            return True
        if split in block.get("task_splits", []):
            return True
    return False


def latest_evaluated_iteration_rows(df_summary, args):
    final_rows = []
    group_cols = ["domain", "experiment_type", "seed", "split"]
    for _, group in df_summary.groupby(group_cols, sort=False):
        evaluated_iterations = []
        for iteration in sorted(group["iteration"].unique()):
            row = group[group["iteration"] == iteration].iloc[0]
            metrics_path = metrics_path_for(
                args,
                row["domain"],
                row["experiment_type"],
                row["seed"],
                iteration,
            )
            if metrics_include_split(metrics_path, row["split"]):
                evaluated_iterations.append(iteration)

        if evaluated_iterations:
            final_iteration = max(evaluated_iterations)
        else:
            final_iteration = group["iteration"].max()
            print(
                "WARNING: no evaluated iteration found for "
                f"{tuple(group.iloc[0][col] for col in group_cols)}; "
                f"falling back to iteration {final_iteration}",
                file=sys.stderr,
            )
        final_rows.append(group[group["iteration"] == final_iteration])
    return pd.concat(final_rows, axis=0).reset_index(drop=True)


def aggregate_summary(df_summary, split):
    df_split = df_summary[df_summary["split"] == split].copy()
    if df_split.empty:
        return []

    rows = []
    for (domain, experiment_type), group in df_split.groupby(
        ["domain", "experiment_type"], sort=False
    ):
        values = group["percent_solved"]
        std_value = float(values.std())
        if pd.isna(std_value):
            std_value = 0.0
        rows.append(
            {
                "domain": domain,
                "domain_label": DOMAIN_LABELS.get(domain, domain),
                "experiment_type": experiment_type,
                "model": EXPERIMENT_LABELS.get(experiment_type, experiment_type),
                "max": float(values.max()),
                "mean": float(values.mean()),
                "std": std_value,
                "n_seeds": int(group["seed"].nunique()),
                "seeds": sorted(group["seed"].unique().tolist()),
                "final_iterations": sorted(group["iteration"].unique().tolist()),
            }
        )
    return sort_rows(rows)


def sort_rows(rows):
    domain_rank = {domain: i for i, domain in enumerate(DOMAIN_ORDER)}
    model_rank = {}
    for order in ROW_ORDER.values():
        for i, model in enumerate(order):
            model_rank.setdefault(model, i)
    return sorted(
        rows,
        key=lambda row: (
            model_rank.get(row["model"], 999),
            domain_rank.get(row["domain_label"], 999),
            row["model"],
            row["domain_label"],
        ),
    )


def pivot_for_markdown(rows):
    models = []
    for row in rows:
        if row["model"] not in models:
            models.append(row["model"])
    by_model_domain = {
        (row["model"], row["domain_label"]): row
        for row in rows
    }
    return models, by_model_domain


def format_number(value):
    return f"{value:.2f}"


def print_markdown(rows, stream):
    models, by_model_domain = pivot_for_markdown(rows)
    headers = ["Model"]
    for domain in DOMAIN_ORDER:
        if any((model, domain) in by_model_domain for model in models):
            headers.extend([f"{domain} max", f"{domain} mean", f"{domain} std"])

    print("| " + " | ".join(headers) + " |", file=stream)
    print("| " + " | ".join(["---"] + ["---:"] * (len(headers) - 1)) + " |", file=stream)
    for model in models:
        values = [model]
        for domain in DOMAIN_ORDER:
            row = by_model_domain.get((model, domain))
            if row is None:
                if any((m, domain) in by_model_domain for m in models):
                    values.extend(["", "", ""])
                continue
            values.extend(
                [
                    format_number(row["max"]),
                    format_number(row["mean"]),
                    format_number(row["std"]),
                ]
            )
        print("| " + " | ".join(values) + " |", file=stream)


def print_csv(rows, stream):
    fieldnames = [
        "model",
        "experiment_type",
        "domain",
        "domain_label",
        "max",
        "mean",
        "std",
        "n_seeds",
        "seeds",
        "final_iterations",
    ]
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        out = dict(row)
        out["seeds"] = " ".join(str(seed) for seed in row["seeds"])
        out["final_iterations"] = " ".join(
            str(iteration) for iteration in row["final_iterations"]
        )
        writer.writerow({key: out[key] for key in fieldnames})


def write_output(rows, output_format, output_path):
    if output_path:
        output_path = Path(output_path)
        if not output_path.is_absolute():
            output_path = ORIGINAL_CWD / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        stream = output_path.open("w", newline="")
    else:
        stream = sys.stdout
    try:
        if output_format == "markdown":
            print_markdown(rows, stream)
        elif output_format == "csv":
            print_csv(rows, stream)
        elif output_format == "json":
            json.dump(rows, stream, indent=2)
            print(file=stream)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    finally:
        if output_path:
            stream.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compute Table 1/2-style synthesis solve-rate summaries."
    )
    parser.add_argument("--experiment-name", required=True)
    parser.add_argument(
        "--experiment-dir",
        default="experiments_iterative",
        help="Experiment directory containing outputs/. Relative paths are resolved from the repo root.",
    )
    parser.add_argument("--domains", nargs="+", default=DEFAULT_DOMAINS)
    parser.add_argument("--experiment-types", nargs="+", default=None)
    parser.add_argument("--seeds", nargs="+", default=None)
    parser.add_argument("--batch-size", default="96")
    parser.add_argument("--split", default="test", choices=["train", "test"])
    parser.add_argument(
        "--preset",
        default="generic",
        choices=sorted(PRESETS.keys()),
        help="Optional row-selection preset.",
    )
    parser.add_argument(
        "--format",
        default="markdown",
        choices=["markdown", "csv", "json"],
    )
    parser.add_argument("--output", default=None)
    parser.add_argument(
        "--allow-incomplete-results",
        action="store_true",
        help="Skip missing run artifacts where the analysis harness supports it.",
    )
    parser.add_argument(
        "--include-all-iterations",
        action="store_true",
        help="Aggregate all iterations instead of only the final iteration per seed.",
    )
    parser.add_argument(
        "--final-selection",
        default="latest-evaluated",
        choices=["latest-evaluated", "latest-checkpoint"],
        help=(
            "How to choose the final iteration per seed. latest-evaluated uses "
            "metrics.json to ignore train-only checkpoints for held-out splits."
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()
    configure_imports()
    _, df = load_synthesis_results(args)
    df_summary = compute_percent_solved(df)
    if not args.include_all_iterations:
        if args.final_selection == "latest-evaluated":
            df_summary = latest_evaluated_iteration_rows(df_summary, args)
        else:
            df_summary = final_iteration_rows(df_summary)
    rows = aggregate_summary(df_summary, split=args.split)
    write_output(rows, args.format, args.output)


if __name__ == "__main__":
    main()

#!/usr/bin/env python
"""
Compute the LILO paper Table 3 dataset summary statistics.

This script intentionally uses the repository's existing task-loader registry
and DreamCoder program tokenization hook:

    Program.left_order_tokens(program, show_vars=True)

for description length, matching the code path used by LILO's frontier
evaluation utilities.
"""

import argparse
import csv
import json
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path

import numpy as np


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOMAINS = ["re2", "clevr", "logo"]
DOMAIN_LABELS = {
    "re2": "REGEX",
    "clevr": "CLEVR",
    "logo": "LOGO",
}


def configure_imports():
    os.chdir(str(REPO_ROOT))
    sys.path.insert(0, str(REPO_ROOT))
    os.environ.setdefault(
        "MPLCONFIGDIR", str(REPO_ROOT / ".cache" / "matplotlib")
    )


def register_task_loaders():
    # Importing these modules registers their loaders with TaskLoaderRegistry.
    import data.clevr.make_tasks  # noqa: F401
    import data.compositional_graphics.make_tasks  # noqa: F401
    import data.re2.make_tasks  # noqa: F401


def program_for_task(task):
    program = task.supervision or getattr(task, "groundTruthProgram", None)
    if program is None:
        raise ValueError(f"Task has no ground-truth program: {task.name}")
    return program


def summarize(values):
    return {
        "mean": float(np.mean(values)),
        "std": float(np.std(values)),
    }


def format_mean_std(summary):
    return f"{summary['mean']:.2f} +/- {summary['std']:.2f}"


def compute_stats(domains, loader_logs_to_stderr=True):
    from dreamcoder.program import Program
    from src.config_builder import get_domain_metadata
    from src.task_loaders import TEST, TRAIN, TaskLoaderRegistry

    rows = []
    for domain in domains:
        metadata = get_domain_metadata(domain)
        loader = TaskLoaderRegistry[metadata["tasks_loader"]]
        if loader_logs_to_stderr:
            with redirect_stdout(sys.stderr):
                tasks_by_split = loader.load_tasks()
        else:
            tasks_by_split = loader.load_tasks()

        for split in [TRAIN, TEST]:
            tasks = tasks_by_split[split]
            programs = [program_for_task(task) for task in tasks]
            description_lengths = [
                len(Program.left_order_tokens(program, show_vars=True))
                for program in programs
            ]
            string_lengths = [len(str(program)) for program in programs]
            rows.append(
                {
                    "domain": domain,
                    "domain_label": DOMAIN_LABELS.get(domain, domain),
                    "split": split,
                    "n_tasks": len(tasks),
                    "n_unique_task_names": len({task.name for task in tasks}),
                    "description_length": summarize(description_lengths),
                    "program_string_length": summarize(string_lengths),
                }
            )
    return rows


def rows_by_domain(rows):
    grouped = {}
    for row in rows:
        grouped.setdefault(row["domain"], {})[row["split"]] = row
    return grouped


def print_markdown(rows, stream):
    grouped = rows_by_domain(rows)
    print(
        "| Domain | #Tasks train | #Tasks test | Description length train | Description length test | String length train | String length test |",
        file=stream,
    )
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |", file=stream)
    for domain in DEFAULT_DOMAINS:
        if domain not in grouped:
            continue
        train = grouped[domain]["train"]
        test = grouped[domain]["test"]
        print(
            "| {domain_label} | {n_train} | {n_test} | {dl_train} | {dl_test} | {sl_train} | {sl_test} |".format(
                domain_label=train["domain_label"],
                n_train=train["n_tasks"],
                n_test=test["n_tasks"],
                dl_train=format_mean_std(train["description_length"]),
                dl_test=format_mean_std(test["description_length"]),
                sl_train=format_mean_std(train["program_string_length"]),
                sl_test=format_mean_std(test["program_string_length"]),
            ),
            file=stream,
        )


def print_csv(rows, stream):
    fieldnames = [
        "domain",
        "domain_label",
        "split",
        "n_tasks",
        "n_unique_task_names",
        "description_length_mean",
        "description_length_std",
        "program_string_length_mean",
        "program_string_length_std",
    ]
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "domain": row["domain"],
                "domain_label": row["domain_label"],
                "split": row["split"],
                "n_tasks": row["n_tasks"],
                "n_unique_task_names": row["n_unique_task_names"],
                "description_length_mean": row["description_length"]["mean"],
                "description_length_std": row["description_length"]["std"],
                "program_string_length_mean": row["program_string_length"]["mean"],
                "program_string_length_std": row["program_string_length"]["std"],
            }
        )


def write_output(rows, output_format, output_path):
    if output_path:
        output_stream = open(output_path, "w", newline="")
    else:
        output_stream = sys.stdout

    try:
        if output_format == "markdown":
            print_markdown(rows, output_stream)
        elif output_format == "csv":
            print_csv(rows, output_stream)
        elif output_format == "json":
            json.dump(rows, output_stream, indent=2)
            print(file=output_stream)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    finally:
        if output_path:
            output_stream.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compute LILO Table 3 dataset summary statistics."
    )
    parser.add_argument(
        "--domains",
        nargs="+",
        default=DEFAULT_DOMAINS,
        help="Domain keys to summarize. Defaults to re2 clevr logo.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "csv", "json"],
        default="markdown",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional output file. Defaults to stdout.",
    )
    parser.add_argument(
        "--show-loader-logs",
        action="store_true",
        help="Keep loader status messages on stdout instead of redirecting them to stderr.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    configure_imports()
    register_task_loaders()
    rows = compute_stats(
        domains=args.domains,
        loader_logs_to_stderr=not args.show_loader_logs,
    )
    write_output(rows, args.format, args.output)


if __name__ == "__main__":
    main()

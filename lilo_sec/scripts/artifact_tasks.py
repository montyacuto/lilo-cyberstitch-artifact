#!/usr/bin/env python3
"""Shared task registry for the combined LILO/CyberSTITCH artifact runner."""

from __future__ import print_function


def _task(
    task_id,
    label,
    section,
    cwd,
    argv,
    description,
    estimate="",
    live_api=False,
    long_running=False,
    env=None,
    requires=None,
):
    return {
        "id": task_id,
        "label": label,
        "section": section,
        "cwd": cwd,
        "argv": argv,
        "description": description,
        "estimate": estimate,
        "live_api": bool(live_api),
        "long_running": bool(long_running),
        "env": env or {},
        "requires": requires or [],
    }


TASKS = [
    _task(
        "lilo-verify-env",
        "Verify LILO environment",
        "lilo",
        "lilo_sec",
        ["scripts/artifact.sh", "verify-env"],
        "Check the legacy LILO runtime, dependencies, bundled DreamCoder binaries, and native library prerequisites.",
        "minutes",
    ),
    _task(
        "lilo-smoke",
        "Run LILO offline smoke",
        "lilo",
        "lilo_sec",
        ["scripts/artifact.sh", "smoke"],
        "Run bounded offline/local LILO smoke checks with no live LLM calls.",
        "minutes",
    ),
    _task(
        "lilo-run-plan",
        "Print LILO full-run plan",
        "lilo",
        "lilo_sec",
        ["scripts/artifact.sh", "run-lilo"],
        "Generate the full-LILO command plan. Dry-run is enforced unless the caller overrides it.",
        "seconds",
        env={"LILO_DRY_RUN": "1"},
    ),
    _task(
        "lilo-run-replay",
        "Run LILO cache replay",
        "lilo",
        "lilo_sec",
        ["scripts/artifact.sh", "run-lilo"],
        "Run LILO through the configured cache replay path. Requires LILO_LLM_CACHE_DIR when replaying a specific cache.",
        "long",
        long_running=True,
        env={"LILO_DRY_RUN": "0", "LILO_LLM_CACHE_MODE": "replay"},
    ),
    _task(
        "lilo-run-live",
        "Run LILO live API reproduction",
        "lilo",
        "lilo_sec",
        ["scripts/artifact.sh", "run-lilo"],
        "Run the selected LILO plan with live LLM/API calls.",
        "long",
        live_api=True,
        long_running=True,
        env={"LILO_DRY_RUN": "0", "LILO_CONFIRM_LIVE_LLM": "YES"},
        requires=["OPENAI_API_KEY"],
    ),
    _task(
        "cyberstitch-doctor",
        "Verify CyberSTITCH environment",
        "cyberstitch",
        "cyberstitch_poc",
        ["$CYBERSTITCH_PYTHON", "-m", "cyberstitch.cli", "doctor"],
        "Run CyberSTITCH's doctor preflight without invoking live API calls.",
        "seconds",
    ),
    _task(
        "cyberstitch-extension-smoke",
        "Run CyberSTITCH offline CodeQL smoke",
        "cyberstitch",
        "lilo_sec",
        ["scripts/artifact.sh", "codeql-extension-smoke"],
        "Run the offline CyberSTITCH CodeQL/OWASP extension smoke.",
        "minutes",
    ),
    _task(
        "cyberstitch-lilo-loop-smoke",
        "Run CyberSTITCH fixture LILO-loop smoke",
        "cyberstitch",
        "lilo_sec",
        ["scripts/artifact.sh", "codeql-lilo-loop-smoke"],
        "Run the CyberSTITCH LILO-loop adapter with checked-in fixture LLM output.",
        "minutes",
    ),
    _task(
        "cyberstitch-autodoc-eval-smoke",
        "Run CyberSTITCH fixture AutoDoc eval smoke",
        "cyberstitch",
        "lilo_sec",
        ["scripts/artifact.sh", "codeql-autodoc-eval-smoke"],
        "Run the CyberSTITCH AutoDoc evaluator against fixture responses.",
        "minutes",
    ),
    _task(
        "cyberstitch-package-verify",
        "Verify packaged CyberSTITCH results",
        "cyberstitch",
        "lilo_sec",
        ["scripts/package_artifact.py", "verify", "--scope", "cyberstitch"],
        "Check selected CyberSTITCH result/cache paths and packaging exclusions.",
        "seconds",
    ),
    _task(
        "cyberstitch-run-combined-pack",
        "Run deterministic combined-pack BenchmarkJava profile",
        "cyberstitch",
        "cyberstitch_poc",
        [
            "scripts/run_curated_benchmarkjava_experiment.sh",
            "--seed-profile",
            "combined-pack",
            "--bundle",
            "none",
        ],
        "Run the deterministic combined-pack BenchmarkJava pipeline.",
        "long",
        long_running=True,
    ),
    _task(
        "cyberstitch-run-official-expanded-pack",
        "Run deterministic companion-pack BenchmarkJava profile",
        "cyberstitch",
        "cyberstitch_poc",
        [
            "scripts/run_curated_benchmarkjava_experiment.sh",
            "--seed-profile",
            "official-expanded-pack",
            "--manifest",
            "benchmarks/owasp_cmdi_sqli_all_benchmarkjava_official_expanded.json",
            "--bundle",
            "none",
        ],
        "Run the deterministic companion/official-expanded BenchmarkJava pipeline.",
        "long",
        long_running=True,
    ),
    _task(
        "cyberstitch-run-bounded-pack",
        "Run deterministic bounded-pack BenchmarkJava profile",
        "cyberstitch",
        "cyberstitch_poc",
        [
            "scripts/run_curated_benchmarkjava_experiment.sh",
            "--seed-profile",
            "bounded-java-pack",
            "--bundle",
            "none",
        ],
        "Run the deterministic bounded Java generated-seed BenchmarkJava pipeline.",
        "long",
        long_running=True,
    ),
    _task(
        "cyberstitch-live-combined-pack",
        "Run live LILO-loop combined-pack profile",
        "cyberstitch",
        "cyberstitch_poc",
        [
            "scripts/run_curated_benchmarkjava_experiment.sh",
            "--seed-profile",
            "combined-pack",
            "--lilo-loop",
            "live",
            "--lilo-partition-mode",
            "auto",
            "--lilo-prompt-byte-budget",
            "45000",
            "--bundle",
            "none",
        ],
        "Run the live API partitioned LILO-loop path for the combined pack.",
        "long",
        live_api=True,
        long_running=True,
        requires=["OPENAI_API_KEY"],
    ),
    _task(
        "cyberstitch-live-official-expanded-pack",
        "Run live LILO-loop companion-pack profile",
        "cyberstitch",
        "cyberstitch_poc",
        [
            "scripts/run_curated_benchmarkjava_experiment.sh",
            "--seed-profile",
            "official-expanded-pack",
            "--manifest",
            "benchmarks/owasp_cmdi_sqli_all_benchmarkjava_official_expanded.json",
            "--lilo-loop",
            "live",
            "--lilo-partition-mode",
            "auto",
            "--lilo-prompt-byte-budget",
            "45000",
            "--bundle",
            "none",
        ],
        "Run the live API partitioned LILO-loop path for the companion pack.",
        "long",
        live_api=True,
        long_running=True,
        requires=["OPENAI_API_KEY"],
    ),
    _task(
        "cyberstitch-live-bounded-pack",
        "Run live LILO-loop bounded-pack profile",
        "cyberstitch",
        "cyberstitch_poc",
        [
            "scripts/run_curated_benchmarkjava_experiment.sh",
            "--seed-profile",
            "bounded-java-pack",
            "--lilo-loop",
            "live",
            "--lilo-partition-mode",
            "auto",
            "--lilo-prompt-byte-budget",
            "45000",
            "--bundle",
            "none",
        ],
        "Run the live API partitioned LILO-loop path for the bounded pack.",
        "long",
        live_api=True,
        long_running=True,
        requires=["OPENAI_API_KEY"],
    ),
    _task(
        "package-smoke",
        "Run package-only smoke",
        "package",
        "lilo_sec",
        ["scripts/package_artifact.py", "verify"],
        "Verify selected package inputs and exclusions without requiring LILO, CyberSTITCH, CodeQL, conda, or API setup.",
        "seconds",
    ),
    _task(
        "package-verify-all",
        "Verify combined package inputs",
        "package",
        "lilo_sec",
        ["scripts/package_artifact.py", "verify"],
        "Check selected LILO and CyberSTITCH package inputs without copying data.",
        "seconds",
    ),
    _task(
        "package-stage-manifest",
        "Write package staging manifest",
        "package",
        "lilo_sec",
        ["scripts/package_artifact.py", "stage"],
        "Write a non-destructive package manifest under package_stage/.",
        "seconds",
    ),
    _task(
        "artifact-report",
        "Print artifact report pointers",
        "package",
        "lilo_sec",
        ["scripts/package_artifact.py", "report"],
        "Print the package and reproduction summary pointers.",
        "seconds",
    ),
]


TASK_BY_ID = dict((task["id"], task) for task in TASKS)


def get_task(task_id):
    return TASK_BY_ID[task_id]


def sections():
    values = []
    for task in TASKS:
        section = task["section"]
        if section not in values:
            values.append(section)
    return values


def tasks_for_section(section):
    return [task for task in TASKS if task["section"] == section]


def live_task_ids():
    return [task["id"] for task in TASKS if task.get("live_api")]


def deterministic_task_ids():
    return [task["id"] for task in TASKS if not task.get("live_api")]

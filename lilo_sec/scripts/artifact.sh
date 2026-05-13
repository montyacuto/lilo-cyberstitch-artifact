#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
if [ -x "$ENV_PREFIX/bin/python" ]; then
  PYTHON="$ENV_PREFIX/bin/python"
else
  PYTHON="${PYTHON:-python3}"
fi

export MPLCONFIGDIR="${MPLCONFIGDIR:-$PWD/.cache/matplotlib}"
mkdir -p "$MPLCONFIGDIR"

usage() {
  cat <<'EOF'
Usage: scripts/artifact.sh <command> [args...]

Commands:
  menu         Open the combined LILO/CyberSTITCH interactive terminal menu.
  verify-env   Check Python, OCaml/DreamCoder binaries, Rust/Stitch, and native dependencies.
  verify-readiness
               Check internal readiness evidence, locks, task data, and init checkpoints.
  smoke        Run bounded offline/local smoke checks. No live LLM calls.
  run-lilo     Generate or run primary full-LILO commands via run_full_lilo_experiment.sh.
  analyze      Regenerate dataset stats, output validation, and synthesis summary tables.
  validate     Validate an existing experiment output directory.
  metadata     Collect hardware/software metadata and checksum key artifact files.
  codeql-extension-smoke
               Run the offline CyberSTITCH CodeQL/OWASP extension harness.
  codeql-curated-experiment
               Run the live curated BenchmarkJava CodeQL experiment. Bundles are opt-in.
  codeql-lilo-loop-smoke
               Run the CyberSTITCH CodeQL LILO-loop adapter with fixture LLM output.
  codeql-autodoc-eval-smoke
               Run the CyberSTITCH CodeQL AutoDoc A/B evaluator with fixture LLM output.
  tasks        List combined LILO/CyberSTITCH artifact tasks.
  run-task     Run one combined artifact task by id.
  package-smoke
               Run package-only smoke checks. No LILO/CyberSTITCH env required.
  package-plan Print selected package plan pointers.
  package-verify
               Verify selected package inputs without copying data.
  package-stage
               Write a package staging manifest; copying is opt-in.
  report       Print combined artifact report pointers.

LLM cache controls for run-lilo:
  LILO_LLM_CACHE_MODE=off|record|replay
  LILO_LLM_CACHE_DIR=Info/llm_caches/<run_id>

By default, run-lilo is dry-run unless LILO_DRY_RUN is set or LILO_CONFIRM_LIVE_LLM=YES.
Live full runs default to LILO_LLM_CACHE_MODE=record; replay mode requires no API key.
EOF
}

command="${1:-}"
if [ -z "$command" ]; then
  usage
  exit 2
fi
shift

case "$command" in
  menu)
    exec scripts/lilo "$@"
    ;;
  verify-env)
    exec "$PYTHON" scripts/check_lilo_environment.py "$@"
    ;;
  verify-readiness)
    exec "$PYTHON" scripts/verify_artifact_readiness.py "$@"
    ;;
  smoke)
    exec scripts/run_artifact_smoke.sh "$@"
    ;;
  run-lilo)
    if [ -z "${LILO_DRY_RUN:-}" ] && [ "${LILO_CONFIRM_LIVE_LLM:-}" != "YES" ]; then
      export LILO_DRY_RUN=1
    fi
    exec scripts/run_full_lilo_experiment.sh "$@"
    ;;
  analyze)
    exec scripts/analyze_artifact_results.sh "$@"
    ;;
  validate)
    exec "$PYTHON" scripts/validate_experiment_outputs.py "$@"
    ;;
  metadata)
    exec scripts/collect_artifact_metadata.sh "$@"
    ;;
  codeql-extension-smoke)
    CYBERSTITCH_ROOT="${CYBERSTITCH_ROOT:-$PWD/../cyberstitch_poc}"
    CYBERSTITCH_PYTHON="${CYBERSTITCH_PYTHON:-python3}"
    cd "$CYBERSTITCH_ROOT"
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli doctor
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli manifest
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli sqir
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli roundtrip
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli fcir
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli stitch --mode offline
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli validate
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli rewrite
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli codeql-check
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli score --sarif fixtures/sample_owasp.sarif
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli report
    ;;
  codeql-curated-experiment)
    CYBERSTITCH_ROOT="${CYBERSTITCH_ROOT:-$PWD/../cyberstitch_poc}"
    exec "$CYBERSTITCH_ROOT/scripts/run_curated_benchmarkjava_experiment.sh" "$@"
    ;;
  codeql-lilo-loop-smoke)
    CYBERSTITCH_ROOT="${CYBERSTITCH_ROOT:-$PWD/../cyberstitch_poc}"
    CYBERSTITCH_PYTHON="${CYBERSTITCH_PYTHON:-python3}"
    export CYBERSTITCH_RESULTS_DIR="${CYBERSTITCH_RESULTS_DIR:-results/lilo_loop_smoke}"
    cd "$CYBERSTITCH_ROOT"
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli doctor
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli manifest
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli sqir
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli roundtrip
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli fcir
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli stitch --mode offline
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli semantic-mine --merge
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli lilo-loop --mode fixture --fixture fixtures/lilo_loop_outputs.json --merge
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli validate
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli rewrite
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli codeql-check
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli report
    ;;
  codeql-autodoc-eval-smoke)
    CYBERSTITCH_ROOT="${CYBERSTITCH_ROOT:-$PWD/../cyberstitch_poc}"
    CYBERSTITCH_PYTHON="${CYBERSTITCH_PYTHON:-python3}"
    export CYBERSTITCH_RESULTS_DIR="${CYBERSTITCH_RESULTS_DIR:-results/autodoc_eval_smoke}"
    cd "$CYBERSTITCH_ROOT"
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli doctor
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli manifest
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli sqir
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli roundtrip
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli fcir
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli stitch --mode offline
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli semantic-mine --merge
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli lilo-loop --mode fixture --fixture fixtures/lilo_loop_outputs.json --merge
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli validate
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli rewrite
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli codeql-check
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli autodoc-eval --mode fixture --fixture fixtures/autodoc_eval_responses.json --samples 1
    "$CYBERSTITCH_PYTHON" -m cyberstitch.cli report
    ;;
  tasks|run-task|package-smoke|package-plan|package-verify|package-stage|report)
    exec scripts/artifact_runner.py "$command" "$@"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "Unknown artifact command: $command" >&2
    usage >&2
    exit 2
    ;;
esac

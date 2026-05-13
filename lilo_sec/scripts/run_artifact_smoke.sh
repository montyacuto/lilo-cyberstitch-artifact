#!/usr/bin/env bash
set -u -o pipefail

cd "$(dirname "$0")/.."

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
RUN_ID="${LILO_ARTIFACT_SMOKE_RUN_ID:-artifact_smoke_$(date +%Y%m%d_%H%M%S)}"
INFO_DIR="$PWD/../Info/artifact_smokes/$RUN_ID"
ENUM_TIMEOUT="${LILO_ARTIFACT_SMOKE_ENUM_TIMEOUT:-5}"
RECOGNITION_STEPS="${LILO_ARTIFACT_SMOKE_RECOGNITION_STEPS:-100}"
BATCH_SIZE="${LILO_ARTIFACT_SMOKE_BATCH_SIZE:-32}"
MODE="${LILO_ARTIFACT_SMOKE_MODE:-all}"

if [ ! -x "$ENV_PREFIX/bin/python" ]; then
  echo "LILO conda environment not found at: $ENV_PREFIX" >&2
  echo "Run scripts/create_lilo_conda_env.sh first." >&2
  exit 1
fi

mkdir -p "$INFO_DIR"

export PYTHONPATH="$PWD:${PYTHONPATH:-}"
export MPLCONFIGDIR="${MPLCONFIGDIR:-$PWD/.cache/matplotlib}"
export LD_LIBRARY_PATH="$ENV_PREFIX/lib:${LD_LIBRARY_PATH:-}"
export PKG_CONFIG_PATH="$ENV_PREFIX/lib/pkgconfig:$ENV_PREFIX/share/pkgconfig:${PKG_CONFIG_PATH:-}"
mkdir -p "$MPLCONFIGDIR"

SUMMARY="$INFO_DIR/summary.tsv"
printf "check\tstatus\texit_code\tduration_seconds\tlog\n" > "$SUMMARY"

run_step() {
  local name="$1"
  local log_path="$2"
  shift 2
  local start_ts end_ts duration exit_code status

  echo "Running smoke check: $name"
  start_ts="$(date +%s)"
  "$@" > "$log_path" 2>&1
  exit_code="$?"
  end_ts="$(date +%s)"
  duration="$((end_ts - start_ts))"
  if [ "$exit_code" -eq 0 ]; then
    status="ok"
  else
    status="exit_$exit_code"
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" "$name" "$status" "$exit_code" "$duration" "$log_path" >> "$SUMMARY"
  return "$exit_code"
}

run_offline_import_smoke() {
  local log_path="$INFO_DIR/offline_import.log"
  run_step "offline_import" "$log_path" "$ENV_PREFIX/bin/python" - <<'PY'
from run_experiment import *  # noqa: F401,F403

p = Program.parse("(_rconcat _x _y)")
print(p.infer())
print(p.evaluate([]))
PY
}

run_dreamcoder_re2_smoke() {
  local log_path="$INFO_DIR/dreamcoder_re2.stdout.log"
  local command_path="$INFO_DIR/dreamcoder_re2.command.txt"
  cat > "$command_path" <<EOF
$ENV_PREFIX/bin/python run_iterative_experiment.py \\
  --experiment_name "$RUN_ID" \\
  --experiment_type dreamcoder \\
  --domain re2 \\
  --encoder re2 \\
  --iterations 1 \\
  --global_batch_sizes "$BATCH_SIZE" \\
  --enumeration_timeout "$ENUM_TIMEOUT" \\
  --recognition_train_steps "$RECOGNITION_STEPS" \\
  --random_seeds 0 \\
  --no_s3_sync \\
  --verbose \\
  --overwrite_dir
EOF
  run_step "dreamcoder_re2" "$log_path" "$ENV_PREFIX/bin/python" run_iterative_experiment.py \
    --experiment_name "$RUN_ID" \
    --experiment_type dreamcoder \
    --domain re2 \
    --encoder re2 \
    --iterations 1 \
    --global_batch_sizes "$BATCH_SIZE" \
    --enumeration_timeout "$ENUM_TIMEOUT" \
    --recognition_train_steps "$RECOGNITION_STEPS" \
    --random_seeds 0 \
    --no_s3_sync \
    --verbose \
    --overwrite_dir
}

exit_code=0

case "$MODE" in
  offline)
    run_offline_import_smoke || exit_code=1
    ;;
  dreamcoder)
    run_dreamcoder_re2_smoke || exit_code=1
    ;;
  all)
    run_offline_import_smoke || exit_code=1
    run_dreamcoder_re2_smoke || exit_code=1
    ;;
  *)
    echo "Unknown LILO_ARTIFACT_SMOKE_MODE: $MODE" >&2
    exit 2
    ;;
esac

if [ "$MODE" = "dreamcoder" ] || [ "$MODE" = "all" ]; then
  "$ENV_PREFIX/bin/python" scripts/validate_experiment_outputs.py \
    --experiment-name "$RUN_ID" \
    --experiment-type dreamcoder \
    --batch-size "$BATCH_SIZE" \
    --domains re2 \
    --seeds 0 \
    --evaluated-split train \
    --output "$INFO_DIR/dreamcoder_re2_validation.json" > "$INFO_DIR/dreamcoder_re2_validation.txt" 2>&1 || exit_code=1
fi

echo "Artifact smoke metadata: $INFO_DIR"
echo "Summary: $SUMMARY"
exit "$exit_code"

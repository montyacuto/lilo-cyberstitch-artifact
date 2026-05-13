#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
EXPERIMENT_NAME="${LILO_SMOKE_EXPERIMENT_NAME:-test_runs_strict_$(date +%Y%m%d_%H%M%S)}"

if [ ! -x "$ENV_PREFIX/bin/python" ]; then
  echo "LILO conda environment not found at: $ENV_PREFIX" >&2
  echo "Run scripts/create_lilo_conda_env.sh first." >&2
  exit 1
fi

export PYTHONPATH="$PWD:${PYTHONPATH:-}"
export MPLCONFIGDIR="$PWD/.cache/matplotlib"
export LD_LIBRARY_PATH="$ENV_PREFIX/lib:${LD_LIBRARY_PATH:-}"
export PKG_CONFIG_PATH="$ENV_PREFIX/lib/pkgconfig:$ENV_PREFIX/share/pkgconfig:${PKG_CONFIG_PATH:-}"

"$ENV_PREFIX/bin/python" run_iterative_experiment.py \
  --experiment_name "$EXPERIMENT_NAME" \
  --experiment_type dreamcoder \
  --domain re2 \
  --encoder re2 \
  --iterations 1 \
  --global_batch_sizes 32 \
  --enumeration_timeout 5 \
  --recognition_train_steps 100 \
  --verbose

LOG_PATH="experiments_iterative/outputs/$EXPERIMENT_NAME/domains/re2/dreamcoder/seed_0/dreamcoder_32/run.log"
if [ ! -f "$LOG_PATH" ]; then
  echo "Expected run log was not written: $LOG_PATH" >&2
  exit 2
fi

if grep -q "Exception encountered while running experiment" "$LOG_PATH"; then
  echo "Experiment logged an exception; see: $LOG_PATH" >&2
  exit 3
fi

echo "README DreamCoder RE2 smoke passed: $LOG_PATH"

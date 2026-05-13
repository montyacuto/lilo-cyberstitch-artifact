#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
RUN_ID="${LILO_ARTIFACT_ANALYSIS_ID:-artifact_analysis_$(date +%Y%m%d_%H%M%S)}"
INFO_DIR="$PWD/../Info/analysis_tables/$RUN_ID"
EXPERIMENT_NAME="${LILO_ANALYZE_EXPERIMENT_NAME:-full_lilo_probe_re2_seed111_gbs32_authfix_20260505}"
EXPERIMENT_TYPES="${LILO_ANALYZE_EXPERIMENT_TYPES:-lilo}"
DOMAINS="${LILO_ANALYZE_DOMAINS:-re2}"
SEEDS="${LILO_ANALYZE_SEEDS:-111}"
BATCH_SIZE="${LILO_ANALYZE_BATCH_SIZE:-32}"
SPLIT="${LILO_ANALYZE_SPLIT:-test}"
ALLOW_INCOMPLETE="${LILO_ANALYZE_ALLOW_INCOMPLETE:-1}"

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

read -r -a EXPERIMENT_TYPE_ARGS <<< "$EXPERIMENT_TYPES"
read -r -a DOMAIN_ARGS <<< "$DOMAINS"
read -r -a SEED_ARGS <<< "$SEEDS"
VALIDATE_EXPERIMENT_TYPE="${LILO_VALIDATE_EXPERIMENT_TYPE:-${EXPERIMENT_TYPE_ARGS[0]}}"

{
  echo "analysis_id=$RUN_ID"
  echo "started_at=$(date -Iseconds)"
  echo "experiment_name=$EXPERIMENT_NAME"
  echo "experiment_types=$EXPERIMENT_TYPES"
  echo "domains=$DOMAINS"
  echo "seeds=$SEEDS"
  echo "batch_size=$BATCH_SIZE"
  echo "split=$SPLIT"
  echo "allow_incomplete=$ALLOW_INCOMPLETE"
  "$ENV_PREFIX/bin/python" --version
} > "$INFO_DIR/environment.txt"

"$ENV_PREFIX/bin/python" scripts/compute_table3_stats.py \
  --format markdown \
  --output "$INFO_DIR/table3_dataset_stats.md"
"$ENV_PREFIX/bin/python" scripts/compute_table3_stats.py \
  --format csv \
  --output "$INFO_DIR/table3_dataset_stats.csv"
"$ENV_PREFIX/bin/python" scripts/compute_table3_stats.py \
  --format json \
  --output "$INFO_DIR/table3_dataset_stats.json"

validation_args=(
  --experiment-name "$EXPERIMENT_NAME"
  --experiment-type "$VALIDATE_EXPERIMENT_TYPE"
  --batch-size "$BATCH_SIZE"
  --domains "${DOMAIN_ARGS[@]}"
  --seeds "${SEED_ARGS[@]}"
  --evaluated-split "$SPLIT"
  --output "$INFO_DIR/output_validation.json"
)
if [ "$ALLOW_INCOMPLETE" = "1" ]; then
  validation_args+=(--allow-missing)
fi
"$ENV_PREFIX/bin/python" scripts/validate_experiment_outputs.py "${validation_args[@]}" \
  > "$INFO_DIR/output_validation.txt"

summary_args=(
  --experiment-name "$EXPERIMENT_NAME"
  --domains "${DOMAIN_ARGS[@]}"
  --experiment-types "${EXPERIMENT_TYPE_ARGS[@]}"
  --seeds "${SEED_ARGS[@]}"
  --batch-size "$BATCH_SIZE"
  --split "$SPLIT"
)
if [ "$ALLOW_INCOMPLETE" = "1" ]; then
  summary_args+=(--allow-incomplete-results)
fi

"$ENV_PREFIX/bin/python" scripts/compute_synthesis_summary_table.py "${summary_args[@]}" \
  --format markdown \
  --output "$INFO_DIR/synthesis_summary.md"
"$ENV_PREFIX/bin/python" scripts/compute_synthesis_summary_table.py "${summary_args[@]}" \
  --format csv \
  --output "$INFO_DIR/synthesis_summary.csv"
"$ENV_PREFIX/bin/python" scripts/compute_synthesis_summary_table.py "${summary_args[@]}" \
  --format json \
  --output "$INFO_DIR/synthesis_summary.json"

echo "Artifact analysis outputs: $INFO_DIR"

#!/usr/bin/env bash
set -u -o pipefail

cd "$(dirname "$0")/.."

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
RUN_ID="${LILO_TABLE3_RUN_ID:-table3_available_$(date +%Y%m%d_%H%M%S)}"
INFO_DIR="$PWD/../Info/table3_runs/$RUN_ID"
ENUM_TIMEOUT="${LILO_TABLE3_ENUM_TIMEOUT:-5}"
RECOGNITION_STEPS="${LILO_TABLE3_RECOGNITION_STEPS:-100}"
BATCH_SIZE="${LILO_TABLE3_BATCH_SIZE:-32}"

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

{
  echo "run_id=$RUN_ID"
  echo "started_at=$(date -Iseconds)"
  echo "cwd=$PWD"
  echo "env_prefix=$ENV_PREFIX"
  echo "enum_timeout=$ENUM_TIMEOUT"
  echo "recognition_steps=$RECOGNITION_STEPS"
  echo "batch_size=$BATCH_SIZE"
  "$ENV_PREFIX/bin/python" --version
  "$ENV_PREFIX/bin/python" -c 'import pkg_resources, torch; print("stitch_core="+pkg_resources.get_distribution("stitch-core").version); print("torch="+torch.__version__)'
  if [ -n "${OPENAI_API_KEY:-}" ]; then
    echo "OPENAI_API_KEY=set"
  else
    echo "OPENAI_API_KEY=missing"
  fi
  if [ -n "${LILO_OPENAI_API_BASE:-}" ]; then
    echo "LILO_OPENAI_API_BASE=set"
  else
    echo "LILO_OPENAI_API_BASE=missing"
  fi
} > "$INFO_DIR/environment.txt" 2>&1

SUMMARY="$INFO_DIR/summary.tsv"
printf "domain\texperiment_type\tstatus\texit_code\tduration_seconds\ttrain_solved\ttest_solved\tgrammar_update\trun_log\tstdout_log\n" > "$SUMMARY"

run_dreamcoder_domain() {
  local domain="$1"
  local encoder="$2"
  local stdout_log="$INFO_DIR/${domain}_dreamcoder.stdout.log"
  local command_file="$INFO_DIR/${domain}_dreamcoder.command.txt"
  local run_log="experiments_iterative/outputs/$RUN_ID/domains/$domain/dreamcoder/seed_0/dreamcoder_${BATCH_SIZE}/run.log"
  local start_ts end_ts duration exit_code status train_solved test_solved grammar_update

  cat > "$command_file" <<EOF
$ENV_PREFIX/bin/python run_iterative_experiment.py \\
  --experiment_name "$RUN_ID" \\
  --experiment_type dreamcoder \\
  --domain "$domain" \\
  --encoder "$encoder" \\
  --iterations 1 \\
  --global_batch_sizes "$BATCH_SIZE" \\
  --enumeration_timeout "$ENUM_TIMEOUT" \\
  --recognition_train_steps "$RECOGNITION_STEPS" \\
  --random_seeds 0 \\
  --no_s3_sync \\
  --verbose \\
  --overwrite_dir
EOF

  echo "Running DreamCoder $domain; stdout: $stdout_log"
  start_ts=$(date +%s)
  "$ENV_PREFIX/bin/python" run_iterative_experiment.py \
    --experiment_name "$RUN_ID" \
    --experiment_type dreamcoder \
    --domain "$domain" \
    --encoder "$encoder" \
    --iterations 1 \
    --global_batch_sizes "$BATCH_SIZE" \
    --enumeration_timeout "$ENUM_TIMEOUT" \
    --recognition_train_steps "$RECOGNITION_STEPS" \
    --random_seeds 0 \
    --no_s3_sync \
    --verbose \
    --overwrite_dir > "$stdout_log" 2>&1
  exit_code=$?
  end_ts=$(date +%s)
  duration=$((end_ts - start_ts))

  if [ -f "$run_log" ]; then
    if grep -q "Exception encountered while running experiment" "$run_log"; then
      status="exception"
    elif [ "$exit_code" -eq 0 ]; then
      status="ok"
    else
      status="exit_$exit_code"
    fi
    train_solved=$(grep "total_solved_tasks_train" "$run_log" | tail -n 1 | sed -E 's|.*: ([0-9]+) / ([0-9]+).*|\1/\2|' || true)
    test_solved=$(grep "total_solved_tasks_test" "$run_log" | tail -n 1 | sed -E 's|.*: ([0-9]+) / ([0-9]+).*|\1/\2|' || true)
    grammar_update=$(grep "Updated grammar" "$run_log" | tail -n 1 | sed -E 's/.*INFO://' || true)
  else
    status="missing_run_log"
    train_solved=""
    test_solved=""
    grammar_update=""
  fi

  printf "%s\tdreamcoder\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$domain" "$status" "$exit_code" "$duration" "$train_solved" "$test_solved" "$grammar_update" "$run_log" "$stdout_log" >> "$SUMMARY"
}

run_dreamcoder_domain re2 re2
run_dreamcoder_domain clevr clevr
run_dreamcoder_domain logo LOGO

{
  echo "LLM-backed README experiments were not run by this script."
  echo "Reason: no OPENAI_API_KEY, LILO_OPENAI_API_BASE, or local GPT cache was visible in the process environment."
  echo "Affected active templates: llm_solver and lilo."
  echo "To run them later, start LiteLLM or provide an API key, source scripts/env_litellm_gpt35.sh, and initialize from the DreamCoder checkpoint for the matching domain/seed."
} > "$INFO_DIR/llm_status.txt"

echo "Completed Table 3 available-experiment run: $INFO_DIR"
echo "Summary: $SUMMARY"

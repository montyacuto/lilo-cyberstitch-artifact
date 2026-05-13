#!/usr/bin/env bash
set -u -o pipefail

cd "$(dirname "$0")/.."

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
LITELLM_ENV_PREFIX="${LILO_LITELLM_ENV_PREFIX:-$PWD/.conda/envs/litellm}"
RUN_ID="${LILO_FULL_RUN_ID:-full_lilo_gpt35_$(date +%Y%m%d_%H%M%S)}"
INFO_DIR="$PWD/../Info/full_lilo_runs/$RUN_ID"
INIT_RUN_ID="${LILO_INIT_RUN_ID:-cheap_init_all_domains_20260505}"
EXPERIMENT_TYPE="${LILO_FULL_EXPERIMENT_TYPE:-lilo}"
BATCH_SIZE="${LILO_FULL_BATCH_SIZE:-32}"
RECOGNITION_STEPS="${LILO_FULL_RECOGNITION_STEPS:-10000}"
MAX_MEM_PER_ENUMERATION_THREAD="${LILO_FULL_MAX_MEM_PER_ENUMERATION_THREAD:-}"
DOMAINS="${LILO_FULL_DOMAINS:-re2}"
SEEDS="${LILO_FULL_SEEDS:-111}"
PROXY_HOST="${LILO_PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${LILO_PROXY_PORT:-4000}"
OPENAI_MODE="${LILO_OPENAI_MODE:-litellm}"
START_LITELLM_WAS_SET="${LILO_START_LITELLM+x}"
START_LITELLM="${LILO_START_LITELLM:-1}"
STOP_LITELLM_ON_EXIT="${LILO_STOP_LITELLM_ON_EXIT:-1}"
DRY_RUN="${LILO_DRY_RUN:-0}"
CONFIRM_LIVE_LLM="${LILO_CONFIRM_LIVE_LLM:-}"
LLM_CACHE_MODE="${LILO_LLM_CACHE_MODE:-}"
if [ -z "$LLM_CACHE_MODE" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    LLM_CACHE_MODE="off"
  else
    LLM_CACHE_MODE="record"
  fi
fi
LLM_CACHE_DIR="${LILO_LLM_CACHE_DIR:-$PWD/../Info/llm_caches/$RUN_ID}"

case "$LLM_CACHE_MODE" in
  off|record|replay) ;;
  *)
    echo "Invalid LILO_LLM_CACHE_MODE: $LLM_CACHE_MODE. Expected off, record, or replay." >&2
    exit 2
    ;;
esac

case "$OPENAI_MODE" in
  litellm|direct) ;;
  *)
    echo "Invalid LILO_OPENAI_MODE: $OPENAI_MODE. Expected litellm or direct." >&2
    exit 2
    ;;
esac

if [ -n "$MAX_MEM_PER_ENUMERATION_THREAD" ]; then
  case "$MAX_MEM_PER_ENUMERATION_THREAD" in
    ''|*[!0-9]*)
      echo "Invalid LILO_FULL_MAX_MEM_PER_ENUMERATION_THREAD: $MAX_MEM_PER_ENUMERATION_THREAD. Expected integer bytes." >&2
      exit 2
      ;;
  esac
fi

if [ "$OPENAI_MODE" = "direct" ] && [ -z "$START_LITELLM_WAS_SET" ]; then
  START_LITELLM="0"
fi

if [ "$OPENAI_MODE" = "direct" ] && [ "$LLM_CACHE_MODE" != "off" ]; then
  echo "LILO_OPENAI_MODE=direct does not use the LILO_LLM_CACHE_MODE wrapper cache. Set LILO_LLM_CACHE_MODE=off." >&2
  exit 2
fi

if [ "$LLM_CACHE_MODE" = "replay" ] && [ -z "$START_LITELLM_WAS_SET" ]; then
  START_LITELLM="0"
fi

if [ ! -x "$ENV_PREFIX/bin/python" ]; then
  echo "LILO conda environment not found at: $ENV_PREFIX" >&2
  echo "Run scripts/create_lilo_conda_env.sh first." >&2
  exit 1
fi

if [ "$START_LITELLM" = "1" ] && [ ! -x "$LITELLM_ENV_PREFIX/bin/litellm" ]; then
  echo "LiteLLM executable not found at: $LITELLM_ENV_PREFIX/bin/litellm" >&2
  exit 1
fi

if [ "$DRY_RUN" != "1" ] && [ "$LLM_CACHE_MODE" != "replay" ] && [ "$CONFIRM_LIVE_LLM" != "YES" ]; then
  echo "Refusing to start live LLM run without LILO_CONFIRM_LIVE_LLM=YES." >&2
  echo "Use LILO_LLM_CACHE_MODE=replay for offline cache replay." >&2
  echo "Use LILO_DRY_RUN=1 to print commands without running experiments." >&2
  exit 2
fi

mkdir -p "$INFO_DIR"
if [ "$DRY_RUN" != "1" ]; then
  if [ "$LLM_CACHE_MODE" = "record" ]; then
    mkdir -p "$LLM_CACHE_DIR"
  elif [ "$LLM_CACHE_MODE" = "replay" ] && [ ! -d "$LLM_CACHE_DIR" ]; then
    echo "Replay cache directory does not exist: $LLM_CACHE_DIR" >&2
    exit 1
  fi
fi

export PYTHONPATH="$PWD:${PYTHONPATH:-}"
export MPLCONFIGDIR="${MPLCONFIGDIR:-$PWD/.cache/matplotlib}"
export LD_LIBRARY_PATH="$ENV_PREFIX/lib:${LD_LIBRARY_PATH:-}"
export PKG_CONFIG_PATH="$ENV_PREFIX/lib/pkgconfig:$ENV_PREFIX/share/pkgconfig:${PKG_CONFIG_PATH:-}"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export HF_HOME="${HF_HOME:-$PWD/.cache/huggingface}"
export TRANSFORMERS_CACHE="${TRANSFORMERS_CACHE:-$HF_HOME/transformers}"
export LILO_LLM_CACHE_MODE="$LLM_CACHE_MODE"
export LILO_LLM_CACHE_DIR="$LLM_CACHE_DIR"
mkdir -p "$MPLCONFIGDIR" "$HF_HOME" "$TRANSFORMERS_CACHE"

if [ -f "$HOME/.config/lilo/openai.env" ]; then
  # shellcheck disable=SC1090
  source "$HOME/.config/lilo/openai.env"
fi

if [ "$OPENAI_MODE" = "litellm" ]; then
  PROVIDER_OPENAI_API_KEY="${LITELLM_OPENAI_API_KEY:-${OPENAI_API_KEY:-}}"
  export LITELLM_OPENAI_API_KEY="$PROVIDER_OPENAI_API_KEY"
  export LITELLM_MASTER_KEY="${LITELLM_MASTER_KEY:-litellm-local-repro-key}"
  export LILO_OPENAI_API_BASE="${LILO_OPENAI_API_BASE:-http://$PROXY_HOST:$PROXY_PORT/v1}"
  export OPENAI_API_KEY="$LITELLM_MASTER_KEY"

  # shellcheck disable=SC1091
  source scripts/env_litellm_initial_lilo.sh
else
  if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "OPENAI_API_KEY is missing. Define it in the environment or ~/.config/lilo/openai.env." >&2
    exit 1
  fi
  unset LILO_OPENAI_API_BASE OPENAI_API_BASE OPENAI_BASE_URL
  unset LILO_LLM_MODEL_MAP LILO_LLM_GPT_3_5_TURBO_MODEL
fi

PROXY_PID=""

cleanup() {
  if [ -n "$PROXY_PID" ] && [ "$STOP_LITELLM_ON_EXIT" = "1" ]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

domain_encoder() {
  case "$1" in
    re2) echo "re2" ;;
    clevr) echo "clevr" ;;
    logo) echo "LOGO" ;;
    *) echo "Unknown domain: $1" >&2; return 1 ;;
  esac
}

domain_iterations() {
  local default_iterations override_iterations
  case "$1" in
    re2)
      default_iterations="16"
      override_iterations="${LILO_FULL_RE2_ITERATIONS:-${LILO_FULL_ITERATIONS:-}}"
      ;;
    clevr)
      default_iterations="10"
      override_iterations="${LILO_FULL_CLEVR_ITERATIONS:-${LILO_FULL_ITERATIONS:-}}"
      ;;
    logo)
      default_iterations="10"
      override_iterations="${LILO_FULL_LOGO_ITERATIONS:-${LILO_FULL_ITERATIONS:-}}"
      ;;
    *) echo "Unknown domain: $1" >&2; return 1 ;;
  esac
  echo "${override_iterations:-$default_iterations}"
}

domain_timeout() {
  local default_timeout override_timeout
  case "$1" in
    re2)
      default_timeout="1000"
      override_timeout="${LILO_FULL_RE2_TIMEOUT:-${LILO_FULL_ENUMERATION_TIMEOUT:-}}"
      ;;
    clevr)
      default_timeout="600"
      override_timeout="${LILO_FULL_CLEVR_TIMEOUT:-${LILO_FULL_ENUMERATION_TIMEOUT:-}}"
      ;;
    logo)
      default_timeout="1800"
      override_timeout="${LILO_FULL_LOGO_TIMEOUT:-${LILO_FULL_ENUMERATION_TIMEOUT:-}}"
      ;;
    *) echo "Unknown domain: $1" >&2; return 1 ;;
  esac
  echo "${override_timeout:-$default_timeout}"
}

checkpoint_path() {
  local domain="$1"
  local seed="$2"
  echo "experiments_iterative/outputs/$INIT_RUN_ID/domains/$domain/dreamcoder/seed_$seed/dreamcoder_32"
}

checkpoint_summary() {
  local run_dir="$1"
  "$ENV_PREFIX/bin/python" - "$run_dir" <<'PY'
import json
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])


def frontier_iterations():
    iterations = []
    if not run_dir.exists():
        return iterations
    for path in run_dir.iterdir():
        if path.is_dir() and path.name.isdigit() and (path / "frontiers.json").exists():
            iterations.append(int(path.name))
    return sorted(iterations)


def split_was_evaluated(iteration, split):
    metrics_path = run_dir / str(iteration) / "metrics.json"
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


def solved_at(iteration, split):
    with (run_dir / str(iteration) / "frontiers.json").open() as f:
        frontiers = json.load(f)
    solved = frontiers.get("_summary", {}).get("n_tasks_solved", {}).get(split, "")
    total = len(frontiers.get(split, {}))
    if solved == "" or total == 0:
        return ""
    return f"{solved}/{total}"


iterations = frontier_iterations()
if not iterations:
    print("\t\t\t")
    sys.exit(0)

train_iteration = iterations[-1]
test_iterations = [i for i in iterations if split_was_evaluated(i, "test")]
test_iteration = test_iterations[-1] if test_iterations else iterations[-1]

print(
    "\t".join(
        [
            str(train_iteration),
            solved_at(train_iteration, "train"),
            str(test_iteration),
            solved_at(test_iteration, "test"),
        ]
    )
)
PY
}

wait_for_proxy() {
  "$ENV_PREFIX/bin/python" - "$PROXY_HOST" "$PROXY_PORT" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
deadline = time.time() + 60
last_error = None
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=2):
            sys.exit(0)
    except OSError as exc:
        last_error = exc
        time.sleep(1)
print(f"Timed out waiting for LiteLLM proxy at {host}:{port}: {last_error}", file=sys.stderr)
sys.exit(1)
PY
}

if [ "$START_LITELLM" = "1" ] && [ "$DRY_RUN" != "1" ]; then
  if [ -z "${LITELLM_OPENAI_API_KEY:-}" ]; then
    echo "LITELLM_OPENAI_API_KEY is missing. Set it or define OPENAI_API_KEY in ~/.config/lilo/openai.env." >&2
    exit 1
  fi
  "$LITELLM_ENV_PREFIX/bin/litellm" \
    --config litellm_config.initial_lilo.yaml \
    --host "$PROXY_HOST" \
    --port "$PROXY_PORT" > "$INFO_DIR/litellm_proxy.log" 2>&1 &
  PROXY_PID="$!"
  if ! wait_for_proxy; then
    echo "LiteLLM proxy failed to start; aborting before launching experiments." >&2
    exit 1
  fi
fi

{
  echo "run_id=$RUN_ID"
  echo "started_at=$(date -Iseconds)"
  echo "cwd=$PWD"
  echo "env_prefix=$ENV_PREFIX"
  echo "litellm_env_prefix=$LITELLM_ENV_PREFIX"
  echo "init_run_id=$INIT_RUN_ID"
  echo "experiment_type=$EXPERIMENT_TYPE"
  echo "openai_mode=$OPENAI_MODE"
  echo "domains=$DOMAINS"
  echo "seeds=$SEEDS"
  echo "batch_size=$BATCH_SIZE"
  echo "recognition_steps=$RECOGNITION_STEPS"
  echo "max_mem_per_enumeration_thread=${MAX_MEM_PER_ENUMERATION_THREAD:-default}"
  echo "iterations_override=${LILO_FULL_ITERATIONS:-}"
  echo "re2_iterations=${LILO_FULL_RE2_ITERATIONS:-}"
  echo "clevr_iterations=${LILO_FULL_CLEVR_ITERATIONS:-}"
  echo "logo_iterations=${LILO_FULL_LOGO_ITERATIONS:-}"
  echo "enumeration_timeout_override=${LILO_FULL_ENUMERATION_TIMEOUT:-}"
  echo "re2_timeout=${LILO_FULL_RE2_TIMEOUT:-}"
  echo "clevr_timeout=${LILO_FULL_CLEVR_TIMEOUT:-}"
  echo "logo_timeout=${LILO_FULL_LOGO_TIMEOUT:-}"
  echo "proxy=${LILO_OPENAI_API_BASE:-direct_openai}"
  echo "start_litellm=$START_LITELLM"
  echo "dry_run=$DRY_RUN"
  echo "pythonhashseed=$PYTHONHASHSEED"
  echo "hf_home=$HF_HOME"
  echo "transformers_cache=$TRANSFORMERS_CACHE"
  echo "llm_cache_mode=$LILO_LLM_CACHE_MODE"
  echo "llm_cache_dir=$LILO_LLM_CACHE_DIR"
  if [ -f "$LILO_LLM_CACHE_DIR/manifest.jsonl" ]; then
    echo "llm_cache_manifest=$LILO_LLM_CACHE_DIR/manifest.jsonl"
  else
    echo "llm_cache_manifest=missing"
  fi
  if [ -n "${LITELLM_OPENAI_API_KEY:-}" ]; then
    echo "LITELLM_OPENAI_API_KEY=set"
  else
    echo "LITELLM_OPENAI_API_KEY=missing"
  fi
  if [ -n "${OPENAI_API_KEY:-}" ]; then
    echo "OPENAI_API_KEY=set"
  else
    echo "OPENAI_API_KEY=missing"
  fi
  "$ENV_PREFIX/bin/python" --version
  "$ENV_PREFIX/bin/python" -c 'import pkg_resources, torch; print("stitch_core="+pkg_resources.get_distribution("stitch-core").version); print("torch="+torch.__version__)'
  if [ -x "$LITELLM_ENV_PREFIX/bin/python" ]; then
    "$LITELLM_ENV_PREFIX/bin/python" -c 'import importlib.metadata as m; print("litellm="+m.version("litellm"))'
  fi
} > "$INFO_DIR/environment.txt" 2>&1

SUMMARY="$INFO_DIR/summary.tsv"
printf "domain\tseed\tstatus\texit_code\tduration_seconds\ttrain_iteration\ttrain_solved\ttest_iteration\ttest_solved\trun_log\tstdout_log\tcheckpoint\n" > "$SUMMARY"

run_lilo_one() {
  local domain="$1"
  local seed="$2"
  local encoder iterations timeout checkpoint stdout_log command_file run_dir run_log start_ts end_ts duration exit_code status
  local checkpoint_fields train_iteration train_solved test_iteration test_solved
  local max_mem_args=()

  encoder="$(domain_encoder "$domain")" || return 1
  iterations="$(domain_iterations "$domain")" || return 1
  timeout="$(domain_timeout "$domain")" || return 1
  checkpoint="$(checkpoint_path "$domain" "$seed")"
  stdout_log="$INFO_DIR/${domain}_seed_${seed}.stdout.log"
  command_file="$INFO_DIR/${domain}_seed_${seed}.command.txt"
  run_dir="experiments_iterative/outputs/$RUN_ID/domains/$domain/$EXPERIMENT_TYPE/seed_$seed/${EXPERIMENT_TYPE}_${BATCH_SIZE}"
  run_log="$run_dir/run.log"
  if [ -n "$MAX_MEM_PER_ENUMERATION_THREAD" ]; then
    max_mem_args=(--max_mem_per_enumeration_thread "$MAX_MEM_PER_ENUMERATION_THREAD")
  fi

  if [ ! -f "$checkpoint/0/frontiers.json" ]; then
    echo "Missing initialization checkpoint: $checkpoint/0/frontiers.json" >&2
    return 1
  fi

  {
    cat <<EOF
$ENV_PREFIX/bin/python run_iterative_experiment.py \\
  --experiment_name "$RUN_ID" \\
  --experiment_type "$EXPERIMENT_TYPE" \\
  --domain "$domain" \\
  --encoder "$encoder" \\
  --iterations "$iterations" \\
  --global_batch_sizes "$BATCH_SIZE" \\
  --enumeration_timeout "$timeout" \\
  --recognition_train_steps "$RECOGNITION_STEPS" \\
  --random_seeds "$seed" \\
  --init_frontiers_from_checkpoint \\
  --resume_checkpoint_directory "$checkpoint" \\
EOF
    if [ -n "$MAX_MEM_PER_ENUMERATION_THREAD" ]; then
      cat <<EOF
  --max_mem_per_enumeration_thread "$MAX_MEM_PER_ENUMERATION_THREAD" \\
EOF
    fi
    cat <<EOF
  --no_s3_sync
EOF
  } > "$command_file"

  if [ "$DRY_RUN" = "1" ]; then
    echo "DRY RUN: wrote command for $domain seed $seed to $command_file"
    printf "%s\t%s\tdry_run\t0\t0\t\t\t\t\t%s\t%s\t%s\n" \
      "$domain" "$seed" "$run_log" "$stdout_log" "$checkpoint" >> "$SUMMARY"
    return 0
  fi

  echo "Running full LILO $domain seed $seed; stdout: $stdout_log"
  start_ts="$(date +%s)"
  "$ENV_PREFIX/bin/python" run_iterative_experiment.py \
    --experiment_name "$RUN_ID" \
    --experiment_type "$EXPERIMENT_TYPE" \
    --domain "$domain" \
    --encoder "$encoder" \
    --iterations "$iterations" \
    --global_batch_sizes "$BATCH_SIZE" \
    --enumeration_timeout "$timeout" \
    --recognition_train_steps "$RECOGNITION_STEPS" \
    --random_seeds "$seed" \
    --init_frontiers_from_checkpoint \
    --resume_checkpoint_directory "$checkpoint" \
    "${max_mem_args[@]}" \
    --no_s3_sync > "$stdout_log" 2>&1
  exit_code="$?"
  end_ts="$(date +%s)"
  duration="$((end_ts - start_ts))"

  if [ -f "$run_log" ]; then
    if grep -Eq "Exception encountered while running experiment|Traceback" "$run_log"; then
      status="exception"
    elif [ "$exit_code" -eq 0 ]; then
      status="ok"
    else
      status="exit_$exit_code"
    fi
    checkpoint_fields="$(checkpoint_summary "$run_dir")"
    IFS=$'\t' read -r train_iteration train_solved test_iteration test_solved <<< "$checkpoint_fields"
    if [ -z "$train_solved" ]; then
      train_solved="$(grep "total_solved_tasks_train" "$run_log" | tail -n 1 | sed -E 's|.*: ([0-9]+) / ([0-9]+).*|\1/\2|' || true)"
    fi
    if [ -z "$test_solved" ]; then
      test_solved="$(grep "total_solved_tasks_test" "$run_log" | tail -n 1 | sed -E 's|.*: ([0-9]+) / ([0-9]+).*|\1/\2|' || true)"
    fi
  else
    status="missing_run_log"
    train_iteration=""
    train_solved=""
    test_iteration=""
    test_solved=""
  fi

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$domain" "$seed" "$status" "$exit_code" "$duration" "$train_iteration" "$train_solved" "$test_iteration" "$test_solved" "$run_log" "$stdout_log" "$checkpoint" >> "$SUMMARY"
}

for domain in $DOMAINS; do
  for seed in $SEEDS; do
    run_lilo_one "$domain" "$seed" || exit 1
  done
done

echo "Full LILO run metadata: $INFO_DIR"
echo "Summary: $SUMMARY"

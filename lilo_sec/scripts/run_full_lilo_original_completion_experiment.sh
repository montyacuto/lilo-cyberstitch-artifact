#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export LILO_OPENAI_MODE=direct
export LILO_START_LITELLM=0
export LILO_FULL_EXPERIMENT_TYPE=lilo_original_completion
export LILO_LLM_CACHE_MODE="${LILO_LLM_CACHE_MODE:-off}"
export LILO_FULL_RUN_ID="${LILO_FULL_RUN_ID:-full_lilo_gpt35_instruct_original_completion_$(date +%Y%m%d_%H%M%S)}"

exec scripts/run_full_lilo_experiment.sh "$@"

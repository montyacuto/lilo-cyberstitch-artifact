#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ROOT="$PWD"
PROJECT_ROOT="$(dirname "$ROOT")"
ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$ROOT/.conda/envs/lilo}"
LITELLM_ENV_PREFIX="${LILO_LITELLM_ENV_PREFIX:-$ROOT/.conda/envs/litellm}"
LOCAL_OPAM_BIN="$ROOT/dreamcoder/solvers/_opam/bin"
RUN_ID="${LILO_ARTIFACT_METADATA_ID:-artifact_metadata_$(date +%Y%m%d_%H%M%S)}"
INFO_DIR="$PROJECT_ROOT/Info/artifact_metadata/$RUN_ID"

mkdir -p "$INFO_DIR"

PATH_ENTRIES=()
if [ -d "$LOCAL_OPAM_BIN" ]; then
  PATH_ENTRIES+=("$LOCAL_OPAM_BIN")
fi
if [ -d "$ENV_PREFIX/bin" ]; then
  PATH_ENTRIES+=("$ENV_PREFIX/bin")
fi
PATH_ENTRIES+=("$PATH")
export PATH
PATH="$(IFS=:; echo "${PATH_ENTRIES[*]}")"
export LD_LIBRARY_PATH="$ENV_PREFIX/lib:${LD_LIBRARY_PATH:-}"
export PKG_CONFIG_PATH="$ENV_PREFIX/lib/pkgconfig:$ENV_PREFIX/share/pkgconfig:${PKG_CONFIG_PATH:-}"
export OPAMROOT="${LILO_OPAMROOT:-$ROOT/.opam}"
if command -v opam >/dev/null 2>&1 && [ -d "$ROOT/dreamcoder/solvers/_opam" ]; then
  eval "$(opam env --switch "$ROOT/dreamcoder/solvers" --set-switch 2>/dev/null)" || true
fi

run_optional() {
  local output_path="$1"
  shift
  {
    echo "$ $*"
    if command -v "$1" >/dev/null 2>&1 || [ -x "$1" ]; then
      "$@" || true
    else
      echo "missing command: $1"
    fi
  } > "$output_path" 2>&1
}

{
  echo "metadata_id=$RUN_ID"
  echo "created_at=$(date -Iseconds)"
  echo "project_root=$PROJECT_ROOT"
  echo "lilo_root=$ROOT"
  echo "lilo_env_prefix=$ENV_PREFIX"
  echo "litellm_env_prefix=$LITELLM_ENV_PREFIX"
  echo "local_opam_bin=$LOCAL_OPAM_BIN"
  echo "opamroot=$OPAMROOT"
  echo "user=$(id -un 2>/dev/null || true)"
  echo "uid=$(id -u 2>/dev/null || true)"
  echo "kernel=$(uname -a)"
} > "$INFO_DIR/manifest.txt"

{
  echo "## CPU"
  lscpu 2>/dev/null || true
  echo
  echo "## Memory"
  free -h 2>/dev/null || true
  echo
  echo "## Filesystems"
  df -h "$PROJECT_ROOT" 2>/dev/null || true
  echo
  echo "## PCI"
  if command -v lspci >/dev/null 2>&1; then
    lspci
  else
    echo "lspci missing"
  fi
} > "$INFO_DIR/hardware.txt" 2>&1

{
  echo "## Shell"
  bash --version | head -n 1
  echo
  echo "## Python"
  if [ -x "$ENV_PREFIX/bin/python" ]; then
    "$ENV_PREFIX/bin/python" --version
    "$ENV_PREFIX/bin/python" -c 'import sys; print(sys.executable)'
  else
    echo "missing: $ENV_PREFIX/bin/python"
  fi
  echo
  echo "## LiteLLM Python"
  if [ -x "$LITELLM_ENV_PREFIX/bin/python" ]; then
    "$LITELLM_ENV_PREFIX/bin/python" --version
    "$LITELLM_ENV_PREFIX/bin/python" -c 'import importlib.metadata as m; print("litellm="+m.version("litellm"))' || true
  else
    echo "missing: $LITELLM_ENV_PREFIX/bin/python"
  fi
  echo
  for command_name in conda opam ocaml dune jbuilder cargo rustc docker codeql aws git; do
    echo "## $command_name"
    if command -v "$command_name" >/dev/null 2>&1; then
      command -v "$command_name"
      case "$command_name" in
        ocaml) "$command_name" -version || true ;;
        git) "$command_name" --version || true ;;
        *) "$command_name" --version || true ;;
      esac
    else
      echo "missing"
    fi
    echo
  done
} > "$INFO_DIR/versions.txt" 2>&1

if command -v conda >/dev/null 2>&1; then
  conda list -p "$ENV_PREFIX" > "$INFO_DIR/lilo_conda_list.txt" 2>&1 || true
  conda list -p "$LITELLM_ENV_PREFIX" > "$INFO_DIR/litellm_conda_list.txt" 2>&1 || true
fi

if [ -x "$ENV_PREFIX/bin/python" ]; then
  "$ENV_PREFIX/bin/python" -m pip freeze > "$INFO_DIR/lilo_pip_freeze.txt" 2>&1 || true
fi
if [ -x "$LITELLM_ENV_PREFIX/bin/python" ]; then
  "$LITELLM_ENV_PREFIX/bin/python" -m pip freeze > "$INFO_DIR/litellm_pip_freeze.txt" 2>&1 || true
fi

{
  echo "## opam switch"
  opam switch 2>/dev/null || true
  echo
  echo "## opam list"
  opam list 2>/dev/null || true
  echo
  echo "## opam switch export"
  opam switch export - 2>/dev/null || true
} > "$INFO_DIR/opam_state.txt" 2>&1

{
  echo "## lilo_sec git"
  git -C "$ROOT" rev-parse HEAD 2>/dev/null || true
  git -C "$ROOT" status --short 2>/dev/null || true
  echo
  echo "## lilo_sec submodules"
  git -C "$ROOT" submodule status --recursive 2>/dev/null || true
  echo
  echo "## upstream clones"
  for repo in "$PROJECT_ROOT/DreamCoder_laps_upstream" "$PROJECT_ROOT/STITCH_upstream"; do
    echo "### $repo"
    git -C "$repo" rev-parse HEAD 2>/dev/null || true
    git -C "$repo" status --short 2>/dev/null || true
  done
} > "$INFO_DIR/git_state.txt" 2>&1

cp "$ROOT/litellm_config.initial_lilo.yaml" "$INFO_DIR/litellm_config.initial_lilo.yaml" 2>/dev/null || true
cp "$ROOT/environment.yml" "$INFO_DIR/environment.yml" 2>/dev/null || true

(
  cd "$PROJECT_ROOT"
  {
    printf '%s\n' \
      Info/Artifact_Entrypoints_20260506.md \
      Info/Artifact_Evaluator_Guide_20260506.md \
      Info/Artifact_Packaging_Boundary_20260506.md \
      Info/CyberSTITCH_CodeQL_Bundle_Policy_20260506.md \
      Info/CyberSTITCH_CodeQL_CMDI100_Experiment_20260506.md \
      Info/CyberSTITCH_CodeQL_CMDI_SQLI_FULL_Experiment_20260506.md \
      Info/artifact_packaging_exclusions_20260506.txt \
      Info/CyberSTITCH_CodeQL_Curated4_Experiment_20260506.md \
      Info/CyberSTITCH_CodeQL_OWASP_PoC_20260506.md \
      Info/CyberSTITCH_CodeQL_Run_Index_20260506.md \
      Info/CyberSTITCH_Environment_Setup_20260506.md \
      Info/CyberSTITCH_GPU_Search_Strategy_20260506.md \
      Info/FullLILO_RunPlan_20260505.md \
      Info/Issues.md \
      Info/LLM_Offline_Replay_20260506.md \
      Info/LiteLLM_Readiness_20260505.md \
      Info/TODO.md \
      lilo \
      lilo_sec/environment.yml \
      lilo_sec/litellm_config.initial_lilo.yaml \
      lilo_sec/experiments_iterative/templates/template_lilo.json \
      lilo_sec/experiments_iterative/templates/template_llm_solver.json \
      lilo_sec/scripts/artifact.sh \
      lilo_sec/scripts/analyze_artifact_results.sh \
      lilo_sec/scripts/collect_artifact_metadata.sh \
      lilo_sec/scripts/lilo \
      lilo_sec/scripts/lilo_menu.py \
      lilo_sec/scripts/run_artifact_smoke.sh \
      lilo_sec/scripts/run_full_lilo_experiment.sh \
      lilo_sec/scripts/validate_experiment_outputs.py \
      lilo_sec/scripts/verify_artifact_readiness.py \
      lilo_sec/src/models/gpt_solver.py \
      lilo_sec/src/openai_compat.py \
      lilo_sec/src/test_openai_compat_cache.py
    find Info/locks -type f | sort
    find Info/analysis_tables -maxdepth 2 -type f \( -name '*.md' -o -name '*.csv' -o -name '*.json' \) | sort
    find Info/table3_stats -type f | sort
    printf '%s\n' \
      cyberstitch_poc/.gitignore \
      cyberstitch_poc/Makefile \
      cyberstitch_poc/README.md \
      cyberstitch_poc/cyberstitch.yml \
      cyberstitch_poc/pyproject.toml \
      cyberstitch_poc/benchmarks/owasp_curated_subset.json \
      cyberstitch_poc/benchmarks/owasp_curated_subset_benchmarkjava.json \
      cyberstitch_poc/benchmarks/owasp_cmdi_100_benchmarkjava.json \
      cyberstitch_poc/benchmarks/owasp_cmdi_sqli_all_benchmarkjava.json \
      cyberstitch_poc/fixtures/sample_owasp.sarif \
      cyberstitch_poc/fixtures/stitch_candidates.json
    find cyberstitch_poc/cyberstitch -maxdepth 1 -type f -name '*.py' | sort
    find cyberstitch_poc/queries -type f | sort
    find cyberstitch_poc/scripts -type f | sort
    find cyberstitch_poc/tests -maxdepth 1 -type f | sort
    find cyberstitch_poc/results -maxdepth 1 -type d -name 'benchmarkjava*' | sort | while IFS= read -r run_dir; do
      printf '%s\n' \
        "$run_dir/report.md" \
        "$run_dir/doctor.json" \
        "$run_dir/bundle-policy.json" \
        "$run_dir/summary.json" \
        "$run_dir/summary.md" \
        "$run_dir/commands.log" \
        "$run_dir/environment.txt"
      [ -d "$run_dir/score" ] && find "$run_dir/score" -maxdepth 1 -type f -name '*.json' | sort
      [ -d "$run_dir/sarif" ] && find "$run_dir/sarif" -maxdepth 1 -type f -name '*.sarif' | sort
      [ -d "$run_dir/compare" ] && find "$run_dir/compare" -maxdepth 1 -type f -name '*.json' | sort
      [ -d "$run_dir/sqir" ] && find "$run_dir/sqir" -type f | sort
      [ -d "$run_dir/fcir" ] && find "$run_dir/fcir" -type f | sort
      [ -d "$run_dir/roundtrip" ] && find "$run_dir/roundtrip" -type f | sort
      [ -d "$run_dir/stitch" ] && find "$run_dir/stitch" -type f | sort
      [ -d "$run_dir/validation" ] && find "$run_dir/validation" -type f | sort
      [ -d "$run_dir/rewritten" ] && find "$run_dir/rewritten" -type f | sort
    done
  } | while IFS= read -r path; do
    if [ -f "$path" ]; then
      sha256sum "$path"
    fi
  done
) > "$INFO_DIR/checksums.sha256"

echo "Artifact metadata: $INFO_DIR"

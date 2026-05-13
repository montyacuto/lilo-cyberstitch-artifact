#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PYTHON_BIN="${CYBERSTITCH_PYTHON:-python3}"
RESULTS_ID="benchmarkjava_curated_$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR=""
OWASP_ROOT="benchmarks/BenchmarkJava"
MANIFEST="benchmarks/owasp_curated_subset_benchmarkjava.json"
BUNDLE_MODE="none"
STITCH_MODE="offline"
STITCH_PYTHON="${CYBERSTITCH_STITCH_PYTHON:-}"
LLM_PROPOSE="none"
LLM_FIXTURE=""
LLM_MODEL="${CYBERSTITCH_LLM_MODEL:-}"
LILO_LOOP="none"
LILO_LOOP_FIXTURE=""
LILO_PARTITION_MODE="${CYBERSTITCH_LILO_PARTITION_MODE:-auto}"
LILO_PROMPT_BYTE_BUDGET="${CYBERSTITCH_LILO_PROMPT_BYTE_BUDGET:-45000}"
LILO_MAX_LIBRARY_ITEMS="${CYBERSTITCH_LILO_MAX_LIBRARY_ITEMS:-0}"
LILO_MAX_CONCEPTS_PER_PARTITION="${CYBERSTITCH_LILO_MAX_CONCEPTS_PER_PARTITION:-0}"
LILO_MAX_USE_SITE_EXAMPLES="${CYBERSTITCH_LILO_MAX_USE_SITE_EXAMPLES:-2}"
AUTODOC_EVAL="none"
AUTODOC_EVAL_FIXTURE=""
AUTODOC_EVAL_SAMPLES="${CYBERSTITCH_AUTODOC_EVAL_SAMPLES:-3}"
SEED_PROFILE="baseline"
SEED_DISCOVERY="official"
INCLUDE_EXPERIMENTAL=0
BOUNDED_SEED_MANIFEST="query_profiles/bounded-java/seed_manifest.json"
CODEQL_CHECK_MODE="strict"
BUILD_COMMAND=""
MAVEN_REPO=""
CODEQL_BIN="${CYBERSTITCH_CODEQL:-}"
SKIP_DB_CREATE=0
BUNDLE_PATH=""
LOG_FILE=""
START_EPOCH=""
RUN_STATUS="running"

usage() {
  cat <<'EOF'
Usage: scripts/run_curated_benchmarkjava_experiment.sh [options]

Runs the curated OWASP BenchmarkJava CodeQL experiment end to end.

Options:
  --results-id <id>       Results subdirectory name under results/.
  --results-dir <path>    Explicit results directory.
  --owasp-root <path>     OWASP BenchmarkJava checkout. Default: benchmarks/BenchmarkJava.
  --manifest <path>       Curated manifest. Default: benchmarks/owasp_curated_subset_benchmarkjava.json.
  --build-command <cmd>   CodeQL manual build command.
  --maven-repo <path>     Maven cache path used by the default build command.
  --codeql <path>         CodeQL binary path if codeql is not on PATH.
  --python <path>         Python executable. Default: CYBERSTITCH_PYTHON or python3.
  --bundle none           Do not create a CodeQL database bundle. Default.
  --bundle debug          Create a restricted bundle with diagnostics, logs, and results.
  --bundle minimal        Create a restricted bundle without diagnostics/logs/results.
  --stitch-mode <mode>    STITCH stage mode: offline or live. Default: offline.
  --stitch-python <path>  Python with stitch_core installed. Defaults to the LILO conda env when present.
  --llm-propose <mode>    Optional LILO LLM proposal mode: none, live, or fixture. Default: none.
  --llm-fixture <path>    JSON proposal fixture for --llm-propose fixture.
  --llm-model <model>     Model name for --llm-propose live. Defaults to CYBERSTITCH_LLM_MODEL or LILO bridge default.
  --lilo-loop <mode>      LILO loop adapter mode: none, fixture, or live. Default: none.
  --lilo-loop-fixture <p> JSON fixture for --lilo-loop fixture. Default: fixtures/lilo_loop_outputs.json.
  --lilo-partition-mode <m>
                          LILO prompt partition mode: auto, off, or role. Default: auto.
  --lilo-prompt-byte-budget <n>
                          Prompt byte budget before partitioning. Default: 45000.
  --lilo-max-library-items <n>
                          Optional rank-based LILO prompt inventory cap. Default: 0 (uncapped).
  --lilo-max-concepts-per-partition <n>
                          Optional concept cap per prompt partition. Default: 0 (uncapped).
  --lilo-max-use-site-examples <n>
                          Compact use-site examples per item. Default: 2.
  --autodoc-eval <mode>   AutoDoc A/B eval mode: none, fixture, live, or replay. Default: none.
  --autodoc-eval-fixture <p>
                          JSON fixture for --autodoc-eval fixture. Default: fixtures/autodoc_eval_responses.json.
  --autodoc-samples <n>   Samples per AutoDoc eval task/condition. Default: CYBERSTITCH_AUTODOC_EVAL_SAMPLES or 3.
  --seed-profile <name>   Query profile: baseline, official-flow, combined, official-pack, combined-pack,
                          official-expanded, official-expanded-pack, bounded-java, or bounded-java-pack.
                          Default: baseline. official-pack adds CodeQL pack FCIR mining to baseline executable queries.
                          combined-pack adds CodeQL pack FCIR mining to combined executable queries.
                          official-expanded uses the companion hand-authored official-semantics seed pack.
                          official-expanded-pack also adds CodeQL pack FCIR mining.
                          bounded-java generates a bounded SQIR-compatible query profile from a checked-in seed manifest.
  --bounded-seed-manifest <path>
                          Seed manifest for bounded-java profiles. Default: query_profiles/bounded-java/seed_manifest.json.
  --codeql-check-mode <m> CodeQL syntax gate: strict or final-only. Default: strict.
  --seed-discovery <mode> Official CodeQL discovery mode: none or official. Default: official.
  --include-experimental  Include experimental CodeQL CWE-78/CWE-89 queries in discovery and pack FCIR.
  --skip-db-create        Reuse an existing CodeQL database in the results directory.
  -h, --help              Show this help.

Bundles are source-containing restricted troubleshooting artifacts and are never
part of the packageable default evidence set.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --results-id)
      RESULTS_ID="$2"
      shift 2
      ;;
    --results-dir)
      RESULTS_DIR="$2"
      shift 2
      ;;
    --owasp-root)
      OWASP_ROOT="$2"
      shift 2
      ;;
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --build-command)
      BUILD_COMMAND="$2"
      shift 2
      ;;
    --maven-repo)
      MAVEN_REPO="$2"
      shift 2
      ;;
    --codeql)
      CODEQL_BIN="$2"
      shift 2
      ;;
    --python)
      PYTHON_BIN="$2"
      shift 2
      ;;
    --bundle)
      BUNDLE_MODE="$2"
      shift 2
      ;;
    --stitch-mode)
      STITCH_MODE="$2"
      shift 2
      ;;
    --stitch-python)
      STITCH_PYTHON="$2"
      shift 2
      ;;
    --llm-propose)
      LLM_PROPOSE="$2"
      shift 2
      ;;
    --llm-fixture)
      LLM_FIXTURE="$2"
      shift 2
      ;;
    --llm-model)
      LLM_MODEL="$2"
      shift 2
      ;;
    --lilo-loop)
      LILO_LOOP="$2"
      shift 2
      ;;
    --lilo-loop-fixture)
      LILO_LOOP_FIXTURE="$2"
      shift 2
      ;;
    --lilo-partition-mode)
      LILO_PARTITION_MODE="$2"
      shift 2
      ;;
    --lilo-prompt-byte-budget)
      LILO_PROMPT_BYTE_BUDGET="$2"
      shift 2
      ;;
    --lilo-max-library-items)
      LILO_MAX_LIBRARY_ITEMS="$2"
      shift 2
      ;;
    --lilo-max-concepts-per-partition)
      LILO_MAX_CONCEPTS_PER_PARTITION="$2"
      shift 2
      ;;
    --lilo-max-use-site-examples)
      LILO_MAX_USE_SITE_EXAMPLES="$2"
      shift 2
      ;;
    --autodoc-eval)
      AUTODOC_EVAL="$2"
      shift 2
      ;;
    --autodoc-eval-fixture)
      AUTODOC_EVAL_FIXTURE="$2"
      shift 2
      ;;
    --autodoc-samples)
      AUTODOC_EVAL_SAMPLES="$2"
      shift 2
      ;;
    --seed-profile)
      SEED_PROFILE="$2"
      shift 2
      ;;
    --bounded-seed-manifest)
      BOUNDED_SEED_MANIFEST="$2"
      shift 2
      ;;
    --codeql-check-mode)
      CODEQL_CHECK_MODE="$2"
      shift 2
      ;;
    --seed-discovery)
      SEED_DISCOVERY="$2"
      shift 2
      ;;
    --include-experimental)
      INCLUDE_EXPERIMENTAL=1
      shift
      ;;
    --skip-db-create)
      SKIP_DB_CREATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$BUNDLE_MODE" in
  none|debug|minimal)
    ;;
  *)
    echo "--bundle must be one of: none, debug, minimal" >&2
    exit 2
    ;;
esac

case "$STITCH_MODE" in
  offline|live)
    ;;
  *)
    echo "--stitch-mode must be one of: offline, live" >&2
    exit 2
    ;;
esac

case "$LLM_PROPOSE" in
  none|live|fixture)
    ;;
  *)
    echo "--llm-propose must be one of: none, live, fixture" >&2
    exit 2
    ;;
esac

case "$LILO_LOOP" in
  none|live|fixture)
    ;;
  *)
    echo "--lilo-loop must be one of: none, live, fixture" >&2
    exit 2
    ;;
esac

case "$LILO_PARTITION_MODE" in
  auto|off|role)
    ;;
  *)
    echo "--lilo-partition-mode must be one of: auto, off, role" >&2
    exit 2
    ;;
esac

case "$AUTODOC_EVAL" in
  none|live|replay|fixture)
    ;;
  *)
    echo "--autodoc-eval must be one of: none, fixture, live, replay" >&2
    exit 2
    ;;
esac

case "$SEED_PROFILE" in
  baseline|official-flow|combined|official-pack|combined-pack|official-expanded|official-expanded-pack|bounded-java|bounded-java-pack)
    ;;
  *)
    echo "--seed-profile must be one of: baseline, official-flow, combined, official-pack, combined-pack, official-expanded, official-expanded-pack, bounded-java, bounded-java-pack" >&2
    exit 2
    ;;
esac

case "$SEED_DISCOVERY" in
  none|official)
    ;;
  *)
    echo "--seed-discovery must be one of: none, official" >&2
    exit 2
    ;;
esac

case "$CODEQL_CHECK_MODE" in
  strict|final-only)
    ;;
  *)
    echo "--codeql-check-mode must be one of: strict, final-only" >&2
    exit 2
    ;;
esac

cd "$ROOT"

if [ -z "$RESULTS_DIR" ]; then
  RESULTS_DIR="results/$RESULTS_ID"
fi

if [ -z "$MAVEN_REPO" ]; then
  MAVEN_REPO="$ROOT/results/m2-repository"
fi

if [ -z "$BUILD_COMMAND" ]; then
  BUILD_COMMAND="mvn -Dmaven.repo.local=$MAVEN_REPO clean package -DskipTests"
fi

if [ -z "$CODEQL_BIN" ] && [ -x "$ROOT/../codeql/codeql" ]; then
  CODEQL_BIN="$ROOT/../codeql/codeql"
fi

if [ -z "$STITCH_PYTHON" ] && [ -x "$ROOT/../lilo_sec/.conda/envs/lilo/bin/python" ]; then
  STITCH_PYTHON="$ROOT/../lilo_sec/.conda/envs/lilo/bin/python"
fi

if [ -z "$LILO_LOOP_FIXTURE" ]; then
  LILO_LOOP_FIXTURE="$ROOT/fixtures/lilo_loop_outputs.json"
fi

if [ -z "$AUTODOC_EVAL_FIXTURE" ]; then
  AUTODOC_EVAL_FIXTURE="$ROOT/fixtures/autodoc_eval_responses.json"
fi

case "$SEED_PROFILE" in
  baseline|official-pack)
    QUERY_DIR="queries"
    ;;
  official-flow)
    QUERY_DIR="query_profiles/official-flow"
    ;;
  combined|combined-pack)
    QUERY_DIR="query_profiles/combined"
    ;;
  official-expanded|official-expanded-pack)
    QUERY_DIR="query_profiles/official-expanded"
    ;;
  bounded-java|bounded-java-pack)
    QUERY_DIR="$RESULTS_DIR/generated-query-profiles/bounded-java"
    ;;
esac

export CYBERSTITCH_OWASP_ROOT="$OWASP_ROOT"
export CYBERSTITCH_CURATED_SUBSET_MANIFEST="$MANIFEST"
export CYBERSTITCH_RESULTS_DIR="$RESULTS_DIR"
export CYBERSTITCH_QUERY_DIR="$QUERY_DIR"
export CYBERSTITCH_CODEQL_BUILD_COMMAND="$BUILD_COMMAND"
if [ -n "$CODEQL_BIN" ]; then
  export CYBERSTITCH_CODEQL="$CODEQL_BIN"
fi
if [ -n "$STITCH_PYTHON" ]; then
  export CYBERSTITCH_STITCH_PYTHON="$STITCH_PYTHON"
fi
if [ -n "$LLM_MODEL" ]; then
  export CYBERSTITCH_LLM_MODEL="$LLM_MODEL"
fi

RESULTS_DIR_ABS="$(mkdir -p "$RESULTS_DIR" && cd "$RESULTS_DIR" && pwd)"
RESULTS_DIR="$RESULTS_DIR_ABS"
LOG_FILE="$RESULTS_DIR/commands.log"
SUMMARY_JSON="$RESULTS_DIR/summary.json"
SUMMARY_MD="$RESULTS_DIR/summary.md"
ENV_SNAPSHOT="$RESULTS_DIR/environment.txt"
INFO_INDEX="$ROOT/../Info/CyberSTITCH_CodeQL_Run_Index_20260506.md"
START_EPOCH="$(date +%s)"

run() {
  {
    printf '[%s] +' "$(date -Is)"
    printf ' %q' "$@"
    printf '\n'
  } | tee -a "$LOG_FILE"
  set +e
  "$@" 2>&1 | tee -a "$LOG_FILE"
  local status="${PIPESTATUS[0]}"
  set -e
  if [ "$status" -ne 0 ]; then
    return "$status"
  fi
}

run_to_file() {
  local output="$1"
  shift
  local stderr_file="${output}.stderr"
  {
    printf '[%s] +' "$(date -Is)"
    printf ' %q' "$@"
    printf ' > %q\n' "$output"
  } | tee -a "$LOG_FILE"
  set +e
  "$@" > "$output" 2> "$stderr_file"
  local status="$?"
  set -e
  if [ -s "$output" ]; then
    tee -a "$LOG_FILE" < "$output"
  fi
  if [ -s "$stderr_file" ]; then
    tee -a "$LOG_FILE" < "$stderr_file" >&2
  fi
  rm -f "$stderr_file"
  return "$status"
}

write_bundle_policy() {
  local bundle_created="$1"
  local bundle_path="$2"
  run "$PYTHON_BIN" -c 'import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
bundle_mode = sys.argv[2]
bundle_created = sys.argv[3] == "true"
bundle_path = sys.argv[4] or None
data = {
    "policy": "opt-in only",
    "bundle_mode": bundle_mode,
    "bundle_created": bundle_created,
    "bundle_path": bundle_path,
    "package_by_default": False,
    "contains_source_code": bool(bundle_created),
    "restricted_reason": "CodeQL database bundles contain analyzed source code and are restricted troubleshooting artifacts.",
}
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(data, indent=2) + "\n")
' "$RESULTS_DIR/bundle-policy.json" "$BUNDLE_MODE" "$bundle_created" "$bundle_path"
}

fail_preflight() {
  echo "Preflight failed:" >&2
  for item in "$@"; do
    echo "- $item" >&2
  done
  echo "" >&2
  echo "Expected prepared-workspace command:" >&2
  echo "  cd <original-workspace>/lilo_sec" >&2
  echo "  scripts/artifact.sh codeql-curated-experiment" >&2
  echo "" >&2
  echo "BenchmarkJava setup if missing:" >&2
  echo "  cd <original-workspace>/cyberstitch_poc/benchmarks" >&2
  echo "  git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git BenchmarkJava" >&2
  echo "  cd BenchmarkJava" >&2
  echo "  git checkout b06d6efaebd577a327514364951916e7df3290b4" >&2
  exit 1
}

preflight() {
  local errors=()
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1 && [ ! -x "$PYTHON_BIN" ]; then
    errors+=("Python executable not found: $PYTHON_BIN")
  fi
  if ! command -v java >/dev/null 2>&1; then
    errors+=("java is not on PATH")
  fi
  if ! command -v mvn >/dev/null 2>&1; then
    errors+=("mvn is not on PATH")
  fi
  if [ -n "$CODEQL_BIN" ]; then
    if [ ! -x "$CODEQL_BIN" ]; then
      errors+=("CodeQL binary is not executable: $CODEQL_BIN")
    fi
  elif ! command -v codeql >/dev/null 2>&1; then
    errors+=("codeql is not on PATH and CYBERSTITCH_CODEQL was not set")
  fi
  if [ ! -d "$OWASP_ROOT" ]; then
    errors+=("OWASP BenchmarkJava checkout not found: $OWASP_ROOT")
  fi
  if [ ! -f "$MANIFEST" ]; then
    errors+=("Curated manifest not found: $MANIFEST")
  fi
  if [ "$SEED_PROFILE" = "bounded-java" ] || [ "$SEED_PROFILE" = "bounded-java-pack" ]; then
    if [ ! -f "$BOUNDED_SEED_MANIFEST" ]; then
      errors+=("Bounded seed manifest not found: $BOUNDED_SEED_MANIFEST")
    fi
  elif [ ! -d "$QUERY_DIR" ]; then
    errors+=("Seed profile query directory not found: $QUERY_DIR")
  fi
  if [ ! -w "$RESULTS_DIR" ]; then
    errors+=("Results directory is not writable: $RESULTS_DIR")
  fi
  mkdir -p "$MAVEN_REPO" || errors+=("Could not create Maven cache: $MAVEN_REPO")
  if [ "$SKIP_DB_CREATE" -eq 1 ] && [ ! -d "$RESULTS_DIR/codeql-dbs/java" ]; then
    errors+=("--skip-db-create requested but database is missing: $RESULTS_DIR/codeql-dbs/java")
  fi
  if [ "$STITCH_MODE" = "live" ]; then
    if [ -n "$STITCH_PYTHON" ]; then
      if [ ! -x "$STITCH_PYTHON" ]; then
        errors+=("STITCH Python interpreter is not executable: $STITCH_PYTHON")
      fi
    elif ! command -v stitch >/dev/null 2>&1 && ! command -v compress >/dev/null 2>&1; then
      errors+=("--stitch-mode live requested but no LILO stitch_core Python, stitch, or compress backend was found")
    fi
  fi
  if [ "$LLM_PROPOSE" = "live" ]; then
    if [ -z "$STITCH_PYTHON" ] || [ ! -x "$STITCH_PYTHON" ]; then
      errors+=("--llm-propose live requested but no executable LILO Python was found")
    fi
  elif [ "$LLM_PROPOSE" = "fixture" ]; then
    if [ -z "$LLM_FIXTURE" ] || [ ! -f "$LLM_FIXTURE" ]; then
      errors+=("--llm-propose fixture requested but --llm-fixture was not a file")
    fi
  fi
  if [ "$LILO_LOOP" = "live" ]; then
    if [ -z "$STITCH_PYTHON" ] || [ ! -x "$STITCH_PYTHON" ]; then
      errors+=("--lilo-loop live requested but no executable LILO Python was found")
    fi
    if [ -z "${OPENAI_API_KEY:-}" ]; then
      errors+=("--lilo-loop live requested but OPENAI_API_KEY is not set")
    fi
  elif [ "$LILO_LOOP" = "fixture" ]; then
    if [ -z "$LILO_LOOP_FIXTURE" ] || [ ! -f "$LILO_LOOP_FIXTURE" ]; then
      errors+=("--lilo-loop fixture requested but fixture was not a file: $LILO_LOOP_FIXTURE")
    fi
  fi
  if [ "$AUTODOC_EVAL" = "live" ] || [ "$AUTODOC_EVAL" = "replay" ]; then
    if [ -z "$STITCH_PYTHON" ] || [ ! -x "$STITCH_PYTHON" ]; then
      errors+=("--autodoc-eval $AUTODOC_EVAL requested but no executable LILO Python was found")
    fi
    if [ "$AUTODOC_EVAL" = "live" ] && [ -z "${OPENAI_API_KEY:-}" ]; then
      errors+=("--autodoc-eval live requested but OPENAI_API_KEY is not set")
    fi
  elif [ "$AUTODOC_EVAL" = "fixture" ]; then
    if [ -z "$AUTODOC_EVAL_FIXTURE" ] || [ ! -f "$AUTODOC_EVAL_FIXTURE" ]; then
      errors+=("--autodoc-eval fixture requested but fixture was not a file: $AUTODOC_EVAL_FIXTURE")
    fi
  fi
  if [ "${#errors[@]}" -gt 0 ]; then
    fail_preflight "${errors[@]}"
  fi
}

write_environment_snapshot() {
  {
    echo "# CyberSTITCH Curated BenchmarkJava Environment"
    echo "Created: $(date -Is)"
    echo "Root: $ROOT"
    echo "Results: $RESULTS_DIR"
    echo "OWASP root: $OWASP_ROOT"
    echo "Manifest: $MANIFEST"
    echo "Bundle mode: $BUNDLE_MODE"
    echo "STITCH mode: $STITCH_MODE"
    echo "STITCH Python: ${STITCH_PYTHON:-}"
    echo "LLM propose: $LLM_PROPOSE"
    echo "LLM fixture: ${LLM_FIXTURE:-}"
    echo "LLM model: ${LLM_MODEL:-}"
    echo "LILO loop: $LILO_LOOP"
    echo "LILO loop fixture: ${LILO_LOOP_FIXTURE:-}"
    echo "LILO partition mode: $LILO_PARTITION_MODE"
    echo "LILO prompt byte budget: $LILO_PROMPT_BYTE_BUDGET"
    echo "LILO max library items: $LILO_MAX_LIBRARY_ITEMS"
    echo "LILO max concepts per partition: $LILO_MAX_CONCEPTS_PER_PARTITION"
    echo "LILO max use-site examples: $LILO_MAX_USE_SITE_EXAMPLES"
    echo "AutoDoc eval: $AUTODOC_EVAL"
    echo "AutoDoc eval fixture: ${AUTODOC_EVAL_FIXTURE:-}"
    echo "AutoDoc eval samples: $AUTODOC_EVAL_SAMPLES"
    echo "Seed profile: $SEED_PROFILE"
    echo "Query dir: $QUERY_DIR"
    echo "Bounded seed manifest: $BOUNDED_SEED_MANIFEST"
    echo "CodeQL syntax gate: $CODEQL_CHECK_MODE"
    echo "Seed discovery: $SEED_DISCOVERY"
    echo "Include experimental CodeQL queries: $INCLUDE_EXPERIMENTAL"
    echo "Build command: $BUILD_COMMAND"
    echo "Maven repo: $MAVEN_REPO"
    echo ""
    echo "## Tool Versions"
    "$PYTHON_BIN" --version 2>&1 || true
    java -version 2>&1 || true
    mvn -version 2>&1 || true
    if [ -n "${CYBERSTITCH_CODEQL:-}" ]; then
      "$CYBERSTITCH_CODEQL" version 2>&1 || true
    else
      codeql version 2>&1 || true
    fi
    echo ""
    echo "## OWASP BenchmarkJava"
    git -C "$OWASP_ROOT" rev-parse HEAD 2>/dev/null || true
    git -C "$OWASP_ROOT" log -1 --format='%H %cI %s' 2>/dev/null || true
  } > "$ENV_SNAPSHOT"
}

write_summary() {
  local duration
  duration="$(($(date +%s) - START_EPOCH))"
  run "$PYTHON_BIN" -c 'import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
status = sys.argv[2]
duration = int(sys.argv[3])
bundle_mode = sys.argv[4]
bundle_path = sys.argv[5] or None
skip_db_create = sys.argv[6] == "1"
stitch_mode = sys.argv[7]
llm_propose = sys.argv[8]
seed_profile = sys.argv[9]
seed_discovery = sys.argv[10]
include_experimental = sys.argv[11] == "1"
lilo_loop = sys.argv[12]
lilo_partition_mode = sys.argv[13]
lilo_prompt_byte_budget = int(sys.argv[14])
lilo_max_library_items = int(sys.argv[15])
lilo_max_concepts_per_partition = int(sys.argv[16])
lilo_max_use_site_examples = int(sys.argv[17])

def read_json(rel):
    path = root / rel
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None

scores = {}
for name in ("original", "roundtrip", "rewritten"):
    data = read_json(f"score/{name}.json")
    if data:
        scores[name] = data.get("totals", {})

comparisons = {}
orig = read_json("compare/original_vs_roundtrip.json")
rewr = read_json("compare/original_vs_rewritten.json")
if orig:
    comparisons["original_vs_roundtrip"] = orig
if rewr:
    comparisons["original_vs_rewritten"] = rewr

decisions = read_json("validation/decisions.json") or {"decisions": []}
accepted = [
    item["candidate"]["name"]
    for item in decisions.get("decisions", [])
    if item.get("accepted")
]
accepted_for_lilo = [
    item["candidate"]["name"]
    for item in decisions.get("decisions", [])
    if item.get("accepted_for_lilo")
]
lilo_only = [
    item["candidate"]["name"]
    for item in decisions.get("decisions", [])
    if item.get("accepted_for_lilo") and not item.get("accepted")
]
rejected = [
    item["candidate"]["name"]
    for item in decisions.get("decisions", [])
    if not item.get("accepted")
]

summary = {
    "status": status,
    "duration_seconds": duration,
    "results_dir": str(root),
    "bundle_policy": "opt-in only",
    "bundle_mode": bundle_mode,
    "stitch_mode": stitch_mode,
    "llm_propose": llm_propose,
    "lilo_loop": lilo_loop,
    "lilo_loop_options": {
        "partition_mode": lilo_partition_mode,
        "prompt_byte_budget": lilo_prompt_byte_budget,
        "max_library_items": lilo_max_library_items,
        "max_concepts_per_partition": lilo_max_concepts_per_partition,
        "max_use_site_examples": lilo_max_use_site_examples,
    },
    "seed_profile": seed_profile,
    "seed_discovery": seed_discovery,
    "include_experimental": include_experimental,
    "bundle_path": bundle_path,
    "bundle_created": bool(bundle_path),
    "skip_db_create": skip_db_create,
    "package_by_default": False,
    "scores": scores,
    "comparisons": comparisons,
    "accepted_abstractions": accepted,
    "accepted_for_lilo_abstractions": accepted_for_lilo,
    "lilo_only_abstractions": lilo_only,
    "rejected_abstractions": rejected,
    "seed_discovery_summary": str(root / "seed-discovery" / "summary.json")
    if (root / "seed-discovery" / "summary.json").exists()
    else None,
    "report": str(root / "report.md"),
    "command_log": str(root / "commands.log"),
    "environment": str(root / "environment.txt"),
}
lilo_loop_summary = root / "lilo-loop" / "summary.json"
if lilo_loop_summary.exists():
    summary["lilo_loop_summary"] = str(lilo_loop_summary)
    data = json.loads(lilo_loop_summary.read_text())
    summary["lilo_loop_partition_count"] = data.get("partition_count")
    summary["lilo_loop_prompt_bytes"] = data.get("prompt_bytes")
autodoc_summary = root / "autodoc-eval" / "summary.json"
if autodoc_summary.exists():
    summary["autodoc_eval_summary"] = str(autodoc_summary)
    data = json.loads(autodoc_summary.read_text())
    summary["autodoc_eval_primary_comparison"] = data.get("primary_comparison")
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

lines = ["# CyberSTITCH Curated BenchmarkJava Run Summary", ""]
lines.append(f"Status: `{status}`")
lines.append(f"Results: `{root}`")
lines.append(f"Duration seconds: `{duration}`")
lines.append(f"Bundle mode: `{bundle_mode}`")
lines.append(f"STITCH mode: `{stitch_mode}`")
lines.append(f"LLM propose: `{llm_propose}`")
lines.append(f"LILO loop: `{lilo_loop}`")
lines.append(f"LILO partition mode: `{lilo_partition_mode}`")
lines.append(f"LILO prompt byte budget: `{lilo_prompt_byte_budget}`")
lines.append(f"Seed profile: `{seed_profile}`")
lines.append(f"Seed discovery: `{seed_discovery}`")
lines.append(f"Include experimental CodeQL queries: `{include_experimental}`")
lines.append(f"Bundle created: `{bool(bundle_path)}`")
lines.append(f"Skip db-create: `{skip_db_create}`")
if bundle_path:
    lines.append(f"Restricted bundle: `{bundle_path}`")
lines.append("")
lines.append("## Scores")
for name, totals in scores.items():
    lines.append(f"- `{name}`: `{totals}`")
lines.append("")
lines.append("## Equivalence")
for name, result in comparisons.items():
    lines.append("- `{}`: equivalent=`{}` missing=`{}` extra=`{}`".format(
        name,
        result.get("equivalent"),
        len(result.get("missing", [])),
        len(result.get("extra", [])),
    ))
lines.append("")
lines.append("## Abstractions")
lines.append(f"- rewrite accepted: `{accepted}`")
lines.append(f"- LILO accepted: `{accepted_for_lilo}`")
lines.append(f"- LILO-only: `{lilo_only}`")
lines.append(f"- rewrite rejected: `{rejected}`")
lines.append("")
seed_summary = root / "seed-discovery" / "summary.json"
if seed_summary.exists():
    data = json.loads(seed_summary.read_text())
    lines.append("## Seed Discovery")
    lines.append("- specs: `{}`".format(len(data.get("specs", []))))
    lines.append("- queries: `{}`".format(len(data.get("queries", []))))
    lines.append("- selected seeds: `{}`".format(len(data.get("selected_seeds", []))))
    lines.append("- score: `{}`".format((data.get("score") or {}).get("totals")))
    lines.append("")
lines.append("## Files")
lines.append("- report: `{}`".format(root / "report.md"))
lines.append("- command log: `{}`".format(root / "commands.log"))
lines.append("- environment: `{}`".format(root / "environment.txt"))
if lilo_loop_summary.exists():
    lines.append("- LILO loop summary: `{}`".format(lilo_loop_summary))
    lines.append("- LILO loop report: `{}`".format(root / "lilo-loop" / "report.md"))
if autodoc_summary.exists():
    lines.append("- AutoDoc eval summary: `{}`".format(autodoc_summary))
    lines.append("- AutoDoc eval report: `{}`".format(root / "autodoc-eval" / "report.md"))
(root / "summary.md").write_text("\n".join(lines) + "\n")
' "$RESULTS_DIR" "$RUN_STATUS" "$duration" "$BUNDLE_MODE" "$BUNDLE_PATH" "$SKIP_DB_CREATE" "$STITCH_MODE" "$LLM_PROPOSE" "$SEED_PROFILE" "$SEED_DISCOVERY" "$INCLUDE_EXPERIMENTAL" "$LILO_LOOP" "$LILO_PARTITION_MODE" "$LILO_PROMPT_BYTE_BUDGET" "$LILO_MAX_LIBRARY_ITEMS" "$LILO_MAX_CONCEPTS_PER_PARTITION" "$LILO_MAX_USE_SITE_EXAMPLES"
}

append_info_index() {
  mkdir -p "$(dirname "$INFO_INDEX")"
  if [ ! -f "$INFO_INDEX" ]; then
    {
      echo "# CyberSTITCH CodeQL Run Index"
      echo ""
      echo "Date: 2026-05-06"
      echo ""
      echo "This index records live curated BenchmarkJava runner invocations."
      echo ""
    } > "$INFO_INDEX"
  fi
  {
    echo "## $(date -Is)"
    echo ""
    echo "- Results: \`$RESULTS_DIR\`"
    echo "- Status: \`$RUN_STATUS\`"
    echo "- Bundle mode: \`$BUNDLE_MODE\`"
    echo "- STITCH mode: \`$STITCH_MODE\`"
    echo "- LLM propose: \`$LLM_PROPOSE\`"
    echo "- LILO loop: \`$LILO_LOOP\`"
    echo "- LILO partition mode: \`$LILO_PARTITION_MODE\`"
    echo "- LILO prompt byte budget: \`$LILO_PROMPT_BYTE_BUDGET\`"
    echo "- LILO max library items: \`$LILO_MAX_LIBRARY_ITEMS\`"
    echo "- LILO max concepts per partition: \`$LILO_MAX_CONCEPTS_PER_PARTITION\`"
    echo "- LILO max use-site examples: \`$LILO_MAX_USE_SITE_EXAMPLES\`"
    echo "- AutoDoc eval: \`$AUTODOC_EVAL\`"
    echo "- Seed profile: \`$SEED_PROFILE\`"
    echo "- Seed discovery: \`$SEED_DISCOVERY\`"
    echo "- Include experimental CodeQL queries: \`$INCLUDE_EXPERIMENTAL\`"
    echo "- Bundle created: \`$([ -n "$BUNDLE_PATH" ] && echo true || echo false)\`"
    echo "- Skip db-create: \`$SKIP_DB_CREATE\`"
    if [ -n "$BUNDLE_PATH" ]; then
      echo "- Restricted bundle: \`$BUNDLE_PATH\`"
    fi
    echo "- Summary: \`$SUMMARY_MD\`"
    echo "- Report: \`$RESULTS_DIR/report.md\`"
    echo ""
  } >> "$INFO_INDEX"
}

finish() {
  local exit_code="$?"
  if [ "$exit_code" -eq 0 ]; then
    RUN_STATUS="completed"
  else
    RUN_STATUS="failed"
  fi
  if [ -n "${RESULTS_DIR:-}" ] && [ -d "$RESULTS_DIR" ]; then
    write_summary || true
    append_info_index || true
  fi
  return "$exit_code"
}

trap finish EXIT

preflight
if [ "$SEED_PROFILE" = "bounded-java" ] || [ "$SEED_PROFILE" = "bounded-java-pack" ]; then
  run "$PYTHON_BIN" -m cyberstitch.cli generate-seeds \
    --manifest "$BOUNDED_SEED_MANIFEST" \
    --output-dir "$QUERY_DIR"
fi
write_environment_snapshot

echo "CyberSTITCH curated BenchmarkJava experiment"
echo "Results: $RESULTS_DIR"
echo "Seed profile: $SEED_PROFILE ($QUERY_DIR)"
echo "Seed discovery: $SEED_DISCOVERY; include experimental: $INCLUDE_EXPERIMENTAL"
echo "LILO loop: $LILO_LOOP"
echo "LILO partition mode: $LILO_PARTITION_MODE; prompt budget: $LILO_PROMPT_BYTE_BUDGET bytes"
echo "AutoDoc eval: $AUTODOC_EVAL"
echo "Bundle policy: opt-in only; requested mode: $BUNDLE_MODE"
if [ "$BUNDLE_MODE" = "none" ]; then
  echo "No CodeQL database bundle will be created by default."
else
  echo "A restricted/source-containing CodeQL database bundle will be created."
fi

write_bundle_policy false ""

run "$PYTHON_BIN" -m cyberstitch.cli doctor
run "$PYTHON_BIN" -m cyberstitch.cli manifest
run "$PYTHON_BIN" -m cyberstitch.cli sqir
run "$PYTHON_BIN" -m cyberstitch.cli roundtrip
run "$PYTHON_BIN" -m cyberstitch.cli fcir
if [ "$SEED_PROFILE" = "official-pack" ] || [ "$SEED_PROFILE" = "combined-pack" ] || [ "$SEED_PROFILE" = "official-expanded-pack" ] || [ "$SEED_PROFILE" = "bounded-java-pack" ]; then
  PACK_ARGS=(codeql-pack-fcir)
  if [ "$INCLUDE_EXPERIMENTAL" -eq 1 ]; then
    PACK_ARGS+=(--include-experimental)
  fi
  run "$PYTHON_BIN" -m cyberstitch.cli "${PACK_ARGS[@]}"
fi
if [ -n "$STITCH_PYTHON" ]; then
  run "$PYTHON_BIN" -m cyberstitch.cli stitch --mode "$STITCH_MODE" --stitch-python "$STITCH_PYTHON"
else
  run "$PYTHON_BIN" -m cyberstitch.cli stitch --mode "$STITCH_MODE"
fi
SEMANTIC_MINE_ARGS=(semantic-mine --merge)
if [ "$SEED_PROFILE" = "official-pack" ] || [ "$SEED_PROFILE" = "combined-pack" ] || [ "$SEED_PROFILE" = "official-expanded-pack" ] || [ "$SEED_PROFILE" = "bounded-java-pack" ]; then
  SEMANTIC_MINE_ARGS+=(--include-codeql-pack)
fi
if [ "$INCLUDE_EXPERIMENTAL" -eq 1 ]; then
  SEMANTIC_MINE_ARGS+=(--include-experimental)
fi
run "$PYTHON_BIN" -m cyberstitch.cli "${SEMANTIC_MINE_ARGS[@]}"
if [ "$LILO_LOOP" != "none" ]; then
  run "$PYTHON_BIN" -m cyberstitch.cli validate
fi
LILO_LOOP_COMMON_ARGS=(
  --partition-mode "$LILO_PARTITION_MODE"
  --prompt-byte-budget "$LILO_PROMPT_BYTE_BUDGET"
  --max-library-items "$LILO_MAX_LIBRARY_ITEMS"
  --max-concepts-per-partition "$LILO_MAX_CONCEPTS_PER_PARTITION"
  --max-use-site-examples "$LILO_MAX_USE_SITE_EXAMPLES"
)
case "$LILO_LOOP" in
  none)
    ;;
  live)
    LILO_LOOP_ARGS=(lilo-loop --mode live --merge "${LILO_LOOP_COMMON_ARGS[@]}")
    if [ -n "$STITCH_PYTHON" ]; then
      LILO_LOOP_ARGS+=(--lilo-python "$STITCH_PYTHON")
    fi
    if [ -n "$LLM_MODEL" ]; then
      LILO_LOOP_ARGS+=(--model "$LLM_MODEL")
    fi
    run "$PYTHON_BIN" -m cyberstitch.cli "${LILO_LOOP_ARGS[@]}"
    ;;
  fixture)
    run "$PYTHON_BIN" -m cyberstitch.cli lilo-loop --mode fixture --fixture "$LILO_LOOP_FIXTURE" --merge "${LILO_LOOP_COMMON_ARGS[@]}"
    ;;
esac
case "$LLM_PROPOSE" in
  none)
    ;;
  live)
    if [ -n "$LLM_MODEL" ]; then
      run "$PYTHON_BIN" -m cyberstitch.cli llm-propose --lilo-python "$STITCH_PYTHON" --model "$LLM_MODEL" --merge
    else
      run "$PYTHON_BIN" -m cyberstitch.cli llm-propose --lilo-python "$STITCH_PYTHON" --merge
    fi
    ;;
  fixture)
    run "$PYTHON_BIN" -m cyberstitch.cli llm-propose --fixture "$LLM_FIXTURE" --merge
    ;;
esac
run "$PYTHON_BIN" -m cyberstitch.cli validate
run "$PYTHON_BIN" -m cyberstitch.cli rewrite
if [ "$CODEQL_CHECK_MODE" = "final-only" ]; then
  run "$PYTHON_BIN" -m cyberstitch.cli codeql-check --final-only
else
  run "$PYTHON_BIN" -m cyberstitch.cli codeql-check
fi

case "$AUTODOC_EVAL" in
  none)
    ;;
  fixture)
    run "$PYTHON_BIN" -m cyberstitch.cli autodoc-eval \
      --mode fixture \
      --source-results "$RESULTS_DIR" \
      --fixture "$AUTODOC_EVAL_FIXTURE" \
      --samples "$AUTODOC_EVAL_SAMPLES"
    ;;
  live|replay)
    AUTODOC_ARGS=(autodoc-eval --mode "$AUTODOC_EVAL" --source-results "$RESULTS_DIR" --samples "$AUTODOC_EVAL_SAMPLES")
    if [ -n "$STITCH_PYTHON" ]; then
      AUTODOC_ARGS+=(--lilo-python "$STITCH_PYTHON")
    fi
    if [ -n "$LLM_MODEL" ]; then
      AUTODOC_ARGS+=(--model "$LLM_MODEL")
    fi
    run "$PYTHON_BIN" -m cyberstitch.cli "${AUTODOC_ARGS[@]}"
    ;;
esac

if [ "$SKIP_DB_CREATE" -eq 0 ]; then
  run "$PYTHON_BIN" -m cyberstitch.cli db-create --overwrite --build-command "$BUILD_COMMAND"
else
  echo "Skipping db-create; using $RESULTS_DIR/codeql-dbs/java"
fi

if [ "$SEED_DISCOVERY" = "official" ]; then
  DISCOVERY_ARGS=(codeql-discover --database "$RESULTS_DIR/codeql-dbs/java" --output-dir "$RESULTS_DIR/seed-discovery")
  if [ "$INCLUDE_EXPERIMENTAL" -eq 1 ]; then
    DISCOVERY_ARGS+=(--include-experimental)
  fi
  run "$PYTHON_BIN" -m cyberstitch.cli "${DISCOVERY_ARGS[@]}"
fi

run "$PYTHON_BIN" -m cyberstitch.cli analyze --queries original
run "$PYTHON_BIN" -m cyberstitch.cli analyze --queries roundtrip
run "$PYTHON_BIN" -m cyberstitch.cli analyze --queries rewritten

run "$PYTHON_BIN" -m cyberstitch.cli score --sarif "$RESULTS_DIR/sarif/original.sarif"
run "$PYTHON_BIN" -m cyberstitch.cli score --sarif "$RESULTS_DIR/sarif/roundtrip.sarif"
run "$PYTHON_BIN" -m cyberstitch.cli score --sarif "$RESULTS_DIR/sarif/rewritten.sarif"
mkdir -p "$RESULTS_DIR/compare"
run_to_file "$RESULTS_DIR/compare/original_vs_roundtrip.json" \
  "$PYTHON_BIN" -m cyberstitch.cli compare "$RESULTS_DIR/sarif/original.sarif" "$RESULTS_DIR/sarif/roundtrip.sarif"
run_to_file "$RESULTS_DIR/compare/original_vs_rewritten.json" \
  "$PYTHON_BIN" -m cyberstitch.cli compare "$RESULTS_DIR/sarif/original.sarif" "$RESULTS_DIR/sarif/rewritten.sarif"

case "$BUNDLE_MODE" in
  none)
    ;;
  debug)
    BUNDLE_PATH="$RESULTS_DIR/bundles/java-codeql-debug-artifacts.zip"
    run "$PYTHON_BIN" -m cyberstitch.cli db-bundle --database "$RESULTS_DIR/codeql-dbs/java" --output "$BUNDLE_PATH"
    write_bundle_policy true "$BUNDLE_PATH"
    ;;
  minimal)
    BUNDLE_PATH="$RESULTS_DIR/bundles/java-codeql-minimal-database.zip"
    run "$PYTHON_BIN" -m cyberstitch.cli db-bundle --database "$RESULTS_DIR/codeql-dbs/java" --output "$BUNDLE_PATH" --no-diagnostics
    write_bundle_policy true "$BUNDLE_PATH"
    ;;
esac

run "$PYTHON_BIN" -m cyberstitch.cli report

echo "Completed CyberSTITCH curated BenchmarkJava experiment."
echo "Packageable evidence: $RESULTS_DIR/report.md, $RESULTS_DIR/score, $RESULTS_DIR/sarif, SQIR/FCIR, STITCH decisions, and rewritten queries."
echo "Summary: $SUMMARY_MD"
echo "Command log: $LOG_FILE"
if [ "$BUNDLE_MODE" != "none" ]; then
  echo "Restricted bundle: $BUNDLE_PATH"
fi

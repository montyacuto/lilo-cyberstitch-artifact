#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"

if [ ! -x "$ENV_PREFIX/bin/python" ]; then
  echo "LILO environment not found at: $ENV_PREFIX" >&2
  echo "Run scripts/create_lilo_conda_env.sh first." >&2
  exit 1
fi

export PYTHONPATH="$PWD:${PYTHONPATH:-}"
export MPLCONFIGDIR="${MPLCONFIGDIR:-$PWD/.cache/matplotlib}"
mkdir -p "$MPLCONFIGDIR"

"$ENV_PREFIX/bin/python" - <<'PY'
from run_experiment import *

p = Program.parse("(_rconcat _x _y)")
print(p.infer())
print(p.evaluate([]))
PY

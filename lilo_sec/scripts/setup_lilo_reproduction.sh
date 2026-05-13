#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Initializing DreamCoder submodule"
git -c url.https://github.com/.insteadOf=git@github.com: submodule update --init dreamcoder

echo "Creating staged Python environment"
scripts/create_lilo_conda_env.sh

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
export PATH="$ENV_PREFIX/bin:$PATH"
export PKG_CONFIG_PATH="$ENV_PREFIX/lib/pkgconfig:$ENV_PREFIX/share/pkgconfig:${PKG_CONFIG_PATH:-}"

echo "Building DreamCoder OCaml binaries"
scripts/build_dreamcoder.sh

echo "Running environment check"
"$ENV_PREFIX/bin/python" scripts/check_lilo_environment.py --no-fail

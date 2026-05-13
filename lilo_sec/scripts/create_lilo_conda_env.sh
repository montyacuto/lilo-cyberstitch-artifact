#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
CONDA_SOLVER="${LILO_CONDA_SOLVER:-libmamba}"
export CONDA_PKGS_DIRS="${CONDA_PKGS_DIRS:-$PWD/.conda/pkgs}"
export PIP_CACHE_DIR="${PIP_CACHE_DIR:-$PWD/.cache/pip}"

mkdir -p "$CONDA_PKGS_DIRS" "$PIP_CACHE_DIR"

if ! command -v conda >/dev/null 2>&1; then
  echo "conda is required to create the LILO reproduction environment." >&2
  exit 1
fi

if [ -x "$ENV_PREFIX/bin/python" ]; then
  echo "Using existing conda environment at: $ENV_PREFIX"
else
  echo "Creating base LILO conda environment at: $ENV_PREFIX"
  conda create -y -p "$ENV_PREFIX" \
    --solver "$CONDA_SOLVER" \
    --strict-channel-priority \
    --override-channels \
    -c conda-forge \
    python=3.7 "pip<24" setuptools wheel \
    numpy pandas scipy scikit-learn \
    pytest python-dateutil typing-extensions \
    cffi dill frozendict multiprocess pathos \
    regex tqdm requests packaging pyyaml psutil
fi

echo "Installing native library dependencies"
conda install -y -p "$ENV_PREFIX" \
  --solver "$CONDA_SOLVER" \
  --strict-channel-priority \
  --override-channels \
  -c conda-forge \
  cairo pycairo zeromq pkg-config graphviz

if [ "${LILO_INSTALL_JUPYTER:-0}" = "1" ]; then
  echo "Installing optional JupyterLab dependency"
  conda install -y -p "$ENV_PREFIX" \
    --solver "$CONDA_SOLVER" \
    --strict-channel-priority \
    --override-channels \
    -c conda-forge \
    jupyterlab
else
  echo "Skipping optional JupyterLab install; set LILO_INSTALL_JUPYTER=1 to include it."
fi

echo "Installing pinned PyTorch CPU stack"
conda install -y -p "$ENV_PREFIX" \
  --solver "$CONDA_SOLVER" \
  --strict-channel-priority \
  --override-channels \
  -c pytorch -c conda-forge \
  pytorch=1.9.1 cpuonly "mkl<2023"

echo "Installing pip-only LILO dependencies"
"$ENV_PREFIX/bin/python" -m pip install \
  "matplotlib==3.5.3" \
  "seaborn==0.12.2" \
  "Pillow==9.5.0" \
  "imageio==2.31.2" \
  "cairocffi==1.6.1" \
  "Pygments==2.17.2" \
  "toml==0.10.2" \
  "black==21.7b0" \
  "pre-commit==2.15.0" \
  "nltk==3.8.1" \
  "num2words==0.5.13" \
  "sexpdata==1.0.2" \
  "openai==0.28.1" \
  "transformers==4.12.5" \
  "tokenizers==0.10.3" \
  "huggingface-hub<0.17" \
  "mypy-extensions==0.4.3" \
  "phx-class-registry==3.0.5" \
  "pytorch-nlp==0.5.0" \
  "stitch_core==0.1.25"

"$ENV_PREFIX/bin/python" -m pip install "pregex==1.0.0" --ignore-requires-python

echo "Environment ready: $ENV_PREFIX"
echo "Activate with: conda activate $ENV_PREFIX"

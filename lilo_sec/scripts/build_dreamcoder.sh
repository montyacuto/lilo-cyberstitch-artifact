#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_PREFIX="${LILO_CONDA_ENV_PREFIX:-$PWD/.conda/envs/lilo}"
OPAM_ROOT="${LILO_OPAMROOT:-$PWD/.opam}"

if [ ! -x "$ENV_PREFIX/bin/python" ]; then
  echo "LILO conda environment not found at: $ENV_PREFIX" >&2
  echo "Run scripts/create_lilo_conda_env.sh first." >&2
  exit 1
fi

if ! command -v opam >/dev/null 2>&1; then
  echo "opam is required to build DreamCoder." >&2
  exit 1
fi

git -c url.https://github.com/.insteadOf=git@github.com: submodule update --init dreamcoder

export PATH="/usr/bin:/usr/local/bin:$ENV_PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$ENV_PREFIX/lib:${LD_LIBRARY_PATH:-}"
export PKG_CONFIG_PATH="$ENV_PREFIX/lib/pkgconfig:$ENV_PREFIX/share/pkgconfig:${PKG_CONFIG_PATH:-}"
export PKG_CONFIG="${LILO_PKG_CONFIG:-/usr/bin/pkg-config}"
export OPAMROOT="$OPAM_ROOT"

mkdir -p "$OPAMROOT"

if [ ! -f "$ENV_PREFIX/lib/pkgconfig/expat.pc" ]; then
  echo "Writing expat.pc shim for conda libexpat"
  mkdir -p "$ENV_PREFIX/lib/pkgconfig"
  {
    printf 'prefix=%s\n' "$ENV_PREFIX"
    printf 'exec_prefix=${prefix}\n'
    printf 'libdir=${exec_prefix}/lib\n'
    printf 'includedir=${prefix}/include\n'
    printf '\n'
    printf 'Name: expat\n'
    printf 'Description: XML parser library\n'
    printf 'Version: 2.8.0\n'
    printf 'Libs: -L${libdir} -lexpat\n'
    printf 'Cflags: -I${includedir}\n'
  } >"$ENV_PREFIX/lib/pkgconfig/expat.pc"
fi

if ! "$PKG_CONFIG" --cflags cairo >/dev/null; then
  echo "pkg-config cannot resolve cairo with the conda native library path." >&2
  echo "Fedora host package command for review: sudo dnf install -y cairo-devel zeromq-devel pkgconf-pkg-config" >&2
  exit 2
fi

if [ ! -f "$OPAMROOT/config" ]; then
  echo "Initializing repo-local opam root at: $OPAMROOT"
  opam init --bare --disable-sandboxing --yes --no-setup
fi

echo "Installing DreamCoder OCaml dependencies"
(
  cd dreamcoder/solvers
  if [ -d _opam ]; then
    echo "Using existing local opam switch at: $PWD/_opam"
  else
    opam switch create --deps-only --yes --assume-depexts .
  fi
)

echo "Building DreamCoder OCaml binaries"
(
  cd dreamcoder/solvers
  eval "$(opam env --switch "$PWD")"
  dune build @install --profile=release
  dune install --sections bin --bindir="$PWD/.."
)

ln -fs ../../logoDrawString dreamcoder/data/geom/logoDrawString

echo "DreamCoder binaries built in: $PWD/dreamcoder"

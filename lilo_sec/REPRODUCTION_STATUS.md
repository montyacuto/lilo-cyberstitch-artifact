# LILO Reproduction Status

Last checked: 2026-05-05.

## Completed

- Initialized the pinned DreamCoder submodule at `e5e02131d77f8682ea5ea0c224be0631601b5c09`.
- Pinned the legacy OpenAI SDK in `environment.yml` to avoid silently installing the incompatible `openai>=1` API.
- Added `src/openai_compat.py` so cached/debug runs can import without a live OpenAI key and live calls can handle both legacy and newer SDK response shapes.
- Added `scripts/check_lilo_environment.py` for repeatable environment diagnostics.
- Added `scripts/setup_lilo_reproduction.sh` as a one-command setup path with an unlocked opam fallback.

## Remaining Blockers

- The active shell is Python 3.14, not the required Python 3.7 conda environment.
- `conda env create -f environment.yml --solver libmamba` still spends several minutes in dependency solving and was stopped manually.
- Fedora native development packages are missing:

```bash
sudo dnf install -y cairo-devel zeromq-devel pkgconf-pkg-config
```

- The DreamCoder locked opam solve fails because the current opam repository no longer contains `cmdliner=1.1.1`. The setup script retries with the unlocked `dune-project` dependencies, but that path also requires the native packages above.
- Docker is installed but not usable by this user because the Docker socket is not accessible.
- CodeQL CLI and AWS CLI are not installed.

## Next Setup Commands

After installing the Fedora native packages, run:

```bash
cd <original-workspace>/lilo_sec
./scripts/setup_lilo_reproduction.sh
```

If conda solving continues to stall, use the upstream Docker image after fixing Docker permissions:

```bash
docker pull gabegrand/lilo
```

Then rerun:

```bash
python scripts/check_lilo_environment.py
```

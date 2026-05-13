# LILO Conda Pinning Artifacts

Generated: 2026-05-05. Regenerated after pinning `stitch_core==0.1.25`.

These files pin the working local LILO Python 3.7 environment at `lilo_sec/.conda/envs/lilo`.

- `lilo-conda-linux-64-explicit.txt`: exact Linux conda package URLs with SHA256 hashes. This is the primary solver-free conda replay artifact for the conda-managed packages.
- `lilo-conda-environment-full.yml`: full conda environment export, including pip-installed packages. This is useful for audit and fallback recreation; the original absolute prefix has been removed for portability.
- `lilo-conda-list.txt`: human-readable conda package table with channels.
- `lilo-pip-only-requirements.txt`: pip packages installed from PyPI, derived from `conda list` entries whose channel is `pypi`.
- `lilo-pip-freeze.txt`: full `pip freeze --all` evidence. Do not use this as the first replay input because it includes distributions provided by conda, such as `torch`.

Recommended replay shape for the Python runtime:

```bash
conda create -p /path/to/lilo-env --file env/locks/lilo-conda-linux-64-explicit.txt
/path/to/lilo-env/bin/python -m pip install -r env/locks/lilo-pip-only-requirements.txt
```

Then run the repo setup scripts for DreamCoder/opam as needed.

LiteLLM proxy locks were added for the separate Python 3.11 environment at `lilo_sec/.conda/envs/litellm`:

- `litellm-conda-linux-64-explicit.txt`: exact conda replay artifact for the proxy environment.
- `litellm-conda-list.txt`: human-readable conda/pip package table.
- `litellm-pip-freeze.txt`: full pip freeze for the proxy environment.

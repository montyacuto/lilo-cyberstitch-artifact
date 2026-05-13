# LILO and CyberSTITCH Reproduction Artifact

This artifact package provides commands for verifying the package, preparing
local runtimes, running bounded checks, and finding packaged evidence. For study
design, results, model-substitution policy, and limitations, see the companion
paper.

By default, the package does not launch long live runs. The default commands can
verify package contents immediately after extraction; environment-dependent
commands check prepared LILO/CyberSTITCH runtimes, run bounded smoke tests, and
print exact commands for long or live reproductions.

The extracted package is about 3.5 GB. Full reruns require substantially more
disk for generated outputs, CodeQL databases, Maven caches, and optional
BenchmarkJava checkouts, which are not included in this package.

## Quick Start

From the package root:

```bash
./artifact --help
./artifact package-verify
./artifact package-smoke
./artifact tasks
./artifact menu
```

Use `./artifact package-verify` first. It checks that included files, results,
caches, and notes are present without requiring the full LILO runtime or live
API access.

Use `./artifact package-smoke` for the same package-only boundary check under a
smoke-test name. It is the command that should work immediately after
extraction, before conda, CodeQL, BenchmarkJava, or API setup.

Use `./artifact verify` only after the LILO and CyberSTITCH environments are
available. It runs:

- LILO environment/readiness verification;
- CyberSTITCH doctor checks;
- combined package input verification.

Use `./artifact menu` for the combined interactive TUI, or `./artifact tasks`
to list every registered task without opening the menu.

## Package Layout

```text
artifact              one-command package runner
run_artifact.sh       alternate entrypoint to the package runner
lilo                  compatibility wrapper for the TUI
lilo_sec/             LILO source with reproduction patches, data, templates, outputs
cyberstitch_poc/      CyberSTITCH source, fixtures, query profiles, results
env/                  dependency lock records
results/lilo/         LILO run logs, monitor evidence, caches
package_stage/        package verification manifest
```

Local development notes are not included in the public package. LILO logs,
monitor evidence, and replay caches are staged under `results/lilo/`.

## Environment Prerequisites

The artifact uses separate runtimes for LILO and CyberSTITCH.

LILO requires:

- Linux or a compatible Unix-like environment;
- conda or miniconda;
- Python 3.7 from the LILO conda environment, not a system/python.org install;
- bundled DreamCoder Linux solver binaries, or the toolchain needed to rebuild
  them;
- `stitch_core==0.1.25`;
- a separate modern LiteLLM environment for live/replay proxy work.

Rebuilding the DreamCoder/OCaml solver binaries additionally requires
OCaml/opam, Rust/Cargo, Cairo/ZeroMQ/Expat development metadata, `pkg-config`,
and `unzip` for the opam binary installer path used by the OCaml setup docs.

CyberSTITCH requires:

- Python `>=3.11`;
- conda or miniconda is recommended for the CyberSTITCH Python environment;
- Python packaging tools for editable install; `setuptools>=68` is the declared
  build backend;
- JDK with `java` on `PATH`;
- Maven with `mvn` on `PATH` for real BenchmarkJava runs;
- CodeQL CLI with `codeql` on `PATH`, or `CYBERSTITCH_CODEQL` set;
- optional OWASP BenchmarkJava checkout for full live CodeQL database runs.

Tool versions used for the packaged runs:

```text
CodeQL command-line toolchain release 2.25.3
Apache Maven 3.9.11
OpenJDK 25.0.3
```

The package includes lock files under `env/locks/`, but excludes local conda,
opam, Maven, CodeQL cache, and other build-cache directories.

Native packages used for the LILO/DreamCoder build include Cairo, ZeroMQ,
Expat, `pkg-config`, and `unzip` for the opam installer. On Fedora-family
systems:

```bash
sudo dnf install -y cairo-devel zeromq-devel expat-devel pkgconf-pkg-config unzip
```

On Debian/Ubuntu-family systems, the corresponding packages are typically:

```bash
sudo apt-get install -y libcairo2-dev libzmq3-dev libexpat1-dev pkg-config unzip
```

## Pinned Dependencies And Models

Exact package evidence is under `env/locks/`.

Primary LILO runtime pins:

- Python `3.7`;
- OpenAI Python SDK `0.28.1`;
- `pip<24`;
- `transformers==4.12.5`;
- `tokenizers==0.10.3`;
- `stitch_core==0.1.25`;
- DreamCoder submodule/source snapshot
  `e5e02131d77f8682ea5ea0c224be0631601b5c09`.

Primary LiteLLM proxy pins:

- Python `3.11.15`;
- `litellm==1.83.14`;
- `litellm-proxy-extras==0.4.69`;
- OpenAI Python SDK `2.24.0`.

Model policy for live LILO reruns:

- LiteLLM keeps LILO-facing paper-era aliases such as `code-davinci-002`,
  `gpt-3.5-turbo`, and `gpt-3.5-turbo-0301`.
- Those aliases route to the pinned provider snapshot
  `openai/gpt-3.5-turbo-0125`.
- The direct original-completion path uses `gpt-3.5-turbo-instruct`. OpenAI
  does not expose a more granular dated snapshot for that model.
- Cached/replay outputs are the primary reproducibility path; live API
  availability for deprecated GPT-3.5-era models can change.

CyberSTITCH runtime pins:

- Python `>=3.11`;
- no third-party Python runtime dependencies in `cyberstitch_poc/pyproject.toml`;
- build backend `setuptools>=68` for editable installs;
- observed packaged-run toolchain: CodeQL `2.25.3`, Maven `3.9.11`,
  OpenJDK `25.0.3`.

## OpenAI API Key Safety

Unlike some other paper artifacts I have seen (including those published at 
security venues), this README will not ask
you to hard-code your OpenAI API key into the source code. Set the key in the
current shell, or preferably keep it outside the repository in an encrypted or
permission-restricted `openai.env` file such as `~/.config/lilo/openai.env`.

For a temporary shell-only key, either export it directly:

```bash
export OPENAI_API_KEY="YOUR_OPENAI_API_KEY"
```

or avoid putting the key in shell history by entering it at a silent prompt:

```bash
read -r -s OPENAI_API_KEY
export OPENAI_API_KEY
```

For a reusable local key file:

```bash
mkdir -p ~/.config/lilo
umask 077
cat > ~/.config/lilo/openai.env <<'EOF'
export OPENAI_API_KEY="YOUR_OPENAI_API_KEY"
EOF
chmod 600 ~/.config/lilo/openai.env
```

Load the key before running live LILO or CyberSTITCH tasks:

```bash
source ~/.config/lilo/openai.env
```

For LILO live reruns, load the key before starting the LiteLLM proxy. The proxy
uses the real OpenAI key, while LILO itself talks to the local proxy through the
local master key:

```bash
source ~/.config/lilo/openai.env
export LITELLM_OPENAI_API_KEY="$OPENAI_API_KEY"
export LITELLM_MASTER_KEY=local-litellm-key
```

Then, in the shell that launches LILO:

```bash
export LILO_OPENAI_API_BASE=http://127.0.0.1:4000/v1
export OPENAI_API_KEY="$LITELLM_MASTER_KEY"
source scripts/env_litellm_initial_lilo.sh
```

For CyberSTITCH live runs, load the real key and then use the explicit live-run
confirmation guard:

```bash
source ~/.config/lilo/openai.env
ARTIFACT_CONFIRM_LIVE_API=YES ./artifact reproduce --suite cyberstitch --mode live --profile official-expanded-pack
```

Do not commit API keys, place them in files under this repository, or paste them
into packaged configuration files. Please.

## Setting Up LILO

The original LILO README is at `lilo_sec/README.md`. This reproduction keeps
Python 3.7 because DreamCoder/LILO are not modern-Python compatible. Python 3.7
is supplied by the conda environment created from `env/locks/`. Use the conda
environment rather than a system/python.org Python 3.7 build; system builds may
lack required standard-library extension modules such as `_ssl`, `_sqlite3`,
`_bz2`, and `_lzma`.

The package includes DreamCoder source plus built Linux solver binaries under
`lilo_sec/dreamcoder`, `lilo_sec/ocaml/bin`, and `lilo_sec/ocaml/linux_bin`.
Normal package verification checks that those files are present; it does not
rebuild them. To rebuild the DreamCoder/OCaml side after preparing conda and
opam, run:

```bash
cd lilo_sec
scripts/build_dreamcoder.sh
scripts/artifact.sh verify-env --require-build-deps
```

Recommended setup from exact package locks:

```bash
cd lilo_sec
conda create -p .conda/envs/lilo --file ../env/locks/lilo-conda-linux-64-explicit.txt
.conda/envs/lilo/bin/python -m pip install --ignore-requires-python \
  -r ../env/locks/lilo-pip-only-requirements.txt
scripts/artifact.sh verify-env
scripts/artifact.sh smoke
```

The `--ignore-requires-python` flag is required because `pregex==1.0.0` is part
of the reproduced LILO environment but declares newer Python metadata than the
Python 3.7 runtime used by LILO.

Alternative setup path:

```bash
cd lilo_sec
conda env create -p .conda/envs/lilo -f environment.yml
scripts/artifact.sh verify-env
```

The LiteLLM proxy uses a separate modern environment. Load `OPENAI_API_KEY` as
described in "OpenAI API Key Safety", then run the proxy with the packaged model
policy:

```bash
cd lilo_sec
conda create -p .conda/envs/litellm python=3.11.15
.conda/envs/litellm/bin/python -m pip install \
  litellm==1.83.14 litellm-proxy-extras==0.4.69 openai==2.24.0
export LITELLM_OPENAI_API_KEY="$OPENAI_API_KEY"
export LITELLM_MASTER_KEY=local-litellm-key
.conda/envs/litellm/bin/litellm --config litellm_config.initial_lilo.yaml --port 4000
```

Then point LILO at the proxy in the shell that launches LILO:

```bash
export LILO_OPENAI_API_BASE=http://127.0.0.1:4000/v1
export OPENAI_API_KEY="$LITELLM_MASTER_KEY"
source scripts/env_litellm_initial_lilo.sh
```

## Setting Up CyberSTITCH

CyberSTITCH uses a separate runtime from the LILO Python 3.7 environment.

Recommended conda setup from the package root:

```bash
cd cyberstitch_poc
conda create -y -p .conda/envs/cyberstitch \
  --strict-channel-priority --override-channels \
  -c conda-forge python=3.11 pip "setuptools>=68"
.conda/envs/cyberstitch/bin/python -m pip install -e . --no-build-isolation
.conda/envs/cyberstitch/bin/python -m cyberstitch.cli doctor
```

The package has no third-party CyberSTITCH runtime Python dependencies; conda
is used here to pin the interpreter and build backend. A venv also works if it
has Python `>=3.11` and `setuptools>=68`.

If using the top-level runner with a non-default Python:

```bash
CYBERSTITCH_PYTHON=$PWD/cyberstitch_poc/.conda/envs/cyberstitch/bin/python ./artifact run-task cyberstitch-doctor
```

For full BenchmarkJava CodeQL runs, provide an external OWASP BenchmarkJava
checkout. The packaged runs used commit:

```text
b06d6efaebd577a327514364951916e7df3290b4
```

Set:

```bash
export CYBERSTITCH_OWASP_ROOT=/absolute/path/to/BenchmarkJava
export CYBERSTITCH_CODEQL=/absolute/path/to/codeql
```

The package excludes `cyberstitch_poc/benchmarks/BenchmarkJava`, CodeQL
databases, CodeQL caches, and Maven cache by default.

## Common Commands

List registered tasks:

```bash
./artifact tasks
./artifact tasks --section lilo
./artifact tasks --section cyberstitch
./artifact tasks --section package
```

Run package-only verification:

```bash
./artifact package-verify
```

Expected output:

```text
Inputs checked: 68
Missing required: 0
Excluded children present: 0
```

Run package-only smoke immediately after extraction:

```bash
./artifact package-smoke
```

This performs the same package boundary check under a smoke-test command name.
It should take seconds and does not require conda, CodeQL, BenchmarkJava,
CyberSTITCH installation, or API access.

Run the combined readiness check after environments are prepared:

```bash
./artifact verify
```

Expected result: LILO environment verification, CyberSTITCH doctor checks, and
package verification all exit with status `0`. This requires the LILO conda
environment and a usable CyberSTITCH Python environment.

Run bounded offline smokes after environments are prepared:

```bash
./artifact smoke
```

Expected result: LILO offline smoke and CyberSTITCH offline CodeQL extension
smoke both exit with status `0`. This does not make live API calls, but it does
require the prepared LILO and CyberSTITCH environments and local CodeQL tooling.

Print package and report pointers:

```bash
./artifact report
```

Run one task by id:

```bash
./artifact run-task cyberstitch-doctor
./artifact run-task package-verify-all
```

`cyberstitch-doctor` should exit with status `0` and report the detected
CyberSTITCH configuration. If `python3` is not the prepared CyberSTITCH
environment, set `CYBERSTITCH_PYTHON` as shown above.

Print a long/live command without running it:

```bash
./artifact run-task cyberstitch-live-official-expanded-pack --print-command
```

## Verification Levels

| Command | Works immediately after extraction | Requires prepared environments | Requires external BenchmarkJava | Requires live API |
| --- | --- | --- | --- | --- |
| `./artifact package-smoke` | yes | no | no | no |
| `./artifact package-verify` | yes | no | no | no |
| `./artifact verify` | no | LILO conda and CyberSTITCH Python | no | no |
| `./artifact smoke` | no | LILO conda, CyberSTITCH Python, local CodeQL tooling | no | no |
| `./artifact reproduce --suite cyberstitch --mode replay` | no | CyberSTITCH Python, CodeQL/Maven/JDK | yes for full BenchmarkJava profiles | no |
| `./artifact reproduce --suite cyberstitch --mode live` | no | CyberSTITCH Python, CodeQL/Maven/JDK | yes for full BenchmarkJava profiles | yes |

Useful targeted checks:

| Claim | Verification command | Expected output |
| --- | --- | --- |
| Package boundary is intact | `./artifact package-smoke` | `Missing required: 0`; `Excluded children present: 0` |
| LILO runtime can be reconstructed | `cd lilo_sec && scripts/artifact.sh verify-env` | exits `0`; no runtime blockers |
| Selected LILO results and caches are present | `./artifact package-verify --scope lilo` | `Missing required: 0` |
| CyberSTITCH Python package is runnable | `CYBERSTITCH_PYTHON=$PWD/cyberstitch_poc/.conda/envs/cyberstitch/bin/python ./artifact run-task cyberstitch-doctor` | doctor exits `0` |
| Selected CyberSTITCH results and LILO caches are present | `./artifact package-verify --scope cyberstitch` | `Missing required: 0` |
| Live CyberSTITCH rerun command is guarded | `./artifact run-task cyberstitch-live-official-expanded-pack --print-command` | prints command only |

Live API tasks require `OPENAI_API_KEY`; see "OpenAI API Key Safety" for safe
setup options. Then confirm deliberately:

```bash
ARTIFACT_CONFIRM_LIVE_API=YES ./artifact reproduce --suite cyberstitch --mode live --profile official-expanded-pack
```

For LILO-specific live runs, `LILO_CONFIRM_LIVE_LLM=YES` is also accepted. For
CyberSTITCH live LILO-loop runs, `CYBERSTITCH_CONFIRM_LIVE_LILO=YES` is also
accepted.

## Packaged Evidence

The package includes evidence needed to inspect or replay the included runs.

Primary LILO contents:

- batch-32 full seed-111 three-domain battery;
- batch-96 full REGEX `gpt-3.5-turbo-instruct` run;
- longest increased-cap partial diagnostic run, which is LOGO 4 GB, not CLEVR;
- run logs, monitor evidence, and replay/cache notes under `results/lilo/`;
- included outputs under `lilo_sec/experiments_iterative/outputs/`.

Primary CyberSTITCH contents:

- deterministic combined, companion/official-expanded, and bounded profiles;
- fixture-backed LILO-loop evidence;
- live API partitioned record runs;
- live LILO caches under `cyberstitch_poc/results/lilo-llm-cache/`;
- per-run summaries, reports, command logs, and environment records under
  `cyberstitch_poc/results/`.

For the full list of included paths and expected package boundaries, see
`package_stage/package_verify.md`.

## License, Citation, And Provenance

- LILO source and its archival citation are retained in `lilo_sec/README.md`.
  That README includes the upstream MIT license text and citation block.
- DreamCoder source and the OCaml solver binaries are bundled as part of the
  LILO reproduction tree. The package preserves the source snapshot and built
  Linux binaries used for these runs; it does not include local opam build
  caches.
- CyberSTITCH source is included under `cyberstitch_poc/`. Check the project
  license and notice requirements before redistributing CyberSTITCH separately.
- CodeQL CLI binaries, CodeQL databases, Maven caches, and the OWASP
  BenchmarkJava source checkout are not bundled. The package includes
  CyberSTITCH query source, BenchmarkJava manifests, derived result artifacts,
  and the BenchmarkJava commit identifier needed to reconstruct full runs.

## Exclusions

The package excludes:

- API secrets and shell histories;
- `.git` directories/files;
- Python bytecode and `__pycache__`;
- conda, opam, pytest, mypy, ruff, and local cache directories;
- DreamCoder OCaml `_opam` and `_build` directories;
- CodeQL databases and CodeQL caches;
- Maven repository cache;
- OWASP BenchmarkJava source checkout;
- generated CodeQL database bundles and archives;
- unsuccessful or superseded live API attempts;
- optional calibration/probe outputs outside this release.

The package verifier checks these boundaries:

```bash
./artifact package-verify
```

The staged package was last verified with:

```text
Inputs checked: 68
Missing required: 0
Excluded children present: 0
```

## Known Deviations And Caveats

See the companion paper for the full limitations and threats-to-validity
discussion. Key artifact caveats:

- LILO is preserved through conda on Python 3.7 rather than modernized.
- Live LLM reruns use accessible GPT-3.5-era replacements, not retired
  `code-davinci-002`.
- Full BenchmarkJava reruns require an external BenchmarkJava checkout and
  CodeQL/Maven/JDK tooling.
- CodeQL databases and Maven cache are excluded by default.
- The batch-32 replay cache is included; the batch-96 direct completion run
  does not have the same request-hash replay cache.
- LOGO batch-96 original-completion runs can hit OCaml solver virtual-memory
  limits.

## Troubleshooting

- `./artifact smoke` fails before LILO starts: run `./artifact package-smoke`
  first to verify extraction, then build the LILO conda environment from
  `env/locks/`.
- LILO reports a missing conda environment: create
  `lilo_sec/.conda/envs/lilo` with the locked conda and pip commands in
  "Setting Up LILO".
- Python 3.7 is difficult to find as a system install: use the conda lock
  files. They install conda-forge `python-3.7.12` with the required standard
  library extension modules.
- DreamCoder/OCaml rebuild checks fail: install the
  Cairo/ZeroMQ/Expat/`pkg-config` native packages and `unzip`, then run
  `cd lilo_sec && scripts/build_dreamcoder.sh`.
- `cyberstitch-doctor` imports fail: install CyberSTITCH with the conda setup
  above and set `CYBERSTITCH_PYTHON` if the prepared Python is not `python3`.
- CodeQL checks fail: put `codeql` on `PATH` or set `CYBERSTITCH_CODEQL` to the
  CodeQL executable.
- Full BenchmarkJava reruns fail at corpus setup: set
  `CYBERSTITCH_OWASP_ROOT` to an external BenchmarkJava checkout at the commit
  listed above.
- Live API tasks fail before launch: set `OPENAI_API_KEY` or
  `~/.config/lilo/openai.env`, and confirm with
  `ARTIFACT_CONFIRM_LIVE_API=YES`.
- LOGO batch-96 original-completion runs can hit OCaml solver virtual-memory
  limits. Increasing the virtual address cap reduces OOM frequency but allows
  larger solver processes and can make runaway searches consume more memory
  before failing.

## Further Documentation

Detailed subsystem documentation:

```text
lilo_sec/README.md
cyberstitch_poc/README.md
env/locks/README.md
package_stage/package_verify.md
```

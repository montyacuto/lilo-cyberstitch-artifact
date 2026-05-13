# CyberSTITCH PoC

This is a small, validation-first scaffold for the CyberSTITCH LILO-extension
prototype packaged with this artifact.

The default offline pipeline intentionally avoids depending on the legacy LILO
Python 3.7 environment. It can run with the standard library:

```bash
python -m cyberstitch.cli --help
python -m cyberstitch.cli doctor
python -m cyberstitch.cli manifest
python -m cyberstitch.cli sqir
python -m cyberstitch.cli roundtrip
python -m cyberstitch.cli fcir
python -m cyberstitch.cli codeql-pack-fcir --pack-root ../codeql
python -m cyberstitch.cli stitch --mode offline
python -m cyberstitch.cli semantic-mine --merge
# optional schema-only LILO LLM proposals:
# python -m cyberstitch.cli llm-propose --fixture fixtures/llm_proposals.json --merge
python -m cyberstitch.cli validate
python -m cyberstitch.cli rewrite
python -m cyberstitch.cli codeql-check
python -m cyberstitch.cli report
```

The Java/OWASP milestone is manifest-driven. The checked-in curated manifest is
`benchmarks/owasp_curated_subset.json`; it targets CWE-78 command injection and
CWE-89 SQL injection and defaults to a tiny OWASP-shaped fixture under
`benchmarks/owasp-fixture`. For a live Benchmark checkout, set:

```bash
CYBERSTITCH_OWASP_ROOT=/path/to/BenchmarkJava \
CYBERSTITCH_CODEQL=/path/to/codeql \
python -m cyberstitch.cli db-create
```

Live CodeQL stages:

```bash
python -m cyberstitch.cli analyze --queries original
python -m cyberstitch.cli score --sarif results/sarif/original.sarif
python -m cyberstitch.cli analyze --queries roundtrip
python -m cyberstitch.cli analyze --queries rewritten
python -m cyberstitch.cli compare results/sarif/original.sarif results/sarif/rewritten.sarif
```

`fcir` writes `results/fcir/programs.json` as the STITCH `programs-list` input
and `results/fcir/provenance.json` as the SQIR/CodeQL mapping sidecar.
`codeql-pack-fcir` emits the same pair for the supported official Java
`codeql/java-queries` CWE-78/CWE-89 query and library shapes.
`semantic-mine` reads SQIR/FCIR provenance, and optionally the CodeQL pack FCIR
sidecar, to emit deterministic concept-backed candidates that distinguish
meaningful CodeQL source/sink/barrier/helper abstractions from syntax
compression.

For live STITCH compression inside this LILO reproduction workspace, the
preferred backend is the `stitch_core` Python binding already installed in the
LILO conda environment:

```bash
python -m cyberstitch.cli stitch --mode live
python -m cyberstitch.cli stitch --mode live --stitch-python ../lilo_sec/.conda/envs/lilo/bin/python
```

`--stitch-python` may also be provided through
`CYBERSTITCH_STITCH_PYTHON`. When no direct `--stitch-binary` is supplied,
CyberSTITCH auto-detects `../lilo_sec/.conda/envs/lilo/bin/python` and invokes
`stitch_core.compress(...)` through a subprocess bridge. Direct `stitch` or
`compress` binaries remain supported as a fallback for a later standalone
CyberSTITCH environment.

`codeql-check` is the syntactic gate for generated helpers and rewritten
queries. It runs `codeql query compile --check-only` per provisionally accepted
candidate and again on the final rewritten query pack. Semantic validation alone
does not make a candidate acceptable for live CodeQL experiments.

`llm-propose` is optional and constrained: it asks the LILO LLM bridge for JSON
schema/name/rationale proposals over existing FCIR semantic node ids. The LLM
does not supply authoritative CodeQL; proposals must still pass semantic
validation, `codeql-check`, and live SARIF equivalence.

`autodoc-eval` evaluates whether LILO/AutoDoc-style names and docstrings help an
LLM use the validated CodeQL helpers. It compares fixed presentations of the
same accepted abstraction inventory, scores structured LLM outputs with
deterministic validators, and never changes CodeQL query semantics:

```bash
python -m cyberstitch.cli autodoc-eval --mode fixture --samples 1
python -m cyberstitch.cli autodoc-eval --mode live --model gpt-3.5-turbo
python -m cyberstitch.cli autodoc-eval --mode replay --model gpt-3.5-turbo
```

Live and replay modes use the existing LILO `openai_compat` cache controls:
`LILO_LLM_CACHE_MODE=record|replay` and `LILO_LLM_CACHE_DIR=...`.

`doctor`, `db-create`, and `analyze` fail clearly when CodeQL is absent or not
configured. CodeQL is expected to be installed user-locally, not through
superuser package management.

For the live curated BenchmarkJava experiment, use the runner:

```bash
scripts/run_curated_benchmarkjava_experiment.sh
```

The runner defaults to `--bundle none`. CodeQL database bundles contain analyzed
source code and are restricted troubleshooting artifacts. Create one only when
needed:

```bash
scripts/run_curated_benchmarkjava_experiment.sh --bundle debug
scripts/run_curated_benchmarkjava_experiment.sh --bundle minimal
scripts/run_curated_benchmarkjava_experiment.sh --stitch-mode live
scripts/run_curated_benchmarkjava_experiment.sh --stitch-mode live --stitch-python ../lilo_sec/.conda/envs/lilo/bin/python
```

From the LILO artifact wrapper, the prepared-workspace one-command path is:

```bash
cd ../lilo_sec
scripts/artifact.sh codeql-curated-experiment
```

Each run writes `commands.log`, `environment.txt`, `summary.json`,
`summary.md`, `compare/*.json`, `bundle-policy.json`, and `report.md` under the
result directory.

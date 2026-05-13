# Artifact Package Manifest

Created: `2026-05-12T23:18:16`
Scope: `all`
Project root: `<artifact-root>`

## Inputs
- ok `README.md` (all) - Combined artifact README.
- ok `LICENSE.txt` (all) - Top-level artifact license.
- ok `run_artifact.sh` (all) - Root artifact runner source.
- ok `artifact` (all) - Packaged one-command artifact runner.
- ok `lilo` (all) - Compatibility wrapper for the combined artifact menu.
- ok `package_stage` (all) - Package verification and staging manifests.
- ok `env/locks` (lilo) - Pinned dependency lock records.
- ok `results/lilo/run_logs/artifact_demo_lilo_seed111_init` (lilo) - Paper-faithful seed-111 init command logs.
- ok `results/lilo/run_logs/artifact_demo_lilo_seed111_batch32_full_battery` (lilo) - Batch-32 full battery command logs.
- ok `results/lilo/run_logs/artifact_demo_lilo_logo_seed111_batch96_instruct_4gb_partial` (lilo) - Longest increased-cap LOGO partial run logs.
- ok `results/lilo/run_logs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment1/run.log` (lilo) - Batch-96 REGEX first segment embedded run log.
- ok `results/lilo/run_logs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment2/run.log` (lilo) - Batch-96 REGEX continuation embedded run log.
- ok `results/lilo/monitors/artifact_demo_lilo_seed111_init` (lilo) - Init monitor evidence.
- ok `results/lilo/monitors/artifact_demo_lilo_seed111_batch32_full_battery` (lilo) - Full battery monitor evidence.
- ok `results/lilo/llm_caches/artifact_demo_lilo_seed111_batch32_replay_cache` (lilo) - Primary batch-32 replay cache.
- ok `results/lilo/llm_caches/batch96_regex_cache_note.md` (lilo) - Batch-96 REGEX cache status note.
- ok `lilo_sec/README.md` (lilo) - LILO source README.
- ok `lilo_sec/REPRODUCTION_STATUS.md` (lilo) - LILO reproduction status note.
- ok `lilo_sec/environment.yml` (lilo) - Pinned conda environment seed file.
- ok `lilo_sec/laps_requirements.txt` (lilo) - Legacy Python requirements record.
- ok `lilo_sec/.gitignore` (lilo) - LILO repository ignore rules.
- ok `lilo_sec/.gitmodules` (lilo) - LILO submodule metadata.
- ok `lilo_sec/Dockerfile` (lilo) - Original Docker reference environment.
- ok `lilo_sec/litellm_config.example.yaml` (lilo) - LiteLLM example configuration.
- ok `lilo_sec/litellm_config.gpt35.yaml` (lilo) - LiteLLM GPT-3.5 compatibility configuration.
- ok `lilo_sec/litellm_config.initial_lilo.yaml` (lilo) - LiteLLM initial LILO compatibility configuration.
- ok `lilo_sec/run_experiment.py` (lilo) - LILO experiment entrypoint.
- ok `lilo_sec/run_iterative_experiment.py` (lilo) - Iterative LILO experiment entrypoint.
- ok `lilo_sec/precompute_embeddings.py` (lilo) - Embedding precomputation helper.
- ok `lilo_sec/run_library_evaluation.py` (lilo) - Library evaluation helper.
- ok `lilo_sec/evaluate_compression_model_scoring.py` (lilo) - Compression-model scoring helper.
- ok `lilo_sec/scripts` (lilo) - Artifact runner and LILO helper scripts.
- ok `lilo_sec/src` (lilo) - LILO reproduction source modifications.
- ok `lilo_sec/data` (lilo) - LILO benchmark task data and embeddings.
- ok `lilo_sec/dreamcoder` (lilo) - Bundled DreamCoder source and binaries.
- ok `lilo_sec/ocaml` (lilo) - OCaml solver source and binaries.
- ok `lilo_sec/experiments` (lilo) - Original experiment definitions.
- ok `lilo_sec/experiments_iterative/templates` (lilo) - LILO iterative experiment templates.
- ok `lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_seed111_init` (lilo) - Paper-faithful init output.
- ok `lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_seed111_batch32_full_battery` (lilo) - Batch-32 full battery output.
- ok `lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment1` (lilo) - Batch-96 REGEX first segment output.
- ok `lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment2` (lilo) - Batch-96 REGEX continuation output.
- ok `lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_logo_seed111_batch96_instruct_4gb_partial` (lilo) - Longest increased-cap LOGO partial output.
- ok `cyberstitch_poc/README.md` (cyberstitch) - CyberSTITCH README.
- ok `cyberstitch_poc/Makefile` (cyberstitch) - CyberSTITCH developer commands.
- ok `cyberstitch_poc/pyproject.toml` (cyberstitch) - CyberSTITCH Python metadata.
- ok `cyberstitch_poc/cyberstitch.yml` (cyberstitch) - CyberSTITCH configuration.
- ok `cyberstitch_poc/cyberstitch` (cyberstitch) - CyberSTITCH implementation.
- ok `cyberstitch_poc/queries` (cyberstitch) - Baseline CyberSTITCH CodeQL queries.
- ok `cyberstitch_poc/query_profiles` (cyberstitch) - CyberSTITCH query profiles and seed manifests.
- ok `cyberstitch_poc/fixtures` (cyberstitch) - Fixture-backed LILO/AutoDoc inputs.
- ok `cyberstitch_poc/scripts` (cyberstitch) - CyberSTITCH experiment runner scripts.
- ok `cyberstitch_poc/tests` (cyberstitch) - CyberSTITCH tests.
- ok `cyberstitch_poc/benchmarks/owasp_curated_subset.json` (cyberstitch) - Curated fixture manifest.
- ok `cyberstitch_poc/benchmarks/owasp_curated_subset_benchmarkjava.json` (cyberstitch) - BenchmarkJava curated manifest.
- ok `cyberstitch_poc/benchmarks/owasp_cmdi_100_benchmarkjava.json` (cyberstitch) - BenchmarkJava command injection manifest.
- ok `cyberstitch_poc/benchmarks/owasp_cmdi_sqli_all_benchmarkjava.json` (cyberstitch) - BenchmarkJava CMDI/SQLI manifest.
- ok `cyberstitch_poc/benchmarks/owasp_cmdi_sqli_all_benchmarkjava_official_expanded.json` (cyberstitch) - Companion-pack BenchmarkJava manifest.
- ok `cyberstitch_poc/benchmarks/owasp-fixture` (cyberstitch) - Checked-in fixture source corpus.
- ok `cyberstitch_poc/benchmarks/js` (cyberstitch) - Checked-in JS fixture corpus.
- ok `cyberstitch_poc/results/artifact_demo_cyberstitch_combined_pack_final` (cyberstitch) - Deterministic combined-pack final run.
- ok `cyberstitch_poc/results/artifact_demo_cyberstitch_companion_pack_final` (cyberstitch) - Deterministic companion-pack final run.
- ok `cyberstitch_poc/results/artifact_demo_cyberstitch_bounded_pack_final` (cyberstitch) - Deterministic bounded-pack final run.
- ok `cyberstitch_poc/results/artifact_demo_cyberstitch_combined_pack_fixture_lilo` (cyberstitch) - Fixture-backed LILO-loop artifact run.
- ok `cyberstitch_poc/results/artifact_demo_cyberstitch_combined_pack_live_api` (cyberstitch) - Live API partitioned combined-pack record run.
- ok `cyberstitch_poc/results/artifact_demo_cyberstitch_companion_pack_live_api` (cyberstitch) - Live API partitioned companion-pack record run.
- ok `cyberstitch_poc/results/artifact_demo_cyberstitch_bounded_pack_live_api` (cyberstitch) - Live API partitioned bounded-pack record run.
- ok `cyberstitch_poc/results/lilo-llm-cache/artifact_demo_cyberstitch_combined_pack_live_api` (cyberstitch) - Live API combined-pack completion cache.
- ok `cyberstitch_poc/results/lilo-llm-cache/artifact_demo_cyberstitch_companion_pack_live_api` (cyberstitch) - Live API companion-pack completion cache.
- ok `cyberstitch_poc/results/lilo-llm-cache/artifact_demo_cyberstitch_bounded_pack_live_api` (cyberstitch) - Live API bounded-pack completion cache.

## Missing Required
- none

## Excluded Children Present
- none

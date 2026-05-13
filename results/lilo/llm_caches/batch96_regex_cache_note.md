# Batch-96 REGEX Cache Status

The batch-96 REGEX `gpt-3.5-turbo-instruct` original-completion runs do not
have a standalone request-hash replay cache like the batch-32 full-battery run.

The package includes the batch-96 REGEX result directories:

```text
lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment1
lilo_sec/experiments_iterative/outputs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment2
```

Those output trees contain the raw LLM result files, including
`gpt_solver_results.json` and `gpt_library_namer_results.json`, plus the
embedded `run.log` files. For convenience, the package also copies the two
embedded run logs to:

```text
results/lilo/run_logs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment1/run.log
results/lilo/run_logs/artifact_demo_lilo_regex_seed111_batch96_instruct_segment2/run.log
```

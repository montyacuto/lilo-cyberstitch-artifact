# CyberSTITCH AutoDoc Evaluation

Status: completed
Mode: `fixture`
Model: `gpt-3.5-turbo`
Source results: `<original-workspace>/cyberstitch_poc/results/benchmarkjava_lilo_full_combined_pack_artifact_20260512`
Inventory items: `50`
Tasks: `11`
Samples per task: `3`

## Scores

- `raw_names` aggregate=`0.021` success=`0.000` parse=`1.000` raw_codeql_violations=`0.818`
- `typed_names` aggregate=`1.000` success=`1.000` parse=`1.000` raw_codeql_violations=`0.000`
- `autodoc_names` aggregate=`1.000` success=`1.000` parse=`1.000` raw_codeql_violations=`0.000`
- `autodoc_docstrings` aggregate=`1.000` success=`1.000` parse=`1.000` raw_codeql_violations=`0.000`

## Primary Comparison

- baseline: `raw_names`
- treatment: `autodoc_docstrings`
- delta: `0.979`
- improved: `True`

## Policy

This evaluation measures LLM usability of validated abstractions. It does not change CodeQL query semantics or vulnerability-detection scores.

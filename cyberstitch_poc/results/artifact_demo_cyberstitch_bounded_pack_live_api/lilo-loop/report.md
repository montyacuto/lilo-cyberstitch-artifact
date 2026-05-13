# CyberSTITCH LILO Loop Report

Source: `lilo-loop-partitioned`
Executable candidate proposals: `4`
Autodoc items: `4`
Groupings: `0`
Query synthesis hints: `3`
Ignored outputs: `0`

## Policy

LLM output is advisory. Only provenance-backed rewrite candidates are allowed to enter CyberSTITCH validation, rewrite, CodeQL syntax, and SARIF equivalence gates.

## Candidate Proposals
- `java_active_threat_model_source` schema=`java_source_predicate_helper_v1` rewrite_eligible=`True`
- `java_command_injection_sink_sink` schema=`java_sink_predicate_helper_v1` rewrite_eligible=`True`
- `remote_flow_source` schema=`rewrite_candidate_reference_v1` rewrite_eligible=`False`
- `java_simple_type_sanitizer_barrier` schema=`java_barrier_predicate_helper_v1` rewrite_eligible=`True`

## Autodoc
- `candidate:java_active_threat_model_source`: Recognizes Java CodeQL ThreatModel semantics for ActiveThreatModelSource.
- `candidate:java_command_injection_sink_sink`: Recognizes Java CodeQL sink semantics for command injection.
- `candidate:java_method_call_sink_method_names_execute_query_486e5c11`: Recognizes Java CodeQL MethodCallSink semantics for method-names:executeQuery.
- `candidate:java_simple_type_sanitizer_barrier`: Recognizes Java CodeQL Barrier semantics for SimpleTypeSanitizer.

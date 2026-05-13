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
- `remote_flow_source` schema=`rewrite_candidate_reference_v1` rewrite_eligible=`False`
- `java_sink_node_sql_injection_sink` schema=`java_sink_predicate_helper_v1` rewrite_eligible=`True`
- `java_command_injection_sanitizer_barrier` schema=`java_barrier_predicate_helper_v1` rewrite_eligible=`True`

## Autodoc
- `candidate:java_active_threat_model_source`: Recognizes Java CodeQL ThreatModel semantics for ActiveThreatModelSource.
- `candidate:java_source_kind_guice_request_parameter_source_d5e556b9`: Recognizes Java CodeQL SourceKind semantics for GuiceRequestParameterSource.
- `candidate:java_sink_node_sql_injection_sink`: Recognizes Java CodeQL sink predicate semantics for SQL injection sinks.
- `candidate:java_command_injection_sanitizer_barrier`: Recognizes Java CodeQL Barrier semantics for CommandInjectionSanitizer.

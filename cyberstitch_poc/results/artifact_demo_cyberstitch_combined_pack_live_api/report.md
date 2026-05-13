# CyberSTITCH CodeQL/OWASP PoC Report

Language: `java`
OWASP root: `<original-workspace>/cyberstitch_poc/benchmarks/BenchmarkJava`
Curated manifest: `<original-workspace>/cyberstitch_poc/benchmarks/owasp_curated_subset_benchmarkjava.json`

## Tooling
- `java`: available openjdk version "25.0.3" 2026-04-21
- `mvn`: available Apache Maven 3.9.11 (Red Hat 3.9.11-5)
- `codeql`: available CodeQL command-line toolchain release 2.25.3.

## Curated Cases
- `BenchmarkTest00017` CWE-78 vulnerable `cmdi`: Header-derived servlet input flows through URL decoding into Runtime.exec argument 0, matching the narrow command sink abstraction.
- `BenchmarkTest00090` CWE-78 safe `cmdi`: Cookie input is present, but the feasible branch assigns a constant before Runtime.exec, exercising a safe command-injection control without list-index taint imprecision.
- `BenchmarkTest00018` CWE-89 vulnerable `sqli`: Header-derived servlet input is concatenated into SQL and passed to Statement.executeUpdate argument 0.
- `BenchmarkTest00107` CWE-89 safe `sqli`: Cookie input is assigned locally, but the SQL string uses a reflected constant before Statement.execute, exercising a safe SQL control.

## Abstractions
Accepted rewrite helpers: 7
Accepted LILO candidates: 50
LILO-only semantic candidates: 43
Rejected for rewrite: 90
Rejected for LILO inventory: 47
Final rewritten query syntax: `True`

Rewrite helpers:
- `java_active_threat_model_source` `java_source_predicate_helper_v1`: 5 use sites, CodeQL syntax `True`
- `java_command_injection_sink_sink` `java_sink_predicate_helper_v1`: 2 use sites, CodeQL syntax `True`
- `java_command_injection_sanitizer_barrier` `java_barrier_predicate_helper_v1`: 2 use sites, CodeQL syntax `True`
- `java_remote_flow_source` `legacy_codeql_helper_v1`: 2 use sites, CodeQL syntax `True`
- `java_query_injection_sink_sink` `java_sink_predicate_helper_v1`: 2 use sites, CodeQL syntax `True`
- `java_java_lang_runtime_exec_sink` `java_sink_predicate_helper_v1`: 2 use sites, CodeQL syntax `True`
- `java_method_names_execute_execute_query_execute_update_sink` `java_sink_predicate_helper_v1`: 2 use sites, CodeQL syntax `True`

LILO-only semantic candidates:
- `java_barrier_kind_command_injection_sanitizer_54fe9f81` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`CommandInjectionSanitizer`
- `java_barrier_kind_exec_tainted_environment_sanitizer_64e8ff50` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`ExecTaintedEnvironmentSanitizer`
- `java_barrier_kind_simple_type_sanitizer_0a047631` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`SimpleTypeSanitizer`
- `java_barrier_kind_simple_type_sanitizer_f70cdda5` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`SimpleTypeSanitizer`
- `java_barrier_kind_barrier_node_command_injection_75be8832` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`barrierNode:command-injection`
- `java_method_call_sink_java_lang_runtime_exec_d636a205` `java_modeled_sink_helper_v1` role=`MethodCallSink` target=`java.lang.Runtime.exec`
- `java_method_call_sink_method_names_execute_execute_query_execute_update_2d9cf866` `java_modeled_sink_helper_v1` role=`MethodCallSink` target=`method-names:execute|executeQuery|executeUpdate`
- `java_modeled_sink_type_command_injection_sink_2da17f01` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`CommandInjectionSink`
- `java_modeled_sink_type_default_command_injection_sink_c9373329` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`DefaultCommandInjectionSink`
- `java_modeled_sink_type_mongo_db_injection_sink_c4849996` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`MongoDbInjectionSink`
- `java_modeled_sink_type_my_batis_sql_injection_sink_7b7ec159` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`MyBatisSqlInjectionSink`
- `java_modeled_sink_type_persistence_query_injection_sink_41d858c8` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`PersistenceQueryInjectionSink`
- `java_modeled_sink_type_query_injection_sink_fba18fca` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`QueryInjectionSink`
- `java_modeled_sink_type_query_injection_sink_acd681bc` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`QueryInjectionSink`
- `java_modeled_sink_type_sql_injection_sink_a7f7cdd4` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`SqlInjectionSink`
- `java_sink_kind_sink_node_command_injection_058dd9c5` `java_modeled_sink_helper_v1` role=`SinkKind` target=`sinkNode:command-injection`
- `java_sink_kind_sink_node_environment_injection_32bdea5f` `java_modeled_sink_helper_v1` role=`SinkKind` target=`sinkNode:environment-injection`
- `java_sink_kind_sink_node_sql_injection_e532ab40` `java_modeled_sink_helper_v1` role=`SinkKind` target=`sinkNode:sql-injection`
- `java_source_kind_android_external_storage_source_edf149a9` `java_remote_source_kind_template_v1` role=`SourceKind` target=`AndroidExternalStorageSource`
- `java_source_kind_android_javascript_interface_method_parameter_01e51fdb` `java_remote_source_kind_template_v1` role=`SourceKind` target=`AndroidJavascriptInterfaceMethodParameter`
- `java_source_kind_exported_android_content_provider_input_1c741880` `java_remote_source_kind_template_v1` role=`SourceKind` target=`ExportedAndroidContentProviderInput`
- `java_source_kind_exported_android_intent_input_5afd578a` `java_remote_source_kind_template_v1` role=`SourceKind` target=`ExportedAndroidIntentInput`
- `java_source_kind_external_remote_flow_source_c97357e4` `java_remote_source_kind_template_v1` role=`SourceKind` target=`ExternalRemoteFlowSource`
- `java_source_kind_guice_request_parameter_source_d5e556b9` `java_remote_source_kind_template_v1` role=`SourceKind` target=`GuiceRequestParameterSource`
- `java_source_kind_jax_rs_method_parameter_source_de780bd2` `java_remote_source_kind_template_v1` role=`SourceKind` target=`JaxRsMethodParameterSource`
- `java_source_kind_jax_ws_method_parameter_source_4c05ab0a` `java_remote_source_kind_template_v1` role=`SourceKind` target=`JaxWsMethodParameterSource`
- `java_source_kind_local_user_input_66e9bccd` `java_remote_source_kind_template_v1` role=`SourceKind` target=`LocalUserInput`
- `java_source_kind_message_body_reader_parameter_source_810ff54e` `java_remote_source_kind_template_v1` role=`SourceKind` target=`MessageBodyReaderParameterSource`
- `java_source_kind_on_activity_result_intent_source_6be87d9c` `java_remote_source_kind_template_v1` role=`SourceKind` target=`OnActivityResultIntentSource`
- `java_source_kind_play_parameter_source_ea212a10` `java_remote_source_kind_template_v1` role=`SourceKind` target=`PlayParameterSource`
- `java_source_kind_remote_flow_source_3dbd0ce5` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource`
- `java_source_kind_remote_flow_source_7bbaf778` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource`
- `java_source_kind_remote_flow_source_get_source_type_android_external_storage_c1deb228` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Android external storage`
- `java_source_kind_remote_flow_source_get_source_type_android_on_activity_result_incoming_intent_3b7a8b24` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Android onActivityResult incoming Intent`
- `java_source_kind_remote_flow_source_get_source_type_exported_android_content_provider_source_bca0b10f` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Exported Android content provider source`
- `java_source_kind_remote_flow_source_get_source_type_exported_android_intent_source_ae63c928` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Exported Android intent source`
- `java_source_kind_remote_flow_source_get_source_type_guice_request_parameter_4fbc8cd3` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Guice request parameter`
- `java_source_kind_remote_flow_source_get_source_type_jax_rs_method_parameter_eef3e93a` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Jax Rs method parameter`
- `java_source_kind_remote_flow_source_get_source_type_jax_ws_method_parameter_60a8f881` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Jax WS method parameter`
- `java_source_kind_remote_flow_source_get_source_type_message_body_reader_parameter_91ac6ff8` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:MessageBodyReader parameter`
- `java_source_kind_remote_flow_source_get_source_type_external_7afe2f1b` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:external`
- `java_threat_model_active_threat_model_source_3c0f2e2d` `java_remote_source_kind_template_v1` role=`ThreatModel` target=`ActiveThreatModelSource`
- `java_threat_model_active_threat_model_source_473aa43e` `java_remote_source_kind_template_v1` role=`ThreatModel` target=`ActiveThreatModelSource`

Rewrite rejection reasons:
- `single_sql_sink`: `['requires at least two use sites']`
- `java_additional_flow_step_mongo_json_step_2a94fedc`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_barrier_kind_command_injection_sanitizer_54fe9f81`: `['unsupported kind', 'not rewrite eligible', 'helper body must be a CodeQL predicate']`
- `java_barrier_kind_exec_tainted_environment_sanitizer_64e8ff50`: `['unsupported kind', 'not rewrite eligible', 'helper body must be a CodeQL predicate']`
- `java_barrier_kind_simple_type_sanitizer_0a047631`: `['unsupported kind', 'not rewrite eligible', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_barrier_kind_simple_type_sanitizer_f70cdda5`: `['unsupported kind', 'not rewrite eligible', 'helper body must be a CodeQL predicate']`
- `java_barrier_kind_barrier_node_command_injection_75be8832`: `['unsupported kind', 'not rewrite eligible', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_flow_config_template_data_flow_config_sig_041e8064`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_flow_config_template_data_flow_config_sig_a179cc3c`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_flow_config_template_data_flow_config_sig_754b88b3`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_argument_to_exec_e0026a4d`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_array_starting_with_relative_5f4700a2`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_array_starting_with_relative_6b62f527`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_array_var_write_23605328`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_as_expr_73d53280`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_built_from_uncontrolled_concat_bbd4acb7`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_built_from_uncontrolled_concat_9be8b9d4`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_built_from_uncontrolled_concat_b215e9cf`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_exec_is_tainted_cd986973`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_exists_a963cb31`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_expr_node_f44c1849`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_flow_71710f22`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_get_to_string_call_fd136cb2`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_is_safe_command_argument_014fc590`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_is_shell_76418667`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_observe_diff_informed_incremental_mode_a3aa1f34`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_observe_diff_informed_incremental_mode_70022ea9`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_query_is_tainted_by_e65d05d8`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_relative_path_05def52b`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_relative_path_a83b954f`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_shell_builtin_4f9b65cc`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_shell_builtin_a2be99dd`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_uncontrolled_string_builder_query_64e97e59`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_uncontrolled_string_builder_query_5e9866dd`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_helper_predicate_variable_step_984b7036`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_method_call_sink_java_lang_runtime_exec_d636a205`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_method_call_sink_method_names_execute_execute_query_execute_update_2d9cf866`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_modeled_sink_type_command_injection_sink_2da17f01`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_modeled_sink_type_default_command_injection_sink_c9373329`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_modeled_sink_type_mongo_db_injection_sink_c4849996`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_modeled_sink_type_my_batis_sql_injection_sink_7b7ec159`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_modeled_sink_type_persistence_query_injection_sink_41d858c8`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_modeled_sink_type_query_injection_sink_fba18fca`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_modeled_sink_type_query_injection_sink_acd681bc`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_modeled_sink_type_sql_injection_sink_a7f7cdd4`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_sink_kind_sink_node_command_injection_058dd9c5`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_sink_kind_sink_node_environment_injection_32bdea5f`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_sink_kind_sink_node_sql_injection_e532ab40`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_source_kind_android_external_storage_source_edf149a9`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_android_javascript_interface_method_parameter_01e51fdb`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_exported_android_content_provider_input_1c741880`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_exported_android_intent_input_5afd578a`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_external_remote_flow_source_c97357e4`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_guice_request_parameter_source_d5e556b9`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_jax_rs_method_parameter_source_de780bd2`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_jax_ws_method_parameter_source_4c05ab0a`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_local_user_input_66e9bccd`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_message_body_reader_parameter_source_810ff54e`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_on_activity_result_intent_source_6be87d9c`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_play_parameter_source_ea212a10`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_3dbd0ce5`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_7bbaf778`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_android_external_storage_c1deb228`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_android_on_activity_result_incoming_intent_3b7a8b24`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_exported_android_content_provider_source_bca0b10f`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_exported_android_intent_source_ae63c928`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_guice_request_parameter_4fbc8cd3`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_jax_rs_method_parameter_eef3e93a`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_jax_ws_method_parameter_60a8f881`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_message_body_reader_parameter_91ac6ff8`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_parameter_of_method_with_javascript_interface_annotation_0fe0f3ff`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_play_query_parameters_ac319954`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_rmi_method_parameter_281dfa33`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_spring_servlet_input_parameter_9a9a04ab`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_struts2_action_support_field_d2cd07c5`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_thrift_iface_parameter_5252f793`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_flow_source_get_source_type_external_7afe2f1b`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_remote_user_input_f3189813`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_rmi_method_parameter_source_a5bfaf1b`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_spring_servlet_input_parameter_source_72b0425c`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_struts2_action_support_class_field_source_eb3d855b`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_thrift_iface_parameter_source_79e4535a`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_uncontrolled_string_builder_source_76477073`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_source_node_contentprovider_231325d9`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_source_node_database_13ebec9b`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_source_node_environment_9b46f350`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_source_node_file_9f1d7ae0`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_source_kind_source_node_remote_5aafd1a4`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'requires at least two use sites', 'helper body must be a CodeQL predicate']`
- `java_threat_model_active_threat_model_source_3c0f2e2d`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`
- `java_threat_model_active_threat_model_source_473aa43e`: `['unsupported kind', 'not rewrite eligible', 'unsupported rewrite schema', 'helper body must be a CodeQL predicate']`

LILO inventory rejection reasons:
- `single_sql_sink`: `['requires at least two use sites or official CodeQL backing']`
- `java_additional_flow_step_mongo_json_step_2a94fedc`: `['outside bounded LILO inventory cap']`
- `java_flow_config_template_data_flow_config_sig_041e8064`: `['structural syntax-compression template']`
- `java_flow_config_template_data_flow_config_sig_a179cc3c`: `['structural syntax-compression template']`
- `java_flow_config_template_data_flow_config_sig_754b88b3`: `['structural syntax-compression template']`
- `java_helper_predicate_argument_to_exec_e0026a4d`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_array_starting_with_relative_5f4700a2`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_array_starting_with_relative_6b62f527`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_array_var_write_23605328`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_as_expr_73d53280`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_built_from_uncontrolled_concat_bbd4acb7`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_built_from_uncontrolled_concat_9be8b9d4`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_built_from_uncontrolled_concat_b215e9cf`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_exec_is_tainted_cd986973`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_exists_a963cb31`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_expr_node_f44c1849`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_flow_71710f22`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_get_to_string_call_fd136cb2`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_is_safe_command_argument_014fc590`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_is_shell_76418667`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_observe_diff_informed_incremental_mode_a3aa1f34`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_observe_diff_informed_incremental_mode_70022ea9`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_query_is_tainted_by_e65d05d8`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_relative_path_05def52b`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_relative_path_a83b954f`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_shell_builtin_4f9b65cc`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_shell_builtin_a2be99dd`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_uncontrolled_string_builder_query_64e97e59`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_uncontrolled_string_builder_query_5e9866dd`: `['outside bounded LILO inventory cap']`
- `java_helper_predicate_variable_step_984b7036`: `['outside bounded LILO inventory cap']`
- `java_source_kind_remote_flow_source_get_source_type_parameter_of_method_with_javascript_interface_annotation_0fe0f3ff`: `['outside bounded LILO inventory cap']`
- `java_source_kind_remote_flow_source_get_source_type_play_query_parameters_ac319954`: `['outside bounded LILO inventory cap']`
- `java_source_kind_remote_flow_source_get_source_type_rmi_method_parameter_281dfa33`: `['outside bounded LILO inventory cap']`
- `java_source_kind_remote_flow_source_get_source_type_spring_servlet_input_parameter_9a9a04ab`: `['outside bounded LILO inventory cap']`
- `java_source_kind_remote_flow_source_get_source_type_struts2_action_support_field_d2cd07c5`: `['outside bounded LILO inventory cap']`
- `java_source_kind_remote_flow_source_get_source_type_thrift_iface_parameter_5252f793`: `['outside bounded LILO inventory cap']`
- `java_source_kind_remote_user_input_f3189813`: `['outside bounded LILO inventory cap']`
- `java_source_kind_rmi_method_parameter_source_a5bfaf1b`: `['outside bounded LILO inventory cap']`
- `java_source_kind_spring_servlet_input_parameter_source_72b0425c`: `['outside bounded LILO inventory cap']`
- `java_source_kind_struts2_action_support_class_field_source_eb3d855b`: `['outside bounded LILO inventory cap']`
- `java_source_kind_thrift_iface_parameter_source_79e4535a`: `['outside bounded LILO inventory cap']`
- `java_source_kind_uncontrolled_string_builder_source_76477073`: `['outside bounded LILO inventory cap']`
- `java_source_kind_source_node_contentprovider_231325d9`: `['outside bounded LILO inventory cap']`
- `java_source_kind_source_node_database_13ebec9b`: `['outside bounded LILO inventory cap']`
- `java_source_kind_source_node_environment_9b46f350`: `['outside bounded LILO inventory cap']`
- `java_source_kind_source_node_file_9f1d7ae0`: `['outside bounded LILO inventory cap']`
- `java_source_kind_source_node_remote_5aafd1a4`: `['outside bounded LILO inventory cap']`

## Semantic Concept Mining
Extracted concepts: `160`
Mined candidates: `96`
Rewrite eligible: `7`
Semantic-only: `89`
- `java_active_threat_model_source` `java_source_predicate_helper_v1` role=`Source` target=`ActiveThreatModelSource` rewrite=`True` usefulness=`semantic`
- `java_command_injection_sink_sink` `java_sink_predicate_helper_v1` role=`Sink` target=`CommandInjectionSink` rewrite=`True` usefulness=`semantic`
- `java_command_injection_sanitizer_barrier` `java_barrier_predicate_helper_v1` role=`Barrier` target=`CommandInjectionSanitizer` rewrite=`True` usefulness=`semantic`
- `java_query_injection_sink_sink` `java_sink_predicate_helper_v1` role=`Sink` target=`QueryInjectionSink` rewrite=`True` usefulness=`semantic`
- `java_remote_flow_source` `java_source_predicate_helper_v1` role=`Source` target=`RemoteFlowSource` rewrite=`True` usefulness=`semantic`
- `java_java_lang_runtime_exec_sink` `java_sink_predicate_helper_v1` role=`Sink` target=`java.lang.Runtime.exec` rewrite=`True` usefulness=`semantic`
- `java_method_names_execute_execute_query_execute_update_sink` `java_sink_predicate_helper_v1` role=`Sink` target=`method-names:execute|executeQuery|executeUpdate` rewrite=`True` usefulness=`semantic`
- `java_additional_flow_step_mongo_json_step_2a94fedc` `java_additional_flow_step_template_v1` role=`AdditionalFlowStep` target=`MongoJsonStep` rewrite=`False` usefulness=`semantic`
- `java_barrier_kind_command_injection_sanitizer_54fe9f81` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`CommandInjectionSanitizer` rewrite=`False` usefulness=`semantic`
- `java_barrier_kind_exec_tainted_environment_sanitizer_64e8ff50` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`ExecTaintedEnvironmentSanitizer` rewrite=`False` usefulness=`semantic`
- `java_barrier_kind_simple_type_sanitizer_0a047631` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`SimpleTypeSanitizer` rewrite=`False` usefulness=`semantic`
- `java_barrier_kind_simple_type_sanitizer_f70cdda5` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`SimpleTypeSanitizer` rewrite=`False` usefulness=`semantic`
- `java_barrier_kind_barrier_node_command_injection_75be8832` `java_barrier_predicate_helper_v1` role=`BarrierKind` target=`barrierNode:command-injection` rewrite=`False` usefulness=`semantic`
- `java_flow_config_template_data_flow_config_sig_041e8064` `java_flow_config_template_v1` role=`FlowConfigTemplate` target=`DataFlow::ConfigSig` rewrite=`False` usefulness=`semantic`
- `java_flow_config_template_data_flow_config_sig_a179cc3c` `java_flow_config_template_v1` role=`FlowConfigTemplate` target=`DataFlow::ConfigSig` rewrite=`False` usefulness=`semantic`
- `java_flow_config_template_data_flow_config_sig_754b88b3` `java_flow_config_template_v1` role=`FlowConfigTemplate` target=`DataFlow::ConfigSig` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_argument_to_exec_e0026a4d` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`argumentToExec` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_array_starting_with_relative_5f4700a2` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`arrayStartingWithRelative` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_array_starting_with_relative_6b62f527` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`arrayStartingWithRelative` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_array_var_write_23605328` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`arrayVarWrite` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_as_expr_73d53280` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`asExpr` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_built_from_uncontrolled_concat_bbd4acb7` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`builtFromUncontrolledConcat` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_built_from_uncontrolled_concat_9be8b9d4` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`builtFromUncontrolledConcat` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_built_from_uncontrolled_concat_b215e9cf` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`builtFromUncontrolledConcat` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_exec_is_tainted_cd986973` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`execIsTainted` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_exists_a963cb31` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`exists` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_expr_node_f44c1849` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`exprNode` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_flow_71710f22` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`flow` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_get_to_string_call_fd136cb2` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`getToStringCall` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_is_safe_command_argument_014fc590` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`isSafeCommandArgument` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_is_shell_76418667` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`isShell` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_observe_diff_informed_incremental_mode_a3aa1f34` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`observeDiffInformedIncrementalMode` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_observe_diff_informed_incremental_mode_70022ea9` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`observeDiffInformedIncrementalMode` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_query_is_tainted_by_e65d05d8` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`queryIsTaintedBy` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_relative_path_05def52b` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`relativePath` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_relative_path_a83b954f` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`relativePath` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_shell_builtin_4f9b65cc` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`shellBuiltin` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_shell_builtin_a2be99dd` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`shellBuiltin` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_uncontrolled_string_builder_query_64e97e59` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`uncontrolledStringBuilderQuery` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_uncontrolled_string_builder_query_5e9866dd` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`uncontrolledStringBuilderQuery` rewrite=`False` usefulness=`semantic`
- `java_helper_predicate_variable_step_984b7036` `java_codeql_helper_predicate_template_v1` role=`HelperPredicate` target=`variableStep` rewrite=`False` usefulness=`semantic`
- `java_method_call_sink_java_lang_runtime_exec_d636a205` `java_modeled_sink_helper_v1` role=`MethodCallSink` target=`java.lang.Runtime.exec` rewrite=`False` usefulness=`semantic`
- `java_method_call_sink_method_names_execute_execute_query_execute_update_2d9cf866` `java_modeled_sink_helper_v1` role=`MethodCallSink` target=`method-names:execute|executeQuery|executeUpdate` rewrite=`False` usefulness=`semantic`
- `java_modeled_sink_type_command_injection_sink_2da17f01` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`CommandInjectionSink` rewrite=`False` usefulness=`semantic`
- `java_modeled_sink_type_default_command_injection_sink_c9373329` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`DefaultCommandInjectionSink` rewrite=`False` usefulness=`semantic`
- `java_modeled_sink_type_mongo_db_injection_sink_c4849996` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`MongoDbInjectionSink` rewrite=`False` usefulness=`semantic`
- `java_modeled_sink_type_my_batis_sql_injection_sink_7b7ec159` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`MyBatisSqlInjectionSink` rewrite=`False` usefulness=`semantic`
- `java_modeled_sink_type_persistence_query_injection_sink_41d858c8` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`PersistenceQueryInjectionSink` rewrite=`False` usefulness=`semantic`
- `java_modeled_sink_type_query_injection_sink_fba18fca` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`QueryInjectionSink` rewrite=`False` usefulness=`semantic`
- `java_modeled_sink_type_query_injection_sink_acd681bc` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`QueryInjectionSink` rewrite=`False` usefulness=`semantic`
- `java_modeled_sink_type_sql_injection_sink_a7f7cdd4` `java_modeled_sink_helper_v1` role=`ModeledSinkType` target=`SqlInjectionSink` rewrite=`False` usefulness=`semantic`
- `java_sink_kind_sink_node_command_injection_058dd9c5` `java_modeled_sink_helper_v1` role=`SinkKind` target=`sinkNode:command-injection` rewrite=`False` usefulness=`semantic`
- `java_sink_kind_sink_node_environment_injection_32bdea5f` `java_modeled_sink_helper_v1` role=`SinkKind` target=`sinkNode:environment-injection` rewrite=`False` usefulness=`semantic`
- `java_sink_kind_sink_node_sql_injection_e532ab40` `java_modeled_sink_helper_v1` role=`SinkKind` target=`sinkNode:sql-injection` rewrite=`False` usefulness=`semantic`
- `java_source_kind_android_external_storage_source_edf149a9` `java_remote_source_kind_template_v1` role=`SourceKind` target=`AndroidExternalStorageSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_android_javascript_interface_method_parameter_01e51fdb` `java_remote_source_kind_template_v1` role=`SourceKind` target=`AndroidJavascriptInterfaceMethodParameter` rewrite=`False` usefulness=`semantic`
- `java_source_kind_exported_android_content_provider_input_1c741880` `java_remote_source_kind_template_v1` role=`SourceKind` target=`ExportedAndroidContentProviderInput` rewrite=`False` usefulness=`semantic`
- `java_source_kind_exported_android_intent_input_5afd578a` `java_remote_source_kind_template_v1` role=`SourceKind` target=`ExportedAndroidIntentInput` rewrite=`False` usefulness=`semantic`
- `java_source_kind_external_remote_flow_source_c97357e4` `java_remote_source_kind_template_v1` role=`SourceKind` target=`ExternalRemoteFlowSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_guice_request_parameter_source_d5e556b9` `java_remote_source_kind_template_v1` role=`SourceKind` target=`GuiceRequestParameterSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_jax_rs_method_parameter_source_de780bd2` `java_remote_source_kind_template_v1` role=`SourceKind` target=`JaxRsMethodParameterSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_jax_ws_method_parameter_source_4c05ab0a` `java_remote_source_kind_template_v1` role=`SourceKind` target=`JaxWsMethodParameterSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_local_user_input_66e9bccd` `java_remote_source_kind_template_v1` role=`SourceKind` target=`LocalUserInput` rewrite=`False` usefulness=`semantic`
- `java_source_kind_message_body_reader_parameter_source_810ff54e` `java_remote_source_kind_template_v1` role=`SourceKind` target=`MessageBodyReaderParameterSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_on_activity_result_intent_source_6be87d9c` `java_remote_source_kind_template_v1` role=`SourceKind` target=`OnActivityResultIntentSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_play_parameter_source_ea212a10` `java_remote_source_kind_template_v1` role=`SourceKind` target=`PlayParameterSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_3dbd0ce5` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_7bbaf778` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_android_external_storage_c1deb228` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Android external storage` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_android_on_activity_result_incoming_intent_3b7a8b24` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Android onActivityResult incoming Intent` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_exported_android_content_provider_source_bca0b10f` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Exported Android content provider source` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_exported_android_intent_source_ae63c928` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Exported Android intent source` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_guice_request_parameter_4fbc8cd3` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Guice request parameter` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_jax_rs_method_parameter_eef3e93a` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Jax Rs method parameter` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_jax_ws_method_parameter_60a8f881` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Jax WS method parameter` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_message_body_reader_parameter_91ac6ff8` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:MessageBodyReader parameter` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_parameter_of_method_with_javascript_interface_annotation_0fe0f3ff` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Parameter of method with JavascriptInterface annotation` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_play_query_parameters_ac319954` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Play Query Parameters` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_rmi_method_parameter_281dfa33` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:RMI method parameter` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_spring_servlet_input_parameter_9a9a04ab` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Spring servlet input parameter` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_struts2_action_support_field_d2cd07c5` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Struts2 ActionSupport field` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_thrift_iface_parameter_5252f793` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:Thrift Iface parameter` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_flow_source_get_source_type_external_7afe2f1b` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteFlowSource.getSourceType:external` rewrite=`False` usefulness=`semantic`
- `java_source_kind_remote_user_input_f3189813` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RemoteUserInput` rewrite=`False` usefulness=`semantic`
- `java_source_kind_rmi_method_parameter_source_a5bfaf1b` `java_remote_source_kind_template_v1` role=`SourceKind` target=`RmiMethodParameterSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_spring_servlet_input_parameter_source_72b0425c` `java_remote_source_kind_template_v1` role=`SourceKind` target=`SpringServletInputParameterSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_struts2_action_support_class_field_source_eb3d855b` `java_remote_source_kind_template_v1` role=`SourceKind` target=`Struts2ActionSupportClassFieldSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_thrift_iface_parameter_source_79e4535a` `java_remote_source_kind_template_v1` role=`SourceKind` target=`ThriftIfaceParameterSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_uncontrolled_string_builder_source_76477073` `java_remote_source_kind_template_v1` role=`SourceKind` target=`UncontrolledStringBuilderSource` rewrite=`False` usefulness=`semantic`
- `java_source_kind_source_node_contentprovider_231325d9` `java_remote_source_kind_template_v1` role=`SourceKind` target=`sourceNode:contentprovider` rewrite=`False` usefulness=`semantic`
- `java_source_kind_source_node_database_13ebec9b` `java_remote_source_kind_template_v1` role=`SourceKind` target=`sourceNode:database` rewrite=`False` usefulness=`semantic`
- `java_source_kind_source_node_environment_9b46f350` `java_remote_source_kind_template_v1` role=`SourceKind` target=`sourceNode:environment` rewrite=`False` usefulness=`semantic`
- `java_source_kind_source_node_file_9f1d7ae0` `java_remote_source_kind_template_v1` role=`SourceKind` target=`sourceNode:file` rewrite=`False` usefulness=`semantic`
- `java_source_kind_source_node_remote_5aafd1a4` `java_remote_source_kind_template_v1` role=`SourceKind` target=`sourceNode:remote` rewrite=`False` usefulness=`semantic`
- `java_threat_model_active_threat_model_source_3c0f2e2d` `java_remote_source_kind_template_v1` role=`ThreatModel` target=`ActiveThreatModelSource` rewrite=`False` usefulness=`semantic`
- `java_threat_model_active_threat_model_source_473aa43e` `java_remote_source_kind_template_v1` role=`ThreatModel` target=`ActiveThreatModelSource` rewrite=`False` usefulness=`semantic`

## Scores
- `original.json`: `{'78': {'TP': 1, 'FN': 0, 'TN': 1, 'FP': 0}, '89': {'TP': 1, 'FN': 0, 'TN': 1, 'FP': 0}}`
- `rewritten.json`: `{'78': {'TP': 1, 'FN': 0, 'TN': 1, 'FP': 0}, '89': {'TP': 1, 'FN': 0, 'TN': 1, 'FP': 0}}`
- `roundtrip.json`: `{'78': {'TP': 1, 'FN': 0, 'TN': 1, 'FP': 0}, '89': {'TP': 1, 'FN': 0, 'TN': 1, 'FP': 0}}`

## Seed Query Discovery
Java query pack: `<original-workspace>/codeql/qlpacks/codeql/java-queries/1.11.1`
Include experimental: `False`
Selection policy: `all`
Resolved specs: `2`
Resolved queries: `6`
Selected seeds: `6`
Discovery score: `{'78': {'TP': 1, 'FN': 0, 'TN': 0, 'FP': 1}, '89': {'TP': 1, 'FN': 0, 'TN': 0, 'FP': 1}}`
- `java/relative-path-command` CWE-78 `Security/CWE/CWE-078/ExecRelative.ql` alerts=`0` experimental=`False`
- `java/command-line-injection` CWE-78 `Security/CWE/CWE-078/ExecTainted.ql` alerts=`112` experimental=`False`
- `java/exec-tainted-environment` CWE-78 `Security/CWE/CWE-078/ExecTaintedEnvironment.ql` alerts=`59` experimental=`False`
- `java/concatenated-command-line` CWE-78 `Security/CWE/CWE-078/ExecUnescaped.ql` alerts=`19` experimental=`False`
- `java/concatenated-sql-query` CWE-89 `Security/CWE/CWE-089/SqlConcatenated.ql` alerts=`120` experimental=`False`
- `java/sql-injection` CWE-89 `Security/CWE/CWE-089/SqlTainted.ql` alerts=`359` experimental=`False`

## Bundle Policy
Policy: `opt-in only`
Bundle mode: `none`
Bundle created: `False`
CodeQL database bundles are restricted/source-containing troubleshooting artifacts and are excluded from package output by default.

## Commands
```bash
python -m cyberstitch.cli doctor
python -m cyberstitch.cli sqir
python -m cyberstitch.cli roundtrip
python -m cyberstitch.cli fcir
# Optional official pack FCIR mining corpus:
# python -m cyberstitch.cli codeql-pack-fcir --include-experimental
python -m cyberstitch.cli stitch --mode offline
python -m cyberstitch.cli semantic-mine --merge
# Optional schema-only LILO LLM proposals:
# python -m cyberstitch.cli llm-propose --merge
python -m cyberstitch.cli validate
python -m cyberstitch.cli rewrite
python -m cyberstitch.cli codeql-check
python -m cyberstitch.cli db-create
# Optional official CodeQL seed discovery after db-create:
# python -m cyberstitch.cli codeql-discover --database results/codeql-dbs/java
python -m cyberstitch.cli analyze --queries original
python -m cyberstitch.cli score --sarif results/sarif/original.sarif
# Optional restricted troubleshooting bundle only:
# python -m cyberstitch.cli db-bundle --output results/bundles/java-codeql-debug-artifacts.zip
```

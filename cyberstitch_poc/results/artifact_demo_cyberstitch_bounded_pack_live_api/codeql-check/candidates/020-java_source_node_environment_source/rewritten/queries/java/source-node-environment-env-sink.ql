/**
 * @name Environment source label reaches environment-injection sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-environment-env-sink
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.CommandLineQuery
import semmle.code.java.security.ExternalProcess
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.SqlInjectionQuery
import semmle.code.java.security.Sanitizers
import semmle.code.java.security.TaintedEnvironmentVariableQuery

module SourceNodeEnvironmentEnvSinkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isSourceNodeEnvironmentSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "environment-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(ExecTaintedEnvironmentSanitizer sanitizer | node = sanitizer)
  }
}

module SourceNodeEnvironmentEnvSinkFlow = TaintTracking::Global<SourceNodeEnvironmentEnvSinkConfig>;
import SourceNodeEnvironmentEnvSinkFlow::PathGraph
import cyberstitch_helpers_java

from SourceNodeEnvironmentEnvSinkFlow::PathNode source, SourceNodeEnvironmentEnvSinkFlow::PathNode sink
where SourceNodeEnvironmentEnvSinkFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:environment source reaches sinkNode:environment-injection sink."

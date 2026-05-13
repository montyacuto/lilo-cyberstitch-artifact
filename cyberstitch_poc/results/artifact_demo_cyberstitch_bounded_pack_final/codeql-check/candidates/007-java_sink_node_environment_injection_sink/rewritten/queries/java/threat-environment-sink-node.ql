/**
 * @name Threat-model source reaches environment-injection sink label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-environment-sink-node
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

module ThreatEnvironmentSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isSinkNodeEnvironmentInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(ExecTaintedEnvironmentSanitizer sanitizer | node = sanitizer)
  }
}

module ThreatEnvironmentSinkNodeFlow = TaintTracking::Global<ThreatEnvironmentSinkNodeConfig>;
import ThreatEnvironmentSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from ThreatEnvironmentSinkNodeFlow::PathNode source, ThreatEnvironmentSinkNodeFlow::PathNode sink
where ThreatEnvironmentSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches sinkNode:environment-injection sink."

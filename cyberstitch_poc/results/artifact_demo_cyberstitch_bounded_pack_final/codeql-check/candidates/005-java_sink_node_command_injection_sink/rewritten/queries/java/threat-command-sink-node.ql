/**
 * @name Threat-model source reaches command-injection sink model label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-command-sink-node
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

module ThreatCommandSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isSinkNodeCommandInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    barrierNode(node, "command-injection")
  }
}

module ThreatCommandSinkNodeFlow = TaintTracking::Global<ThreatCommandSinkNodeConfig>;
import ThreatCommandSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from ThreatCommandSinkNodeFlow::PathNode source, ThreatCommandSinkNodeFlow::PathNode sink
where ThreatCommandSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches sinkNode:command-injection sink."

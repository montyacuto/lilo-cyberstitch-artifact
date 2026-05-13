/**
 * @name Active threat model source reaches argumentToExec command sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/threat-cwe078-argument-to-exec
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.CommandLineQuery
import semmle.code.java.security.ExternalProcess

module ThreatArgumentToExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | argumentToExec(sink.asExpr(), command))
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isCommandInjectionSanitizerBarrier(node)
  }
}

module ThreatArgumentToExecFlow = TaintTracking::Global<ThreatArgumentToExecConfig>;
import ThreatArgumentToExecFlow::PathGraph
import cyberstitch_helpers_java

from ThreatArgumentToExecFlow::PathNode source, ThreatArgumentToExecFlow::PathNode sink
where ThreatArgumentToExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Threat-model source reaches an argumentToExec command sink."

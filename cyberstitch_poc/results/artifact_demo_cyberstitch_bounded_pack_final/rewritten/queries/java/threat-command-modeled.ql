/**
 * @name Threat-model source reaches CommandInjectionSink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-command-modeled
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

module ThreatCommandModeledConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | sink = command)
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isCommandInjectionSanitizerBarrier(node)
  }
}

module ThreatCommandModeledFlow = TaintTracking::Global<ThreatCommandModeledConfig>;
import ThreatCommandModeledFlow::PathGraph
import cyberstitch_helpers_java

from ThreatCommandModeledFlow::PathNode source, ThreatCommandModeledFlow::PathNode sink
where ThreatCommandModeledFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches CommandInjectionSink sink."

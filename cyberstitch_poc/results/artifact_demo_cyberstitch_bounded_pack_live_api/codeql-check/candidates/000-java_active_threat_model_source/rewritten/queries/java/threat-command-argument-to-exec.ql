/**
 * @name Threat-model source reaches argumentToExec sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-command-argument-to-exec
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

module ThreatCommandArgumentToExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command |
      argumentToExec(sink.asExpr(), command)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(CommandInjectionSanitizer sanitizer | node = sanitizer)
  }
}

module ThreatCommandArgumentToExecFlow = TaintTracking::Global<ThreatCommandArgumentToExecConfig>;
import ThreatCommandArgumentToExecFlow::PathGraph
import cyberstitch_helpers_java

from ThreatCommandArgumentToExecFlow::PathNode source, ThreatCommandArgumentToExecFlow::PathNode sink
where ThreatCommandArgumentToExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches argumentToExec sink."

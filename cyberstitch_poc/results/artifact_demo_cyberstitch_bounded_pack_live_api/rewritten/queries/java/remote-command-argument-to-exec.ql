/**
 * @name Remote input reaches argumentToExec sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/remote-command-argument-to-exec
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

module RemoteCommandArgumentToExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command |
      argumentToExec(sink.asExpr(), command)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isCommandInjectionSanitizerBarrier(node)
  }
}

module RemoteCommandArgumentToExecFlow = TaintTracking::Global<RemoteCommandArgumentToExecConfig>;
import RemoteCommandArgumentToExecFlow::PathGraph
import cyberstitch_helpers_java

from RemoteCommandArgumentToExecFlow::PathNode source, RemoteCommandArgumentToExecFlow::PathNode sink
where RemoteCommandArgumentToExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "RemoteFlowSource source reaches argumentToExec sink."

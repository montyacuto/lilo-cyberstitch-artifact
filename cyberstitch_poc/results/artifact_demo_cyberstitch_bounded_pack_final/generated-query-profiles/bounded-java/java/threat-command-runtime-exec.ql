/**
 * @name Threat-model source reaches Runtime.exec
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-command-runtime-exec
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

module ThreatCommandRuntimeExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().hasQualifiedName("java.lang", "Runtime", "exec") and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

module ThreatCommandRuntimeExecFlow = TaintTracking::Global<ThreatCommandRuntimeExecConfig>;
import ThreatCommandRuntimeExecFlow::PathGraph

from ThreatCommandRuntimeExecFlow::PathNode source, ThreatCommandRuntimeExecFlow::PathNode sink
where ThreatCommandRuntimeExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches java.lang.Runtime.exec sink."

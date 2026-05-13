/**
 * @name Threat-model source reaches execute argument sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-sql-execute
 * @tags security external/cwe/cwe-089
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

module ThreatSqlExecuteConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().hasName("execute") and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

module ThreatSqlExecuteFlow = TaintTracking::Global<ThreatSqlExecuteConfig>;
import ThreatSqlExecuteFlow::PathGraph

from ThreatSqlExecuteFlow::PathNode source, ThreatSqlExecuteFlow::PathNode sink
where ThreatSqlExecuteFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches execute sink."

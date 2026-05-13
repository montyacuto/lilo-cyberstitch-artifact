/**
 * @name Threat-model source reaches SQL statement execution methods
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-sql-statement-execute-all
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

module ThreatSqlStatementExecuteAllConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().hasName("execute") and
      sink.asExpr() = call.getArgument(0)
      or
      call.getMethod().hasName("executeQuery") and
      sink.asExpr() = call.getArgument(0)
      or
      call.getMethod().hasName("executeUpdate") and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

module ThreatSqlStatementExecuteAllFlow = TaintTracking::Global<ThreatSqlStatementExecuteAllConfig>;
import ThreatSqlStatementExecuteAllFlow::PathGraph
import cyberstitch_helpers_java

from ThreatSqlStatementExecuteAllFlow::PathNode source, ThreatSqlStatementExecuteAllFlow::PathNode sink
where ThreatSqlStatementExecuteAllFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches execute|executeQuery|executeUpdate sink."

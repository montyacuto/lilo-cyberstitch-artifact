/**
 * @name Remote input reaches SQL statement execution methods
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/remote-sql-statement-execute-all
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

module RemoteSqlStatementExecuteAllConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call | call.getMethod().hasName("execute") and
    sink.asExpr() = call.getArgument(0) or
    call.getMethod().hasName("executeQuery") and
    sink.asExpr() = call.getArgument(0) or
    call.getMethod().hasName("executeUpdate") and
    sink.asExpr() = call.getArgument(0))
  }

}

module RemoteSqlStatementExecuteAllFlow = TaintTracking::Global<RemoteSqlStatementExecuteAllConfig>;
import RemoteSqlStatementExecuteAllFlow::PathGraph

from RemoteSqlStatementExecuteAllFlow::PathNode source, RemoteSqlStatementExecuteAllFlow::PathNode sink
where RemoteSqlStatementExecuteAllFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "RemoteFlowSource source reaches execute|executeQuery|executeUpdate sink."

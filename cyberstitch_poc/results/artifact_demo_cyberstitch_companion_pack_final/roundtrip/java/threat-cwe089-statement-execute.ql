/**
 * @name Active threat model source reaches SQL statement execution
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/threat-cwe089-statement-execute
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ThreatSqlStatementConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
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

module ThreatSqlStatementFlow = TaintTracking::Global<ThreatSqlStatementConfig>;
import ThreatSqlStatementFlow::PathGraph

from ThreatSqlStatementFlow::PathNode source, ThreatSqlStatementFlow::PathNode sink
where ThreatSqlStatementFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Threat-model source reaches java.sql.Statement execution."

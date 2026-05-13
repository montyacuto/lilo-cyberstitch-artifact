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
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isMethodNamesExecuteExecuteQueryExecuteUpdateSink(sink)
  }
}

module ThreatSqlStatementFlow = TaintTracking::Global<ThreatSqlStatementConfig>;
import ThreatSqlStatementFlow::PathGraph
import cyberstitch_helpers_java

from ThreatSqlStatementFlow::PathNode source, ThreatSqlStatementFlow::PathNode sink
where ThreatSqlStatementFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Threat-model source reaches java.sql.Statement execution."

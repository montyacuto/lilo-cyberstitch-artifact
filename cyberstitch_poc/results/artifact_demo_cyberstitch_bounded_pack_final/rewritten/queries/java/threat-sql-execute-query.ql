/**
 * @name Threat-model source reaches executeQuery argument sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-sql-execute-query
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

module ThreatSqlExecuteQueryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isMethodNamesExecuteQuerySink(sink)
  }
}

module ThreatSqlExecuteQueryFlow = TaintTracking::Global<ThreatSqlExecuteQueryConfig>;
import ThreatSqlExecuteQueryFlow::PathGraph
import cyberstitch_helpers_java

from ThreatSqlExecuteQueryFlow::PathNode source, ThreatSqlExecuteQueryFlow::PathNode sink
where ThreatSqlExecuteQueryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches executeQuery sink."

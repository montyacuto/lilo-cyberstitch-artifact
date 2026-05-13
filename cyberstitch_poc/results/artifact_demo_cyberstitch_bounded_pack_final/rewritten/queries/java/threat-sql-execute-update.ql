/**
 * @name Threat-model source reaches executeUpdate argument sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-sql-execute-update
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

module ThreatSqlExecuteUpdateConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isMethodNamesExecuteUpdateSink(sink)
  }
}

module ThreatSqlExecuteUpdateFlow = TaintTracking::Global<ThreatSqlExecuteUpdateConfig>;
import ThreatSqlExecuteUpdateFlow::PathGraph
import cyberstitch_helpers_java

from ThreatSqlExecuteUpdateFlow::PathNode source, ThreatSqlExecuteUpdateFlow::PathNode sink
where ThreatSqlExecuteUpdateFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches executeUpdate sink."

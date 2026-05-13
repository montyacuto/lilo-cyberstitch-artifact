/**
 * @name Threat-model source reaches sql-injection sink label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-sql-sink-node
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

module ThreatSqlSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "sql-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    barrierNode(node, "sql-injection")
  }
}

module ThreatSqlSinkNodeFlow = TaintTracking::Global<ThreatSqlSinkNodeConfig>;
import ThreatSqlSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from ThreatSqlSinkNodeFlow::PathNode source, ThreatSqlSinkNodeFlow::PathNode sink
where ThreatSqlSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches sinkNode:sql-injection sink."

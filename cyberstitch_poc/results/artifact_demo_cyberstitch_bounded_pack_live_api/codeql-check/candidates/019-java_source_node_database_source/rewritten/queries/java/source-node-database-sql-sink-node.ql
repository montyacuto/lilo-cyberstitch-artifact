/**
 * @name Database source label reaches sql-injection sink label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-database-sql-sink-node
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

module SourceNodeDatabaseSqlSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isSourceNodeDatabaseSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "sql-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    barrierNode(node, "sql-injection")
  }
}

module SourceNodeDatabaseSqlSinkNodeFlow = TaintTracking::Global<SourceNodeDatabaseSqlSinkNodeConfig>;
import SourceNodeDatabaseSqlSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from SourceNodeDatabaseSqlSinkNodeFlow::PathNode source, SourceNodeDatabaseSqlSinkNodeFlow::PathNode sink
where SourceNodeDatabaseSqlSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:database source reaches sinkNode:sql-injection sink."

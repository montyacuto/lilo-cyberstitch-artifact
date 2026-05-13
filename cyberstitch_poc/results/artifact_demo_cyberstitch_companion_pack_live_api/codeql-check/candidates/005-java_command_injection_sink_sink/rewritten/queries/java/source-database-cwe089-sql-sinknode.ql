/**
 * @name Database source node reaches SQL sink node
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/source-database-cwe089-sql-sinknode
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow

module SourceDatabaseSqlSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "database")
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "sql-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    barrierNode(node, "sql-injection")
  }
}

module SourceDatabaseSqlSinkNodeFlow = TaintTracking::Global<SourceDatabaseSqlSinkNodeConfig>;
import SourceDatabaseSqlSinkNodeFlow::PathGraph

from SourceDatabaseSqlSinkNodeFlow::PathNode source, SourceDatabaseSqlSinkNodeFlow::PathNode sink
where SourceDatabaseSqlSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Database source node reaches a SQL-injection sink node."

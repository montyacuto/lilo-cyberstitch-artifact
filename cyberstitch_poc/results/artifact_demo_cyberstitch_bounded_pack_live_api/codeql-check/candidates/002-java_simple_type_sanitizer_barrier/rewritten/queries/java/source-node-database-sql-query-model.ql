/**
 * @name Database source label reaches QueryInjectionSink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-database-sql-query-model
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

module SourceNodeDatabaseSqlQueryModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "database")
  }

  predicate isSink(DataFlow::Node sink) {
    exists(QueryInjectionSink query | sink = query)
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isSimpleTypeSanitizerBarrier(node)
  }
}

module SourceNodeDatabaseSqlQueryModelFlow = TaintTracking::Global<SourceNodeDatabaseSqlQueryModelConfig>;
import SourceNodeDatabaseSqlQueryModelFlow::PathGraph
import cyberstitch_helpers_java

from SourceNodeDatabaseSqlQueryModelFlow::PathNode source, SourceNodeDatabaseSqlQueryModelFlow::PathNode sink
where SourceNodeDatabaseSqlQueryModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:database source reaches QueryInjectionSink sink."

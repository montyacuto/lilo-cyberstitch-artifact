/**
 * @name External remote source label reaches sql-injection sink label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-remote-sql-sink-node
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

module SourceNodeRemoteSqlSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "remote")
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isSinkNodeSqlInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    barrierNode(node, "sql-injection")
  }
}

module SourceNodeRemoteSqlSinkNodeFlow = TaintTracking::Global<SourceNodeRemoteSqlSinkNodeConfig>;
import SourceNodeRemoteSqlSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from SourceNodeRemoteSqlSinkNodeFlow::PathNode source, SourceNodeRemoteSqlSinkNodeFlow::PathNode sink
where SourceNodeRemoteSqlSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:remote source reaches sinkNode:sql-injection sink."

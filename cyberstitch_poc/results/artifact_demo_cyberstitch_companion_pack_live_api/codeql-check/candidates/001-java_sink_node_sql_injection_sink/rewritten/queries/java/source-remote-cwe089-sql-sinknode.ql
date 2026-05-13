/**
 * @name Remote source node reaches SQL sink node
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/source-remote-cwe089-sql-sinknode
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow

module SourceRemoteSqlSinkNodeConfig implements DataFlow::ConfigSig {
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

module SourceRemoteSqlSinkNodeFlow = TaintTracking::Global<SourceRemoteSqlSinkNodeConfig>;
import SourceRemoteSqlSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from SourceRemoteSqlSinkNodeFlow::PathNode source, SourceRemoteSqlSinkNodeFlow::PathNode sink
where SourceRemoteSqlSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote source node reaches a SQL-injection sink node."

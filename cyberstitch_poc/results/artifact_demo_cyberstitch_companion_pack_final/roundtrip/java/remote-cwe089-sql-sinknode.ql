/**
 * @name Remote flow source reaches SQL sink node
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/remote-cwe089-sql-sinknode
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow

module RemoteSqlSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "sql-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    barrierNode(node, "sql-injection")
  }

}

module RemoteSqlSinkNodeFlow = TaintTracking::Global<RemoteSqlSinkNodeConfig>;
import RemoteSqlSinkNodeFlow::PathGraph

from RemoteSqlSinkNodeFlow::PathNode source, RemoteSqlSinkNodeFlow::PathNode sink
where RemoteSqlSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote flow source reaches a SQL-injection sink node."

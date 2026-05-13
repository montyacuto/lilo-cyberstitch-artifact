/**
 * @name Remote input reaches modeled SQL sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/remote-cwe089-sql-sinkmodel
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow

module RemoteSqlSinkModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "sql-injection")
  }

}

module RemoteSqlSinkModelFlow = TaintTracking::Global<RemoteSqlSinkModelConfig>;
import RemoteSqlSinkModelFlow::PathGraph

from RemoteSqlSinkModelFlow::PathNode source, RemoteSqlSinkModelFlow::PathNode sink
where RemoteSqlSinkModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches a modeled SQL-injection sink."

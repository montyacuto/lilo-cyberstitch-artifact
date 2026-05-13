/**
 * @name Remote input reaches sql-injection sink label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/remote-sql-sink-node
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

module RemoteSqlSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isSinkNodeSqlInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isBarrierNodeSqlInjectionBarrier(node)
  }
}

module RemoteSqlSinkNodeFlow = TaintTracking::Global<RemoteSqlSinkNodeConfig>;
import RemoteSqlSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from RemoteSqlSinkNodeFlow::PathNode source, RemoteSqlSinkNodeFlow::PathNode sink
where RemoteSqlSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "RemoteFlowSource source reaches sinkNode:sql-injection sink."

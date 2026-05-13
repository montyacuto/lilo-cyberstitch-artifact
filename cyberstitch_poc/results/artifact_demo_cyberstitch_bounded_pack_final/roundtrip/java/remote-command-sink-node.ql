/**
 * @name Remote input reaches command-injection sink model label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/remote-command-sink-node
 * @tags security external/cwe/cwe-078
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

module RemoteCommandSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "command-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    barrierNode(node, "command-injection")
  }

}

module RemoteCommandSinkNodeFlow = TaintTracking::Global<RemoteCommandSinkNodeConfig>;
import RemoteCommandSinkNodeFlow::PathGraph

from RemoteCommandSinkNodeFlow::PathNode source, RemoteCommandSinkNodeFlow::PathNode sink
where RemoteCommandSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "RemoteFlowSource source reaches sinkNode:command-injection sink."

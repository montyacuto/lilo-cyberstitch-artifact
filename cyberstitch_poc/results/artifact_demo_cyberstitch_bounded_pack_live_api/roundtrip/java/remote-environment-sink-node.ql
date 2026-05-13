/**
 * @name Remote input reaches environment-injection sink label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/remote-environment-sink-node
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

module RemoteEnvironmentSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "environment-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(ExecTaintedEnvironmentSanitizer sanitizer | node = sanitizer)
  }

}

module RemoteEnvironmentSinkNodeFlow = TaintTracking::Global<RemoteEnvironmentSinkNodeConfig>;
import RemoteEnvironmentSinkNodeFlow::PathGraph

from RemoteEnvironmentSinkNodeFlow::PathNode source, RemoteEnvironmentSinkNodeFlow::PathNode sink
where RemoteEnvironmentSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "RemoteFlowSource source reaches sinkNode:environment-injection sink."

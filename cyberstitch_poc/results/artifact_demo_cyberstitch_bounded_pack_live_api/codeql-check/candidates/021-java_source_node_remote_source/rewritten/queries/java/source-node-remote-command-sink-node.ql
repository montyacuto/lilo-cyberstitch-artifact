/**
 * @name External remote source label reaches command-injection sink label
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-remote-command-sink-node
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

module SourceNodeRemoteCommandSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isSourceNodeRemoteSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "command-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    barrierNode(node, "command-injection")
  }
}

module SourceNodeRemoteCommandSinkNodeFlow = TaintTracking::Global<SourceNodeRemoteCommandSinkNodeConfig>;
import SourceNodeRemoteCommandSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from SourceNodeRemoteCommandSinkNodeFlow::PathNode source, SourceNodeRemoteCommandSinkNodeFlow::PathNode sink
where SourceNodeRemoteCommandSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:remote source reaches sinkNode:command-injection sink."

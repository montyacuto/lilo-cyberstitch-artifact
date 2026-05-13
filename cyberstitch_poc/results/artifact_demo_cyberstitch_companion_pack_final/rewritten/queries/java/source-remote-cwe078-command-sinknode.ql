/**
 * @name Remote source node reaches command sink node
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/source-remote-cwe078-command-sinknode
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow

module SourceRemoteCommandSinkNodeConfig implements DataFlow::ConfigSig {
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

module SourceRemoteCommandSinkNodeFlow = TaintTracking::Global<SourceRemoteCommandSinkNodeConfig>;
import SourceRemoteCommandSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from SourceRemoteCommandSinkNodeFlow::PathNode source, SourceRemoteCommandSinkNodeFlow::PathNode sink
where SourceRemoteCommandSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote source node reaches a command-injection sink node."

/**
 * @name Remote source node reaches modeled command sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/source-remote-cwe078-command-model
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.CommandLineQuery

module SourceRemoteCommandModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "remote")
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | sink = command)
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isCommandInjectionSanitizerBarrier(node)
  }
}

module SourceRemoteCommandModelFlow = TaintTracking::Global<SourceRemoteCommandModelConfig>;
import SourceRemoteCommandModelFlow::PathGraph
import cyberstitch_helpers_java

from SourceRemoteCommandModelFlow::PathNode source, SourceRemoteCommandModelFlow::PathNode sink
where SourceRemoteCommandModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote source node reaches a modeled command-injection sink."

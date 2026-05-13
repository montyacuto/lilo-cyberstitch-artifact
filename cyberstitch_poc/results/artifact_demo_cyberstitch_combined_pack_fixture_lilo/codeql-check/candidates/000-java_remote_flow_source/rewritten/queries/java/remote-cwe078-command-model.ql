/**
 * @name Remote input reaches modeled command execution
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/remote-cwe078-command-model
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.CommandLineQuery

module RemoteCommandModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isRemoteFlowSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | sink = command)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(CommandInjectionSanitizer sanitizer | node = sanitizer)
  }
}

module RemoteCommandModelFlow = TaintTracking::Global<RemoteCommandModelConfig>;
import RemoteCommandModelFlow::PathGraph
import cyberstitch_helpers_java

from RemoteCommandModelFlow::PathNode source, RemoteCommandModelFlow::PathNode sink
where RemoteCommandModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches a modeled command-injection sink."

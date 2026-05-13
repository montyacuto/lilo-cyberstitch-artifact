/**
 * @name Remote source node reaches environment injection sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/source-remote-cwe078-environment-sinknode
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.TaintedEnvironmentVariableQuery

module SourceRemoteEnvironmentInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "remote")
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isSinkNodeEnvironmentInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(ExecTaintedEnvironmentSanitizer sanitizer | node = sanitizer)
  }
}

module SourceRemoteEnvironmentInjectionFlow = TaintTracking::Global<SourceRemoteEnvironmentInjectionConfig>;
import SourceRemoteEnvironmentInjectionFlow::PathGraph
import cyberstitch_helpers_java

from SourceRemoteEnvironmentInjectionFlow::PathNode source, SourceRemoteEnvironmentInjectionFlow::PathNode sink
where SourceRemoteEnvironmentInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote source node reaches an environment-injection sink."

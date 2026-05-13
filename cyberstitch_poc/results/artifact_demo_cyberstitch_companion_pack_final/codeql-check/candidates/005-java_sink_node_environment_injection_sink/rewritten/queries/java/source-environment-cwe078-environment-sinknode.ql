/**
 * @name Environment source node reaches environment injection sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/source-environment-cwe078-environment-sinknode
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.TaintedEnvironmentVariableQuery

module SourceEnvironmentInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "environment")
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isSinkNodeEnvironmentInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(ExecTaintedEnvironmentSanitizer sanitizer | node = sanitizer)
  }
}

module SourceEnvironmentInjectionFlow = TaintTracking::Global<SourceEnvironmentInjectionConfig>;
import SourceEnvironmentInjectionFlow::PathGraph
import cyberstitch_helpers_java

from SourceEnvironmentInjectionFlow::PathNode source, SourceEnvironmentInjectionFlow::PathNode sink
where SourceEnvironmentInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Environment source node reaches an environment-injection sink."

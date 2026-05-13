/**
 * @name Remote input reaches modeled query execution
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/remote-cwe089-query-model
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.Sanitizers

module RemoteQueryModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isRemoteFlowSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isQueryInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(SimpleTypeSanitizer sanitizer | node = sanitizer)
  }
}

module RemoteQueryModelFlow = TaintTracking::Global<RemoteQueryModelConfig>;
import RemoteQueryModelFlow::PathGraph
import cyberstitch_helpers_java

from RemoteQueryModelFlow::PathNode source, RemoteQueryModelFlow::PathNode sink
where RemoteQueryModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches a modeled query-injection sink."

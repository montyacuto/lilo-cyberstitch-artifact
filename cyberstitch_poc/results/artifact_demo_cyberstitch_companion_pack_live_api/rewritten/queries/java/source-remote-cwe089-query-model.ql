/**
 * @name Remote source node reaches modeled query injection sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/source-remote-cwe089-query-model
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.SqlInjectionQuery
import semmle.code.java.security.Sanitizers

module SourceRemoteQueryModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isSourceNodeRemoteSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isQueryInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isSimpleTypeSanitizerBarrier(node)
  }
}

module SourceRemoteQueryModelFlow = TaintTracking::Global<SourceRemoteQueryModelConfig>;
import SourceRemoteQueryModelFlow::PathGraph
import cyberstitch_helpers_java

from SourceRemoteQueryModelFlow::PathNode source, SourceRemoteQueryModelFlow::PathNode sink
where SourceRemoteQueryModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote source node reaches a query-injection sink."

/**
 * @name Database source node reaches modeled query injection sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/source-database-cwe089-query-model
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.SqlInjectionQuery
import semmle.code.java.security.Sanitizers

module SourceDatabaseQueryModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isSourceNodeDatabaseSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isQueryInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isSimpleTypeSanitizerBarrier(node)
  }
}

module SourceDatabaseQueryModelFlow = TaintTracking::Global<SourceDatabaseQueryModelConfig>;
import SourceDatabaseQueryModelFlow::PathGraph
import cyberstitch_helpers_java

from SourceDatabaseQueryModelFlow::PathNode source, SourceDatabaseQueryModelFlow::PathNode sink
where SourceDatabaseQueryModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Database source node reaches a query-injection sink."

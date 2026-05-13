/**
 * @name External remote source label reaches QueryInjectionSink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-remote-sql-query-model
 * @tags security external/cwe/cwe-089
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

module SourceNodeRemoteSqlQueryModelConfig implements DataFlow::ConfigSig {
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

module SourceNodeRemoteSqlQueryModelFlow = TaintTracking::Global<SourceNodeRemoteSqlQueryModelConfig>;
import SourceNodeRemoteSqlQueryModelFlow::PathGraph
import cyberstitch_helpers_java

from SourceNodeRemoteSqlQueryModelFlow::PathNode source, SourceNodeRemoteSqlQueryModelFlow::PathNode sink
where SourceNodeRemoteSqlQueryModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:remote source reaches QueryInjectionSink sink."

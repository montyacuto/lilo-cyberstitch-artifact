/**
 * @name Remote input reaches QueryInjectionSink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/remote-sql-query-model
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

module RemoteSqlQueryModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isQueryInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(SimpleTypeSanitizer sanitizer | node = sanitizer)
  }
}

module RemoteSqlQueryModelFlow = TaintTracking::Global<RemoteSqlQueryModelConfig>;
import RemoteSqlQueryModelFlow::PathGraph
import cyberstitch_helpers_java

from RemoteSqlQueryModelFlow::PathNode source, RemoteSqlQueryModelFlow::PathNode sink
where RemoteSqlQueryModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "RemoteFlowSource source reaches QueryInjectionSink sink."

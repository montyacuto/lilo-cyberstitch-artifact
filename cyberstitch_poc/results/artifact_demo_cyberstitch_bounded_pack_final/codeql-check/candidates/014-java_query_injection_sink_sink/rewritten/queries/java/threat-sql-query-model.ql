/**
 * @name Threat-model source reaches QueryInjectionSink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-sql-query-model
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

module ThreatSqlQueryModelConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isQueryInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(SimpleTypeSanitizer sanitizer | node = sanitizer)
  }
}

module ThreatSqlQueryModelFlow = TaintTracking::Global<ThreatSqlQueryModelConfig>;
import ThreatSqlQueryModelFlow::PathGraph
import cyberstitch_helpers_java

from ThreatSqlQueryModelFlow::PathNode source, ThreatSqlQueryModelFlow::PathNode sink
where ThreatSqlQueryModelFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches QueryInjectionSink sink."

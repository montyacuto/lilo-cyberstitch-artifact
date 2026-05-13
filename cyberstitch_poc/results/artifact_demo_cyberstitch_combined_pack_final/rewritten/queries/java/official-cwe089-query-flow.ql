/**
 * @name Official CodeQL SQL injection source to sink flow
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-cwe089-query-flow
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.SqlInjectionQuery

module CyberStitchOfficialSqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isQueryInjectionSink(sink)
  }
}

module CyberStitchOfficialSqlFlow = TaintTracking::Global<CyberStitchOfficialSqlConfig>;
import CyberStitchOfficialSqlFlow::PathGraph
import cyberstitch_helpers_java

from CyberStitchOfficialSqlFlow::PathNode source, CyberStitchOfficialSqlFlow::PathNode sink
where CyberStitchOfficialSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Official CodeQL source reaches query-injection sink."

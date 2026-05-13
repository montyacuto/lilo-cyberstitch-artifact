/**
 * @name Active threat model source reaches SQL sink node
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/threat-cwe089-sql-sinknode
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow

module ThreatSqlSinkNodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "sql-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isBarrierNodeSqlInjectionBarrier(node)
  }
}

module ThreatSqlSinkNodeFlow = TaintTracking::Global<ThreatSqlSinkNodeConfig>;
import ThreatSqlSinkNodeFlow::PathGraph
import cyberstitch_helpers_java

from ThreatSqlSinkNodeFlow::PathNode source, ThreatSqlSinkNodeFlow::PathNode sink
where ThreatSqlSinkNodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Threat-model source reaches a SQL-injection sink node."

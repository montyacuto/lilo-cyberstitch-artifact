/**
 * @name Active threat model source reaches Runtime.exec
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/threat-cwe078-runtime-exec
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ThreatRuntimeExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isJavaLangRuntimeExecSink(sink)
  }
}

module ThreatRuntimeExecFlow = TaintTracking::Global<ThreatRuntimeExecConfig>;
import ThreatRuntimeExecFlow::PathGraph
import cyberstitch_helpers_java

from ThreatRuntimeExecFlow::PathNode source, ThreatRuntimeExecFlow::PathNode sink
where ThreatRuntimeExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Threat-model source reaches Runtime.exec."

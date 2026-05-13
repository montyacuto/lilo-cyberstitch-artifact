/**
 * @name Official CodeQL environment variable command injection flow
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-cwe078-environment-flow
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.TaintedEnvironmentVariableQuery

module CyberStitchOfficialEnvironmentConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "environment-injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isExecTaintedEnvironmentSanitizerBarrier(node)
  }
}

module CyberStitchOfficialEnvironmentFlow = TaintTracking::Global<CyberStitchOfficialEnvironmentConfig>;
import CyberStitchOfficialEnvironmentFlow::PathGraph
import cyberstitch_helpers_java

from CyberStitchOfficialEnvironmentFlow::PathNode source, CyberStitchOfficialEnvironmentFlow::PathNode sink
where CyberStitchOfficialEnvironmentFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Official CodeQL source reaches an environment-injection sink."

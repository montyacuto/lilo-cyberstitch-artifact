/**
 * @name OWASP remote input reaches command execution
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/owasp-cwe078-command
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module OwaspCommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isJavaLangRuntimeExecSink(sink)
  }
}

module OwaspCommandInjectionFlow = TaintTracking::Global<OwaspCommandInjectionConfig>;
import OwaspCommandInjectionFlow::PathGraph
import cyberstitch_helpers_java

from OwaspCommandInjectionFlow::PathNode source, OwaspCommandInjectionFlow::PathNode sink
where OwaspCommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches Runtime.exec."

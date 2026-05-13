/**
 * @name Official CodeQL command injection source to sink flow
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-cwe078-command-flow
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.CommandLineQuery

module CyberStitchOfficialCommandConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | sink = command)
  }

  predicate isBarrier(DataFlow::Node node) {
    CyberStitchJavaHelpers::isCommandInjectionSanitizerBarrier(node)
  }
}

module CyberStitchOfficialCommandFlow = TaintTracking::Global<CyberStitchOfficialCommandConfig>;
import CyberStitchOfficialCommandFlow::PathGraph
import cyberstitch_helpers_java

from CyberStitchOfficialCommandFlow::PathNode source, CyberStitchOfficialCommandFlow::PathNode sink
where CyberStitchOfficialCommandFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Official CodeQL source reaches command-injection sink."

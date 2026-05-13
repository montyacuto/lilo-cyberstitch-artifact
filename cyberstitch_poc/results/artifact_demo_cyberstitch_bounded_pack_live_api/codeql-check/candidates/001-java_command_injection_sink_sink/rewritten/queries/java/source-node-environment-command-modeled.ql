/**
 * @name Environment source label reaches CommandInjectionSink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-environment-command-modeled
 * @tags security external/cwe/cwe-078
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

module SourceNodeEnvironmentCommandModeledConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "environment")
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isCommandInjectionSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(CommandInjectionSanitizer sanitizer | node = sanitizer)
  }
}

module SourceNodeEnvironmentCommandModeledFlow = TaintTracking::Global<SourceNodeEnvironmentCommandModeledConfig>;
import SourceNodeEnvironmentCommandModeledFlow::PathGraph
import cyberstitch_helpers_java

from SourceNodeEnvironmentCommandModeledFlow::PathNode source, SourceNodeEnvironmentCommandModeledFlow::PathNode sink
where SourceNodeEnvironmentCommandModeledFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:environment source reaches CommandInjectionSink sink."

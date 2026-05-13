/**
 * @name External remote source label reaches CommandInjectionSink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-remote-command-modeled
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

module SourceNodeRemoteCommandModeledConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "remote")
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | sink = command)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(CommandInjectionSanitizer sanitizer | node = sanitizer)
  }
}

module SourceNodeRemoteCommandModeledFlow = TaintTracking::Global<SourceNodeRemoteCommandModeledConfig>;
import SourceNodeRemoteCommandModeledFlow::PathGraph

from SourceNodeRemoteCommandModeledFlow::PathNode source, SourceNodeRemoteCommandModeledFlow::PathNode sink
where SourceNodeRemoteCommandModeledFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:remote source reaches CommandInjectionSink sink."

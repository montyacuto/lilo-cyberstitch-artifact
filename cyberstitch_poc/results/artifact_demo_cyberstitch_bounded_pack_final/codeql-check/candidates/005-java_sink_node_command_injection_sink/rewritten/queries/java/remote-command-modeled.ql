/**
 * @name Remote input reaches CommandInjectionSink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/remote-command-modeled
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

module RemoteCommandModeledConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | sink = command)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(CommandInjectionSanitizer sanitizer | node = sanitizer)
  }
}

module RemoteCommandModeledFlow = TaintTracking::Global<RemoteCommandModeledConfig>;
import RemoteCommandModeledFlow::PathGraph

from RemoteCommandModeledFlow::PathNode source, RemoteCommandModeledFlow::PathNode sink
where RemoteCommandModeledFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "RemoteFlowSource source reaches CommandInjectionSink sink."

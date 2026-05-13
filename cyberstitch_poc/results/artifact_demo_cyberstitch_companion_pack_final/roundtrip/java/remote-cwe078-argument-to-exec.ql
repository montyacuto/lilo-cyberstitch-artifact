/**
 * @name Remote input reaches argumentToExec command sink
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/official-expanded/remote-cwe078-argument-to-exec
 * @tags security external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.CommandLineQuery
import semmle.code.java.security.ExternalProcess

module RemoteArgumentToExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | argumentToExec(sink.asExpr(), command))
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(CommandInjectionSanitizer sanitizer | node = sanitizer)
  }

}

module RemoteArgumentToExecFlow = TaintTracking::Global<RemoteArgumentToExecConfig>;
import RemoteArgumentToExecFlow::PathGraph

from RemoteArgumentToExecFlow::PathNode source, RemoteArgumentToExecFlow::PathNode sink
where RemoteArgumentToExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches an argumentToExec command sink."

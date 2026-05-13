/**
 * @name Remote input reaches Runtime.exec
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/remote-command-runtime-exec
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

module RemoteCommandRuntimeExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isJavaLangRuntimeExecSink(sink)
  }
}

module RemoteCommandRuntimeExecFlow = TaintTracking::Global<RemoteCommandRuntimeExecConfig>;
import RemoteCommandRuntimeExecFlow::PathGraph
import cyberstitch_helpers_java

from RemoteCommandRuntimeExecFlow::PathNode source, RemoteCommandRuntimeExecFlow::PathNode sink
where RemoteCommandRuntimeExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "RemoteFlowSource source reaches java.lang.Runtime.exec sink."

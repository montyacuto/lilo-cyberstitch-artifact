/**
 * @name Remote input reaches child_process.exec
 * @kind path-problem
 * @problem.severity error
 * @id js/cyberstitch/remote-to-exec
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

module RemoteToExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Express::RouteHandler rh | source = rh.getARequest())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef("child_process").getAMemberCall("exec") and
      sink = call.getArgument(0)
    )
  }
}

module RemoteToExecFlow = TaintTracking::Global<RemoteToExecConfig>;

from RemoteToExecFlow::PathNode source, RemoteToExecFlow::PathNode sink
where RemoteToExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches child_process.exec."

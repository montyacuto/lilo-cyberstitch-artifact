/**
 * @name Remote input reaches child_process.execSync
 * @kind path-problem
 * @problem.severity error
 * @id js/cyberstitch/remote-to-exec-sync
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

module RemoteToExecSyncConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Express::RouteHandler rh | source = rh.getARequest())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef("child_process").getAMemberCall("execSync") and
      sink = call.getArgument(0)
    )
  }
}

module RemoteToExecSyncFlow = TaintTracking::Global<RemoteToExecSyncConfig>;

from RemoteToExecSyncFlow::PathNode source, RemoteToExecSyncFlow::PathNode sink
where RemoteToExecSyncFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches child_process.execSync."

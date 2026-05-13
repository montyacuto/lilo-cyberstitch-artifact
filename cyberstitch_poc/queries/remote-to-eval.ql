/**
 * @name Remote input reaches eval
 * @kind path-problem
 * @problem.severity error
 * @id js/cyberstitch/remote-to-eval
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

module RemoteToEvalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Express::RouteHandler rh | source = rh.getARequest())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call = DataFlow::globalVarRef("eval").getACall() and
      sink = call.getArgument(0)
    )
  }
}

module RemoteToEvalFlow = TaintTracking::Global<RemoteToEvalConfig>;

from RemoteToEvalFlow::PathNode source, RemoteToEvalFlow::PathNode sink
where RemoteToEvalFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches eval."

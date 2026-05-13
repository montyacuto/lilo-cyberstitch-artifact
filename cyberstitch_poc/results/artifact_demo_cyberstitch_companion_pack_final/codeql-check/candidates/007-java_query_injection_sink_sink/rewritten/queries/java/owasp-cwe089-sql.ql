/**
 * @name OWASP remote input reaches SQL execution
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/owasp-cwe089-sql
 * @tags security external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module OwaspSqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().hasName("execute") and
      sink.asExpr() = call.getArgument(0)
      or
      call.getMethod().hasName("executeQuery") and
      sink.asExpr() = call.getArgument(0)
      or
      call.getMethod().hasName("executeUpdate") and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

module OwaspSqlInjectionFlow = TaintTracking::Global<OwaspSqlInjectionConfig>;
import OwaspSqlInjectionFlow::PathGraph

from OwaspSqlInjectionFlow::PathNode source, OwaspSqlInjectionFlow::PathNode sink
where OwaspSqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote input reaches java.sql.Statement execution."

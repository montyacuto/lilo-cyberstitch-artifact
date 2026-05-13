/**
 * @name Threat-model source reaches Mongo BasicDBObject.parse
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/threat-sql-mongo-parse
 * @tags security external/cwe/cwe-089
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

module ThreatSqlMongoParseConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    CyberStitchJavaHelpers::isActiveThreatModelSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().hasQualifiedName("com.mongodb", "BasicDBObject", "parse") and
      sink.asExpr() = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(SimpleTypeSanitizer sanitizer | node = sanitizer)
  }
}

module ThreatSqlMongoParseFlow = TaintTracking::Global<ThreatSqlMongoParseConfig>;
import ThreatSqlMongoParseFlow::PathGraph
import cyberstitch_helpers_java

from ThreatSqlMongoParseFlow::PathNode source, ThreatSqlMongoParseFlow::PathNode sink
where ThreatSqlMongoParseFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "ActiveThreatModelSource source reaches com.mongodb.BasicDBObject.parse sink."

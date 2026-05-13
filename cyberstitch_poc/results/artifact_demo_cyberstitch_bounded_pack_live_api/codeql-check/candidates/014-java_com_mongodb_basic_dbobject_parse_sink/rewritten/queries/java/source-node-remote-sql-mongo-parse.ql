/**
 * @name External remote source label reaches Mongo BasicDBObject.parse
 * @kind path-problem
 * @problem.severity error
 * @id java/cyberstitch/bounded/source-node-remote-sql-mongo-parse
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

module SourceNodeRemoteSqlMongoParseConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    sourceNode(source, "remote")
  }

  predicate isSink(DataFlow::Node sink) {
    CyberStitchJavaHelpers::isComMongodbBasicDbobjectParseSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(SimpleTypeSanitizer sanitizer | node = sanitizer)
  }
}

module SourceNodeRemoteSqlMongoParseFlow = TaintTracking::Global<SourceNodeRemoteSqlMongoParseConfig>;
import SourceNodeRemoteSqlMongoParseFlow::PathGraph
import cyberstitch_helpers_java

from SourceNodeRemoteSqlMongoParseFlow::PathNode source, SourceNodeRemoteSqlMongoParseFlow::PathNode sink
where SourceNodeRemoteSqlMongoParseFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "sourceNode:remote source reaches com.mongodb.BasicDBObject.parse sink."

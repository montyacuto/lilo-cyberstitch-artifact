import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.CommandLineQuery
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.Sanitizers
import semmle.code.java.security.SqlInjectionQuery
import semmle.code.java.security.TaintedEnvironmentVariableQuery

module CyberStitchJavaHelpers {
  predicate isRemoteFlowSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  predicate isCommandInjectionSink(DataFlow::Node sink) {
    exists(CommandInjectionSink command | argumentToExec(sink.asExpr(), command))
  }

  predicate isCommandInjectionSanitizerBarrier(DataFlow::Node node) {
    exists(CommandInjectionSanitizer sanitizer | node = sanitizer)
  }

  predicate isJavaLangRuntimeExecSink(DataFlow::Node sink) {
    exists(MethodCall call | call.getMethod().hasQualifiedName("java.lang", "Runtime", "exec") and sink.asExpr() = call.getArgument(0))
  }

  predicate isSinkNodeCommandInjectionSink(DataFlow::Node sink) {
    sinkNode(sink, "command-injection")
  }

  predicate isBarrierNodeCommandInjectionBarrier(DataFlow::Node node) {
    barrierNode(node, "command-injection")
  }

  predicate isSinkNodeEnvironmentInjectionSink(DataFlow::Node sink) {
    sinkNode(sink, "environment-injection")
  }

  predicate isExecTaintedEnvironmentSanitizerBarrier(DataFlow::Node node) {
    exists(ExecTaintedEnvironmentSanitizer sanitizer | node = sanitizer)
  }

  predicate isMethodNamesExecuteQuerySink(DataFlow::Node sink) {
    exists(MethodCall call | call.getMethod().hasName("executeQuery") and sink.asExpr() = call.getArgument(0))
  }

  predicate isMethodNamesExecuteUpdateSink(DataFlow::Node sink) {
    exists(MethodCall call | call.getMethod().hasName("executeUpdate") and sink.asExpr() = call.getArgument(0))
  }

  predicate isMethodNamesExecuteSink(DataFlow::Node sink) {
    exists(MethodCall call | call.getMethod().hasName("execute") and sink.asExpr() = call.getArgument(0))
  }

  predicate isComMongodbBasicDbobjectParseSink(DataFlow::Node sink) {
    exists(MethodCall call | call.getMethod().hasQualifiedName("com.mongodb", "BasicDBObject", "parse") and sink.asExpr() = call.getArgument(0))
  }

  predicate isSimpleTypeSanitizerBarrier(DataFlow::Node node) {
    exists(SimpleTypeSanitizer sanitizer | node = sanitizer)
  }

  predicate isQueryInjectionSink(DataFlow::Node sink) {
    exists(QueryInjectionSink query | sink = query)
  }

  predicate isSinkNodeSqlInjectionSink(DataFlow::Node sink) {
    sinkNode(sink, "sql-injection")
  }

  predicate isBarrierNodeSqlInjectionBarrier(DataFlow::Node node) {
    barrierNode(node, "sql-injection")
  }

  predicate isMethodNamesExecuteExecuteQueryExecuteUpdateSink(DataFlow::Node sink) {
    exists(MethodCall call | call.getMethod().hasName("execute") and sink.asExpr() = call.getArgument(0) or call.getMethod().hasName("executeQuery") and sink.asExpr() = call.getArgument(0) or call.getMethod().hasName("executeUpdate") and sink.asExpr() = call.getArgument(0))
  }

  predicate isSourceNodeDatabaseSource(DataFlow::Node source) {
    sourceNode(source, "database")
  }

  predicate isSourceNodeEnvironmentSource(DataFlow::Node source) {
    sourceNode(source, "environment")
  }

  predicate isSourceNodeRemoteSource(DataFlow::Node source) {
    sourceNode(source, "remote")
  }

  predicate isActiveThreatModelSource(DataFlow::Node source) {
    exists(ActiveThreatModelSource remote | source = remote)
  }

}

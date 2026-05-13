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
  predicate isCommandInjectionSanitizerBarrier(DataFlow::Node node) {
    exists(CommandInjectionSanitizer sanitizer | node = sanitizer)
  }

}

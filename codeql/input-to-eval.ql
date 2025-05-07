/**
 * @name User input to eval
 * @description Using user-controlled input in eval() can lead to code injection.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id py/user-input-to-eval
 * @tags security
 *       external/cwe/cwe-094
 */

import python
import semmle.python.dataflow.new.DataFlow

module SensitiveLoggerConfig implements DataFlow::ConfigSig {  // 1: module always implements DataFlow::ConfigSig or DataFlow::StateConfigSig
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CredentialExpr } // 3: no need to specify 'override'
  predicate isSink(DataFlow::Node sink) { sinkNode(sink, "log-injection") }

  predicate isBarrier(DataFlow::Node sanitizer) {  // 4: 'isBarrier' replaces 'isSanitizer'
    sanitizer.asExpr() instanceof LiveLiteral or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof NumberType or
    sanitizer.getType() instanceof TypeType
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) } // 4: isBarrierIn instead of isSanitizerIn

}

module SensitiveLoggerFlow = TaintTracking::Global<SensitiveLoggerConfig>; // 2: TaintTracking selected 

import SensitiveLoggerFlow::PathGraph  // 7: the PathGraph specific to the module you are using

from SensitiveLoggerFlow::PathNode source, SensitiveLoggerFlow::PathNode sink  // 8 & 9: using the module directly
where SensitiveLoggerFlow::flowPath(source, sink)  // 9: using the flowPath from the module 
select sink.getNode(), source, sink, "This $@ is written to a log file.", source.getNode(),
  "potentially sensitive information"

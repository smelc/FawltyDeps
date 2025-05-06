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

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    exists(CallNode call |
      call = this.getAstNode() and
      call.getFunction().toString() = "input"
    )
  }
}

class EvalSink extends DataFlow::Node {
  EvalSink() {
    exists(CallNode call |
      call.getFunction().toString() = "eval" and
      call.getArg(0) = this.getAstNode()
    )
  }
}

class UserInputToEvalConfig extends TaintTracking::Configuration {
  UserInputToEvalConfig() { this = "UserInputToEvalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof EvalSink
  }
}

from UserInputToEvalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Calling eval with user input from $@", source.getNode(), "this input"
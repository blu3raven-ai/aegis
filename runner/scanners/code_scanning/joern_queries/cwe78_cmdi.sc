// CWE-78 — OS Command Injection
// Source: HTTP request parameters, env vars.
// Sink:   os.system, subprocess.run with shell=True, child_process.exec.
// Sanitizer: subprocess in list form, allow-list check.
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._

def jsonEscape(s: String): String = s
  .replace("\\", "\\\\")
  .replace("\"", "\\\"")
  .replace("\n", "\\n")
  .replace("\r", "\\r")
  .replace("\t", "\\t")

@main def main(cpgFile: String, outFile: String): Unit = {
  importCpg(cpgFile)

  // Source: Flask-style HTTP request accessor expressions like
  // `request.args.get("host")`. Matches the call node directly because Python
  // globals (`request`) are not method parameters.
  val sources = cpg.call.code("request\\.(args|form|json|values|headers|cookies|data|files|environ|params|body)\\..*")
  // First-position sink only: shell=True invocations pass the full command as arg 1.
  // Safe list-form `subprocess.run(["ping", ..., host])` builds the list before the
  // sink call, so a list literal reaches arg 1 — we treat the list literal at arg 1
  // as a sanitizer (each element is shell-escaped by the runtime), excluding flows
  // whose sink-position argument is a list/tuple literal expression.
  val sinks = cpg.call.name("system|popen|exec|spawn|run|call|check_output|check_call|Popen").argument
    .where(_.argumentIndex(1))
    .whereNot(_.code("\\[.*\\]"))

  val flows = sinks.reachableByFlows(sources)

  import java.io._
  val pw = new PrintWriter(new File(outFile))
  try {
    flows.foreach { flow =>
      val sink = flow.elements.last
      val source = flow.elements.head
      val trace = flow.elements.map { node =>
        s"""{"file":"${jsonEscape(node.file.name.headOption.getOrElse(""))}","line":${node.lineNumber.getOrElse(0)},"snippet":"${jsonEscape(node.code)}","role":"${if (node == source) "source" else if (node == sink) "sink" else "intermediate"}"}"""
      }.mkString("[", ",", "]")
      pw.println(s"""{"cwe":"CWE-78","file":"${jsonEscape(sink.file.name.headOption.getOrElse(""))}","line":${sink.lineNumber.getOrElse(0)},"rule_id":"joern-cmdi","severity":"critical","title":"OS Command Injection","dataflow_trace":${trace}}""")
    }
  } finally pw.close()
}

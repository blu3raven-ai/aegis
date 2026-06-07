// CWE-22 — Path Traversal
// Source: HTTP request parameters, headers.
// Sink:   open / fs.readFile / Path.resolve / java.io.File constructors.
// Sanitizer: path normalization + allow-list root check.
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
  // `request.args.get("name")`. Matches the call node directly because Python
  // globals (`request`) are not method parameters.
  val sources = cpg.call.code("request\\.(args|form|json|values|headers|cookies|data|files|environ|params|body)\\..*")
  // First-position sink only — the file path is arg 1. Safe code paths normalize
  // user input through `os.path.realpath` and gate it with a `startswith` root
  // check; we treat both as sanitizers and drop flows that pass through either.
  val sinks = cpg.call.name("open|readFile|readFileSync|resolve").argument
    .where(_.argumentIndex(1))

  val flows = sinks.reachableByFlows(sources).filterNot { flow =>
    flow.elements.exists { node =>
      val c = node.code
      c.contains("realpath") || c.contains("abspath") || c.contains(".startswith")
    }
  }

  import java.io._
  val pw = new PrintWriter(new File(outFile))
  try {
    flows.foreach { flow =>
      val sink = flow.elements.last
      val source = flow.elements.head
      val trace = flow.elements.map { node =>
        s"""{"file":"${jsonEscape(node.file.name.headOption.getOrElse(""))}","line":${node.lineNumber.getOrElse(0)},"snippet":"${jsonEscape(node.code)}","role":"${if (node == source) "source" else if (node == sink) "sink" else "intermediate"}"}"""
      }.mkString("[", ",", "]")
      pw.println(s"""{"cwe":"CWE-22","file":"${jsonEscape(sink.file.name.headOption.getOrElse(""))}","line":${sink.lineNumber.getOrElse(0)},"rule_id":"joern-path","severity":"high","title":"Path Traversal","dataflow_trace":${trace}}""")
    }
  } finally pw.close()
}

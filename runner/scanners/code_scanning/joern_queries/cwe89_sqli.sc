// CWE-89 — SQL Injection
// Source: HTTP request parameters and query strings.
// Sink:   db.execute / cursor.execute / raw query builders.
// Sanitizer: parameterized query API (psycopg2 named params, sqlalchemy
//            .params(), prepared statements).
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
  // `request.args.get("id")`, `request.form.get(...)`, `request.json[...]`.
  // Joern's Python frontend models these as call nodes whose `.code` starts with
  // `request.<attr>.`, so we match on the call expression directly rather than
  // method parameters (Python globals are not method params).
  val sources = cpg.call.code("request\\.(args|form|json|values|headers|cookies|data|files|environ|params|body)\\..*")
  // First-position sink only — query string is arg 1; bound-parameters tuple is arg 2.
  // Parameterized queries (db.execute("... WHERE id = ?", (user_id,))) keep the taint
  // in arg 2 and don't reach the arg-1 sink, so safe patterns naturally won't match.
  val sinks = cpg.call.name("execute|executemany|raw|query").argument
    .where(_.argumentIndex(1))

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
      pw.println(s"""{"cwe":"CWE-89","file":"${jsonEscape(sink.file.name.headOption.getOrElse(""))}","line":${sink.lineNumber.getOrElse(0)},"rule_id":"joern-sqli","severity":"high","title":"SQL Injection","dataflow_trace":${trace}}""")
    }
  } finally pw.close()
}

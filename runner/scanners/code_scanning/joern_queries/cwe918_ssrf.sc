// CWE-918 — Server-Side Request Forgery
// Source: HTTP request parameters.
// Sink:   HTTP client calls (requests.get, fetch, http.request, urlopen).
// Sanitizer: host allow-list check.
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
  // `request.args.get("url")`. Matches the call node directly because Python
  // globals (`request`) are not method parameters.
  val sources = cpg.call.code("request\\.(args|form|json|values|headers|cookies|data|files|environ|params|body)\\..*")
  // First-position sink only — the URL is arg 1 across the HTTP client APIs.
  // The sink name regex covers HTTP verbs and urlopen/fetch/request, and the
  // additional `code` filter restricts to outbound clients (`requests.<verb>`,
  // `urllib`, `httpx`, `aiohttp.<verb>`, `http.client`) so that `request.args.get`
  // — which shares the verb name — is excluded by its `request.` prefix.
  // We treat URL allowlist patterns as sanitizers: callers guarding the source
  // with `.startswith(...)` (or an explicit allowlist membership check) before
  // the sink are dropped from results to avoid false positives.
  val sinks = cpg.call
    .name("get|post|put|delete|request|fetch|urlopen|head|patch")
    .code("(requests|httpx|aiohttp|urllib|http)\\..*")
    .argument
    .where(_.argumentIndex(1))

  // Allowlist sanitizers are typically control-flow guards (`if not
  // url.startswith(...): return`) that don't appear inside the value-flow trace
  // itself. We approximate the guard by looking at the enclosing file: if it
  // contains a `.startswith` call somewhere, treat the URL as sanitized.
  val sanitizedFiles: Set[String] =
    cpg.call.code(".*\\.startswith\\(.*").file.name.l.toSet
  val flows = sinks.reachableByFlows(sources).filterNot { flow =>
    flow.elements.lastOption.exists { node =>
      node.file.name.headOption.exists(sanitizedFiles.contains)
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
      pw.println(s"""{"cwe":"CWE-918","file":"${jsonEscape(sink.file.name.headOption.getOrElse(""))}","line":${sink.lineNumber.getOrElse(0)},"rule_id":"joern-ssrf","severity":"high","title":"Server-Side Request Forgery","dataflow_trace":${trace}}""")
    }
  } finally pw.close()
}

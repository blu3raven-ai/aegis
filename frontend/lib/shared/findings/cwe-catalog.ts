/**
 * Curated catalog of the CWE weaknesses SAST scanners most often emit, with a
 * short analyst-facing description and MITRE's "Likelihood of Exploit" where it
 * is rated. Lets the drawer explain a weakness class inline instead of making
 * the analyst leave for cwe.mitre.org. Not exhaustive — `cweInfo` returns null
 * for ids we don't cover, and the drawer falls back to the bare MITRE link.
 */

export type CweLikelihood = "High" | "Medium" | "Low"

export interface CweInfo {
  name: string
  /** MITRE "Likelihood of Exploit", when rated. */
  likelihood?: CweLikelihood
  description: string
}

const CATALOG: Record<string, CweInfo> = {
  "CWE-20": {
    name: "Improper Input Validation",
    description:
      "Input isn't validated (or is validated incorrectly) before use, letting malformed data alter control or data flow.",
  },
  "CWE-22": {
    name: "Path Traversal",
    likelihood: "High",
    description:
      "User-controlled path segments ('../') reach filesystem APIs, letting an attacker read or write files outside the intended directory.",
  },
  "CWE-78": {
    name: "OS Command Injection",
    likelihood: "High",
    description:
      "Untrusted input is interpolated into a shell command, letting an attacker run arbitrary commands on the host.",
  },
  "CWE-79": {
    name: "Cross-site Scripting (XSS)",
    likelihood: "High",
    description:
      "Untrusted input is reflected into a page without encoding, letting an attacker run script in a victim's browser session.",
  },
  "CWE-89": {
    name: "SQL Injection",
    likelihood: "High",
    description:
      "Untrusted input is concatenated into a SQL query, letting an attacker read, modify, or destroy database contents.",
  },
  "CWE-90": {
    name: "LDAP Injection",
    description:
      "Untrusted input alters an LDAP query, letting an attacker bypass authentication or read directory data.",
  },
  "CWE-94": {
    name: "Code Injection",
    likelihood: "Medium",
    description:
      "Untrusted input is interpreted as code (e.g. via eval), letting an attacker execute arbitrary logic in-process.",
  },
  "CWE-95": {
    name: "Eval Injection",
    likelihood: "Medium",
    description:
      "Input flows into a dynamic-evaluation primitive (eval/exec), giving an attacker arbitrary code execution.",
  },
  "CWE-116": {
    name: "Improper Encoding or Escaping of Output",
    description:
      "Output isn't encoded for its sink, enabling injection in the downstream interpreter (HTML, SQL, shell).",
  },
  "CWE-200": {
    name: "Exposure of Sensitive Information",
    description:
      "Sensitive data is disclosed to an actor not explicitly authorized to see it.",
  },
  "CWE-209": {
    name: "Information Exposure Through an Error Message",
    description:
      "Error messages leak stack traces, queries, or secrets that help an attacker map the system.",
  },
  "CWE-287": {
    name: "Improper Authentication",
    description:
      "Identity isn't proven correctly, letting an attacker act as another user.",
  },
  "CWE-295": {
    name: "Improper Certificate Validation",
    likelihood: "Medium",
    description:
      "TLS certificates aren't verified, exposing connections to man-in-the-middle interception.",
  },
  "CWE-311": {
    name: "Missing Encryption of Sensitive Data",
    description:
      "Sensitive data is stored or transmitted without encryption, exposing it if intercepted.",
  },
  "CWE-312": {
    name: "Cleartext Storage of Sensitive Information",
    description: "Sensitive data is written to disk/DB in cleartext, exposing it on compromise.",
  },
  "CWE-319": {
    name: "Cleartext Transmission of Sensitive Information",
    likelihood: "Medium",
    description:
      "Sensitive data crosses the network unencrypted (http://), exposing it to anyone on-path.",
  },
  "CWE-326": {
    name: "Inadequate Encryption Strength",
    description: "A weak key size or algorithm is used, making the ciphertext feasible to break.",
  },
  "CWE-327": {
    name: "Use of a Broken or Risky Cryptographic Algorithm",
    likelihood: "Medium",
    description:
      "A deprecated cipher/hash (MD5, SHA-1, DES) is used, undermining the protection it's meant to provide.",
  },
  "CWE-338": {
    name: "Use of Cryptographically Weak PRNG",
    description:
      "A non-cryptographic random source seeds security values (tokens, keys), making them predictable.",
  },
  "CWE-352": {
    name: "Cross-Site Request Forgery (CSRF)",
    likelihood: "Medium",
    description:
      "State-changing requests lack an anti-forgery token, letting a malicious site act as the logged-in user.",
  },
  "CWE-377": {
    name: "Insecure Temporary File",
    description: "A temp file is created predictably/world-readable, enabling tampering or disclosure.",
  },
  "CWE-400": {
    name: "Uncontrolled Resource Consumption",
    description:
      "Work isn't bounded, letting an attacker exhaust CPU, memory, or connections (denial of service).",
  },
  "CWE-434": {
    name: "Unrestricted Upload of File with Dangerous Type",
    likelihood: "Medium",
    description:
      "Uploaded files aren't constrained by type, letting an attacker plant executable content.",
  },
  "CWE-502": {
    name: "Deserialization of Untrusted Data",
    likelihood: "Medium",
    description:
      "Untrusted bytes are deserialized into objects, often yielding remote code execution.",
  },
  "CWE-601": {
    name: "Open Redirect",
    description:
      "A redirect target is taken from user input, enabling phishing that abuses the site's trust.",
  },
  "CWE-611": {
    name: "XML External Entity (XXE)",
    likelihood: "Medium",
    description:
      "An XML parser resolves external entities, enabling file disclosure or SSRF from crafted XML.",
  },
  "CWE-614": {
    name: "Sensitive Cookie Without 'Secure' Attribute",
    description: "A session cookie can ride cleartext requests, exposing it to interception.",
  },
  "CWE-732": {
    name: "Incorrect Permission Assignment for Critical Resource",
    description: "A resource is over-permissioned, letting unauthorized actors read or modify it.",
  },
  "CWE-776": {
    name: "XML Entity Expansion (Billion Laughs)",
    description: "Nested entity expansion exhausts memory, causing denial of service.",
  },
  "CWE-798": {
    name: "Use of Hard-coded Credentials",
    likelihood: "High",
    description:
      "Credentials are embedded in source, so anyone with the code (or binary) gains access.",
  },
  "CWE-862": {
    name: "Missing Authorization",
    description: "An action isn't authorization-checked, letting any caller perform it.",
  },
  "CWE-863": {
    name: "Incorrect Authorization",
    description: "The authorization check is present but wrong, granting access it shouldn't.",
  },
  "CWE-918": {
    name: "Server-Side Request Forgery (SSRF)",
    likelihood: "Medium",
    description:
      "The server fetches a user-controlled URL, letting an attacker reach internal services or metadata endpoints.",
  },
  "CWE-1004": {
    name: "Sensitive Cookie Without 'HttpOnly' Flag",
    description: "A session cookie is reachable from JavaScript, so XSS can steal it.",
  },
}

/** Look up curated context for a CWE id (e.g. "CWE-79"); null when uncatalogued. */
export function cweInfo(cwe: string | null | undefined): CweInfo | null {
  if (!cwe) return null
  const m = cwe.trim().match(/^CWE-(\d+)$/i)
  if (!m) return null
  return CATALOG[`CWE-${m[1]}`] ?? null
}

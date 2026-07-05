
export type RulesetGroup = "security" | "languages" | "frameworks"

export interface Ruleset {
  id: string
  name: string
  description: string
  group: RulesetGroup
}

export const CODE_SCANNING_RULESETS: Ruleset[] = [
  // Security (user-selectable)
  { id: "p/owasp-top-ten",     name: "OWASP Top 10",    description: "Injection, XSS, broken auth, and more.", group: "security" },
  { id: "p/cwe-top-25",        name: "CWE Top 25",       description: "Most dangerous software weaknesses.",    group: "security" },
  { id: "p/default",           name: "Default",          description: "General best practices.",                group: "security" },
  { id: "p/r2c-security-audit",name: "Security Audit",   description: "Deep security audit rules by R2C.",      group: "security" },
]

/** Language and framework packs always appended — Opengrep only applies them to matching file types. */
export const AUTO_RULESETS = [
  "p/python", "p/java", "p/javascript", "p/typescript", "p/golang",
  "p/ruby", "p/php", "p/c", "p/cpp", "p/kotlin", "p/swift", "p/rust",
  "p/django", "p/flask", "p/express", "p/react", "p/spring",
]

const DEFAULT_RULESETS = ["p/owasp-top-ten", "p/cwe-top-25"]

/** Parse a comma-separated rulesets string into an array of IDs. */
export function parseRulesets(raw: string | null | undefined): string[] {
  if (!raw) return [...DEFAULT_RULESETS]
  return raw.split(",").map((s) => s.trim()).filter(Boolean)
}

/** Serialise a rulesets array to a sorted comma-separated string. */
export function serialiseRulesets(ids: string[]): string {
  return [...ids].sort().join(",")
}

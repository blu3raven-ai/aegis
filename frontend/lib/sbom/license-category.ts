/**
 * Frontend mirror of the backend license taxonomy (backend/src/sbom/licenses.py).
 *
 * The backend is authoritative for every GraphQL surface — it classifies once at
 * ingest and the category arrives on the wire. This module provides (a) the
 * presentation (label / tone / tooltip per category) every badge reuses, and
 * (b) a client-side `categorize()` for the per-repo table, which parses the
 * downloaded CycloneDX JSON in the browser and has no backend category.
 *
 * Keep the maps a strict mirror of the Python source; drift would show the same
 * package in different categories on the per-repo table vs the estate search.
 */

export type LicenseCategory =
  | "public-domain"
  | "permissive"
  | "weak-copyleft"
  | "copyleft"
  | "network-copyleft"
  | "proprietary"
  | "unknown"
  | "none"

export const CATEGORY_RANK: Record<LicenseCategory, number> = {
  "public-domain": 0,
  permissive: 1,
  "weak-copyleft": 2,
  none: 3,
  unknown: 4,
  proprietary: 5,
  copyleft: 6,
  "network-copyleft": 7,
}

/** A non-colour glyph keyed to risk class so the tier survives for colourblind
 * users (the badge text is the SPDX id, which doesn't encode the tier).
 * `warning` = copyleft obligations, `lock` = proprietary, `review` = needs a look. */
export type LicenseIcon = "warning" | "lock" | "review"

export const CATEGORY_META: Record<
  LicenseCategory,
  { label: string; tone: string; tooltip: string; icon?: LicenseIcon }
> = {
  "public-domain": {
    label: "Public domain",
    tone: "border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok-text)]",
    tooltip: "No obligations (Unlicense, 0BSD, CC0).",
  },
  permissive: {
    label: "Permissive",
    tone: "border-[var(--color-accent)]/30 bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
    tooltip: "Attribution only (MIT, Apache-2.0, BSD, ISC).",
  },
  "weak-copyleft": {
    label: "Weak copyleft",
    tone: "border-[var(--color-severity-high-border)] bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)]",
    tooltip: "File/library-level copyleft (LGPL, MPL-2.0, EPL).",
    icon: "warning",
  },
  copyleft: {
    label: "Copyleft",
    tone: "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
    tooltip: "Viral source-disclosure on distribution (GPL). Blocks shipping inside a proprietary product.",
    icon: "warning",
  },
  "network-copyleft": {
    label: "Network copyleft",
    tone: "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
    tooltip: "AGPL — source-disclosure extends to network/SaaS use. Mandatory legal review.",
    icon: "warning",
  },
  proprietary: {
    label: "Proprietary",
    tone: "border-[var(--color-argus-border)] bg-[var(--color-argus-subtle)] text-[var(--color-argus)]",
    tooltip: "Commercial / EULA — verify a held license permits use and redistribution.",
    icon: "lock",
  },
  unknown: {
    label: "Unknown",
    tone: "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
    tooltip: "Declared but unrecognized — may be restrictive (could be AGPL/proprietary). Needs review.",
    icon: "review",
  },
  none: {
    label: "No license",
    tone: "border-[var(--color-border)] bg-transparent text-[var(--color-text-tertiary)]",
    tooltip: "No license declared — legally all-rights-reserved, not free to use.",
    icon: "review",
  },
}

/** Worst-first — drives facet ordering. */
export const CATEGORY_ORDER: LicenseCategory[] = (
  Object.keys(CATEGORY_RANK) as LicenseCategory[]
).sort((a, b) => CATEGORY_RANK[b] - CATEGORY_RANK[a])

const SPDX_CATEGORY: Record<string, LicenseCategory> = {
  MIT: "permissive", "Apache-2.0": "permissive", "Apache-1.1": "permissive",
  "BSD-2-Clause": "permissive", "BSD-3-Clause": "permissive", ISC: "permissive",
  Zlib: "permissive", PostgreSQL: "permissive", "Python-2.0": "permissive",
  "BSD-2-Clause-Patent": "permissive", "BlueOak-1.0.0": "permissive",
  "0BSD": "public-domain", Unlicense: "public-domain", "CC0-1.0": "public-domain", WTFPL: "public-domain",
  "MPL-2.0": "weak-copyleft", "MPL-1.1": "weak-copyleft", "EPL-2.0": "weak-copyleft", "EPL-1.0": "weak-copyleft",
  "CDDL-1.0": "weak-copyleft", "CDDL-1.1": "weak-copyleft",
  "LGPL-2.0-only": "weak-copyleft", "LGPL-2.1-only": "weak-copyleft", "LGPL-2.1-or-later": "weak-copyleft",
  "LGPL-3.0-only": "weak-copyleft", "LGPL-3.0-or-later": "weak-copyleft",
  "GPL-2.0-only": "copyleft", "GPL-2.0-or-later": "copyleft",
  "GPL-3.0-only": "copyleft", "GPL-3.0-or-later": "copyleft",
  "AGPL-3.0-only": "network-copyleft", "AGPL-3.0-or-later": "network-copyleft",
}

const DEPRECATED_ALIASES: Record<string, string> = {
  "GPL-2.0": "GPL-2.0-only", "GPL-3.0": "GPL-3.0-only",
  "LGPL-2.0": "LGPL-2.0-only", "LGPL-2.1": "LGPL-2.1-only", "LGPL-3.0": "LGPL-3.0-only",
  "AGPL-3.0": "AGPL-3.0-only",
  "GPL-2.0+": "GPL-2.0-or-later", "GPL-3.0+": "GPL-3.0-or-later",
  "LGPL-2.1+": "LGPL-2.1-or-later", "LGPL-3.0+": "LGPL-3.0-or-later", "AGPL-3.0+": "AGPL-3.0-or-later",
}

// Normalized free-text name -> SPDX id. Keys are the output of normalizeName.
const NAME_ALIASES: Record<string, string> = {
  mit: "MIT",
  "apache 2.0": "Apache-2.0", "apache 2": "Apache-2.0", apache: "Apache-2.0", "apache software": "Apache-2.0",
  bsd: "BSD-3-Clause", "new bsd": "BSD-3-Clause", "modified bsd": "BSD-3-Clause", "simplified bsd": "BSD-2-Clause",
  isc: "ISC", zlib: "Zlib",
  "mozilla public 2.0": "MPL-2.0", "mpl 2.0": "MPL-2.0", "eclipse public 2.0": "EPL-2.0",
  gplv3: "GPL-3.0-only", "gpl 3": "GPL-3.0-only", "gpl 3.0": "GPL-3.0-only",
  gplv2: "GPL-2.0-only", "gpl 2": "GPL-2.0-only", "gpl 2.0": "GPL-2.0-only",
  lgplv3: "LGPL-3.0-only", "lgplv2.1": "LGPL-2.1-only", agplv3: "AGPL-3.0-only", "agpl 3.0": "AGPL-3.0-only",
  unlicense: "Unlicense", wtfpl: "WTFPL", cc0: "CC0-1.0",
}

const PROPRIETARY_PAT = /proprietary|commercial|eula|all[\s_-]+rights[\s_-]+reserved/i
const NAME_FILLER = /\b(the|license|licence|version|v)\b/gi
const SPDX_KEYS_LOWER = new Map(Object.keys(SPDX_CATEGORY).map((k) => [k.toLowerCase(), k]))
const DEPRECATED_LOWER = new Map(Object.entries(DEPRECATED_ALIASES).map(([k, v]) => [k.toLowerCase(), v]))

function normalizeName(text: string): string {
  return text
    .toLowerCase()
    .replace(NAME_FILLER, " ")
    .replace(/[^a-z0-9. ]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
}

function canonicalId(token: string): string {
  const tok = token.trim()
  const lower = tok.toLowerCase()
  const deprecated = DEPRECATED_LOWER.get(lower)
  if (deprecated) return deprecated
  const spdx = SPDX_KEYS_LOWER.get(lower)
  return spdx ?? tok
}

function classifyToken(token: string): LicenseCategory {
  const raw = token.trim()
  if (!raw) return "unknown"
  const upper = raw.toUpperCase()
  if (upper === "NONE") return "none"
  if (upper === "NOASSERTION") return "unknown"

  const canonical = canonicalId(raw)
  if (SPDX_CATEGORY[canonical]) return SPDX_CATEGORY[canonical]
  if (PROPRIETARY_PAT.test(raw)) return "proprietary"
  if (raw.toLowerCase().startsWith("licenseref")) return "unknown"

  const resolved = NAME_ALIASES[normalizeName(raw)]
  if (resolved && SPDX_CATEGORY[resolved]) return SPDX_CATEGORY[resolved]
  return "unknown"
}

/**
 * Classify a license string — a single SPDX id, a free-text name, or an SPDX
 * expression with OR/AND/WITH and parentheses. OR -> least restrictive
 * (consumer chooses); AND/WITH -> most restrictive (obligations stack). Mirrors
 * the recursive-descent evaluator in backend/src/sbom/licenses.py.
 */
export function categorize(license: string | null | undefined): LicenseCategory {
  if (!license) return "none"
  const s = license.trim()
  if (!s) return "none"

  const tokens = s.match(/\(|\)|[^()\s]+/g) ?? []
  let pos = 0
  const peek = (): string | undefined => tokens[pos]

  const parseOr = (): LicenseCategory => {
    const cats = [parseAnd()]
    while ((peek() ?? "").toUpperCase() === "OR") {
      pos++
      cats.push(parseAnd())
    }
    return cats.reduce((best, c) => (CATEGORY_RANK[c] < CATEGORY_RANK[best] ? c : best))
  }
  const parseAnd = (): LicenseCategory => {
    const cats = [parseWith()]
    while ((peek() ?? "").toUpperCase() === "AND") {
      pos++
      cats.push(parseWith())
    }
    return cats.reduce((worst, c) => (CATEGORY_RANK[c] > CATEGORY_RANK[worst] ? c : worst))
  }
  const parseWith = (): LicenseCategory => {
    const cat = parsePrimary()
    while ((peek() ?? "").toUpperCase() === "WITH") {
      pos++
      parsePrimary() // exception classifies by the base license
    }
    return cat
  }
  const parsePrimary = (): LicenseCategory => {
    const tok = peek()
    if (tok === "(") {
      pos++
      const cat = parseOr()
      if (peek() === ")") pos++
      return cat
    }
    if (tok === undefined) return "unknown"
    pos++
    return classifyToken(tok)
  }

  const parsed = parseOr()
  if (pos >= tokens.length) return parsed
  // Leftover, unparsed tokens — a malformed or operator-less list (some tools
  // emit "MIT GPL-3.0-only"). Classify every license token and take the most
  // restrictive, matching the backend, so a trailing copyleft isn't dropped.
  const leftoverCats = tokens
    .filter((t) => t !== "(" && t !== ")" && !["AND", "OR", "WITH"].includes(t.toUpperCase()))
    .map(classifyToken)
  if (leftoverCats.length === 0) return parsed
  return leftoverCats.reduce((worst, c) => (CATEGORY_RANK[c] > CATEGORY_RANK[worst] ? c : worst))
}

/**
 * Classify a CycloneDX `licenses[]` array (the raw entry shapes) into one risk
 * category — the shape-aware mirror of backend `classify_licenses`. Routes
 * `{expression}` through the expression evaluator and `{license:{id|name}}`
 * through the whole-token classifier (so a free-text name with spaces is not
 * tokenized like an expression). Multiple entries stack -> most restrictive.
 */
export function classifyLicensesRaw(raw: unknown): LicenseCategory {
  if (!Array.isArray(raw) || raw.length === 0) return "none"
  const cats: LicenseCategory[] = []
  for (const entry of raw) {
    if (typeof entry !== "object" || entry === null) continue
    const e = entry as Record<string, unknown>
    if (typeof e["expression"] === "string" && e["expression"].trim()) {
      cats.push(categorize(e["expression"]))
      continue
    }
    const lic = e["license"]
    if (typeof lic === "object" && lic !== null) {
      const obj = lic as Record<string, unknown>
      const token =
        (typeof obj["id"] === "string" ? obj["id"] : "") ||
        (typeof obj["name"] === "string" ? obj["name"] : "")
      if (token.trim()) cats.push(classifyToken(token))
    }
  }
  if (cats.length === 0) return "unknown" // entries existed but none classified
  return cats.reduce((worst, c) => (CATEGORY_RANK[c] > CATEGORY_RANK[worst] ? c : worst))
}

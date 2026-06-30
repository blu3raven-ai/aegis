"use client"

type Reference = { label: string; href: string; sub: string }

// Cap the list so a noisy advisory (some carry 20+ references) doesn't bury
// the drawer; the canonical id-derived links always come first.
const MAX_REFERENCES = 12

function normaliseHref(url: string): string {
  return url.trim().toLowerCase().replace(/\/+$/, "")
}

/** Build the canonical id-derived links from the ids the finding already
 *  carries: the CVE/GHSA identifier and the first CWE. */
function buildIdReferences(cve: string | undefined, cwe: string | undefined): Reference[] {
  const refs: Reference[] = []

  if (cve) {
    const id = cve.trim().toUpperCase()
    if (id.startsWith("CVE-")) {
      refs.push({
        label: id,
        href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
        sub: "NVD",
      })
    } else if (id.startsWith("GHSA-")) {
      refs.push({
        label: id,
        href: `https://github.com/advisories/${encodeURIComponent(id)}`,
        sub: "GitHub Advisory",
      })
    }
  }

  if (cwe) {
    const m = cwe.match(/^CWE-(\d+)$/i)
    if (m) {
      refs.push({
        label: cwe.toUpperCase(),
        href: `https://cwe.mitre.org/data/definitions/${m[1]}.html`,
        sub: "MITRE",
      })
    }
  }

  return refs
}

/** Friendly "host/path" label + a source tag for an arbitrary advisory URL. */
function describeUrl(url: string): Reference {
  try {
    const u = new URL(url)
    const host = u.hostname.replace(/^www\./, "")
    const path = u.pathname.replace(/\/+$/, "")
    let sub = host
    if (host.includes("github.com")) sub = path.includes("/commit/") ? "Commit" : "GitHub"
    else if (host.includes("nvd.nist.gov")) sub = "NVD"
    else if (host.includes("cve.org") || host.includes("mitre.org")) sub = "CVE"
    const raw = `${host}${path}`
    const label = raw.length > 52 ? `${raw.slice(0, 51)}…` : raw
    return { label, href: url, sub }
  } catch {
    return { label: url.slice(0, 52), href: url, sub: "Link" }
  }
}

/** Merge the id-derived links with the advisory-supplied reference URLs,
 *  deduped by href so the GHSA/NVD links don't appear twice. */
function buildReferences(
  cve: string | undefined,
  cwe: string | undefined,
  advisoryReferences: string[] | undefined,
): Reference[] {
  const refs = buildIdReferences(cve, cwe)
  const seen = new Set(refs.map((r) => normaliseHref(r.href)))

  for (const url of advisoryReferences ?? []) {
    if (!url) continue
    const key = normaliseHref(url)
    if (seen.has(key)) continue
    seen.add(key)
    refs.push(describeUrl(url))
  }

  return refs.slice(0, MAX_REFERENCES)
}

/** External references for the drawer: canonical NVD / GitHub Advisory / MITRE
 *  links derived from the finding's ids, plus the advisory's own reference URLs.
 *  Renders nothing when there's nothing to link. */
export function FindingReferencesSection({
  cve,
  cwe,
  advisoryReferences,
}: {
  cve?: string
  cwe?: string
  advisoryReferences?: string[]
}) {
  const refs = buildReferences(cve, cwe, advisoryReferences)
  if (refs.length === 0) return null

  return (
    <section className="mt-6">
      <h3 className="mb-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
        References
      </h3>
      <ul className="space-y-1.5">
        {refs.map((r) => (
          <li key={r.href}>
            <a
              href={r.href}
              target="_blank"
              rel="noreferrer noopener"
              className="group flex items-center justify-between gap-3 rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] px-3 py-2 text-sm transition-colors hover:border-[var(--color-accent)]"
            >
              <span className="flex items-center gap-2 truncate">
                <span className="font-mono text-[var(--color-text-primary)]">{r.label}</span>
                <span className="text-2xs uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                  {r.sub}
                </span>
              </span>
              <span
                aria-hidden="true"
                className="text-[var(--color-text-secondary)] transition-colors group-hover:text-[var(--color-accent)]"
              >
                Open ↗
              </span>
            </a>
          </li>
        ))}
      </ul>
    </section>
  )
}

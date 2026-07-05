const PERMISSIVE = new Set(["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense"])
const COPYLEFT = new Set(["GPL-2.0", "GPL-3.0", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "MPL-2.0"])

function badgeStyle(spdxId: string): string {
  if (PERMISSIVE.has(spdxId)) {
    return "bg-[var(--color-accent-subtle)] text-[var(--color-accent)] border-[var(--color-accent)]/30"
  }
  if (COPYLEFT.has(spdxId)) {
    return "bg-orange-500/10 text-orange-500 border-orange-500/30"
  }
  return "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)] border-[var(--color-border)]"
}

export function ComponentLicenseBadge({ spdxId }: { spdxId: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-px text-2xs font-semibold ${badgeStyle(spdxId)}`}
      title={spdxId}
    >
      {spdxId}
    </span>
  )
}

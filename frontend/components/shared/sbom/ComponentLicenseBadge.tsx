import { CATEGORY_META, categorize, type LicenseCategory, type LicenseIcon } from "@/lib/sbom/license-category"

// Distinct shapes per risk class so the tier reads without relying on colour
// (WCAG: don't convey meaning by colour alone). The badge label is the SPDX id,
// which doesn't encode the tier, so the glyph carries it.
const ICON_PATH: Record<LicenseIcon, string> = {
  warning: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z",
  lock: "M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z",
  review: "M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M12 18h.008v.008H12V18Zm9-6a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
}

function LicenseIconGlyph({ icon }: { icon: LicenseIcon }) {
  return (
    <svg className="h-3 w-3 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICON_PATH[icon]} />
    </svg>
  )
}

/**
 * License badge coloured by risk category. GraphQL surfaces pass the
 * backend-classified `category`; the per-repo client-parsed table passes only a
 * `spdxId`/expression and the category is derived. Shows the license string with
 * the category in the tooltip so the risk tier is always one hover away, and a
 * shape glyph so the tier survives without colour.
 */
export function ComponentLicenseBadge({
  spdxId,
  category,
}: {
  spdxId?: string | null
  category?: LicenseCategory | null
}) {
  const cat: LicenseCategory = category ?? categorize(spdxId)
  const meta = CATEGORY_META[cat]
  const label = spdxId?.trim() || meta.label
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-px text-2xs font-semibold ${meta.tone}`}
      title={`${meta.label}: ${meta.tooltip}`}
    >
      {meta.icon && <LicenseIconGlyph icon={meta.icon} />}
      {label}
    </span>
  )
}

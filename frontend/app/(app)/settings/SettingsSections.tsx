"use client"

import { Card } from "@/components/ui/Card"
import { SETTINGS_SECTIONS, type SettingsSectionDef } from "./registry"

/**
 * The settings body: a scrollable column of section cards (grouping + jump-links
 * come from the left nav). Every section renders its full detail inline on the
 * card; its controls save through the page-level save bar (GlobalSaveBar, mounted
 * in the settings layout) or their own actions. Deep links (/settings#<id>) scroll
 * to a section via its id anchor.
 */
export function SettingsSections() {
  return (
    <div className="flex flex-col gap-6">
      {SETTINGS_SECTIONS.map((s) => (
        // The id + scroll margin are the target for the left nav's scroll-to and
        // its active-section highlight, and for /settings#<id> deep links.
        <div key={s.id} id={s.id} className="scroll-mt-4">
          <SectionCard section={s} />
        </div>
      ))}
    </div>
  )
}

/** A section rendered directly on the page: its detail body edits inline and
 *  reports to the page-level save bar. */
function SectionCard({ section }: { section: SettingsSectionDef }) {
  const Detail = section.detailComponent
  return (
    <Card padding="lg" className="flex flex-col gap-4">
      <div>
        <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
          {section.title}
        </h3>
        {section.subtitle && (
          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">{section.subtitle}</p>
        )}
      </div>
      <Detail />
    </Card>
  )
}

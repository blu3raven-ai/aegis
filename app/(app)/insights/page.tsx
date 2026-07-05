"use client"

import { InsightsContent } from "@/components/shared/insights/InsightsContent"

export default function InsightsPage() {
  return (
    <div className="flex h-full flex-col overflow-y-auto bg-[var(--color-bg)]">
      <InsightsContent />
    </div>
  )
}

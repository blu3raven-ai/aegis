// components/shared/FindingDrawer/DrawerSection.tsx

import { Card } from "@/components/ui/Card"

export function DrawerSection({
  label,
  action,
  children,
}: {
  label: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <Card as="section" padding="none" className="rounded-md">
      <div className="flex items-center justify-between px-4 pt-4 pb-2">
        <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          {label}
        </p>
        {action}
      </div>
      <div className="space-y-4 px-4 pb-4">{children}</div>
    </Card>
  )
}

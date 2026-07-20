import { type ReactNode } from "react"
import { Card } from "@/components/ui/Card"

export function InsightCard({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string
  title: string
  description: string
  children: ReactNode
}) {
  return (
    <Card className="rounded-md shadow-[var(--shadow-card)]">
      <p className="font-mono text-xs font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">{eyebrow}</p>
      <h3 className="mt-2 text-base font-semibold text-[var(--color-text-primary)]">{title}</h3>
      <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{description}</p>
      <div className="mt-4">{children}</div>
    </Card>
  )
}

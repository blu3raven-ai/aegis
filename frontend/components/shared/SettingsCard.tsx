import { Card } from "@/components/ui/Card"

interface SettingsCardProps {
  eyebrow: string
  title: string
  subtitle?: string
  children: React.ReactNode
}

export function SettingsCard({ eyebrow, title, subtitle, children }: SettingsCardProps) {
  return (
    <Card padding="none" className="rounded-xl px-6 py-5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">{eyebrow}</p>
      <h3 className="mt-1.5 text-sm font-semibold text-[var(--color-text-primary)]">{title}</h3>
      {subtitle && <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">{subtitle}</p>}
      <div className="mt-4">{children}</div>
    </Card>
  )
}

// components/shared/FindingDrawer/DrawerSection.tsx

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
    <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
      <div className="flex items-center justify-between px-4 pt-4 pb-2">
        <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
          {label}
        </p>
        {action}
      </div>
      <div className="space-y-4 px-4 pb-4">{children}</div>
    </section>
  )
}

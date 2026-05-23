// components/shared/FindingDrawer/DrawerSection.tsx

export function DrawerSection({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
      <p className="px-4 pt-4 pb-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
        {label}
      </p>
      <div className="px-4 pb-4">{children}</div>
    </section>
  )
}

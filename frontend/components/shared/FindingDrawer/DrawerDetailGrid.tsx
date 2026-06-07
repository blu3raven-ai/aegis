// components/shared/FindingDrawer/DrawerDetailGrid.tsx

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        {label}
      </p>
      <p className="mt-1 break-words text-sm font-medium text-[var(--color-text-primary)]">
        {value}
      </p>
    </div>
  )
}

export function DrawerDetailGrid({
  items,
}: {
  items: { label: string; value: string }[]
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {items.map((item) => (
        <DetailItem key={item.label} label={item.label} value={item.value} />
      ))}
    </div>
  )
}

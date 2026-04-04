export function KpiCard({
  label,
  value,
  note,
  valueClass,
  onClick,
}: {
  label: string
  value: string
  note: string
  valueClass: string
  onClick?: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col rounded-3xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4 text-left shadow-[0_28px_80px_rgba(15,23,42,0.06)] transition-colors hover:border-blue-300 cursor-pointer"
    >
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        {label}
      </p>
      <p className={`mt-3 text-4xl font-semibold leading-none tabular-nums ${valueClass}`}>{value}</p>
      <p className="mt-2 text-sm text-[var(--color-text-secondary)]">{note}</p>
    </button>
  )
}

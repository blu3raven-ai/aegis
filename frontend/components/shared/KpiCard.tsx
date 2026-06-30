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
  const base =
    "flex flex-col rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-3 text-left shadow-[0_28px_80px_rgba(15,23,42,0.06)]"
  const body = (
    <>
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        {label}
      </p>
      <p className={`mt-2 text-2xl font-semibold leading-none tabular-nums ${valueClass}`}>{value}</p>
      <p className="mt-2 text-sm text-[var(--color-text-secondary)]">{note}</p>
    </>
  )

  // Only a card with a real handler is interactive — otherwise render a plain
  // div so it doesn't advertise clickability or steal a tab stop.
  if (!onClick) {
    return <div className={base}>{body}</div>
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${base} cursor-pointer transition-colors hover:border-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]`}
    >
      {body}
    </button>
  )
}

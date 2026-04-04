
const COLOR_MAP = {
  accent:  "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 text-[var(--color-accent)]",
  emerald: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
  orange:  "border-orange-500/40 bg-orange-500/10 text-orange-400",
} as const

interface FilterTagProps {
  label: string
  onClear: () => void
  color?: keyof typeof COLOR_MAP
}

export function FilterTag({ label, onClear, color = "accent" }: FilterTagProps) {
  return (
    <span className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold ${COLOR_MAP[color]}`}>
      {label}
      <button type="button" onClick={onClear} className="ml-0.5 rounded hover:opacity-70" aria-label={`Clear ${label} filter`}>
        <svg className="h-3.5 w-3.5" viewBox="0 0 20 20" fill="currentColor">
          <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
        </svg>
      </button>
    </span>
  )
}

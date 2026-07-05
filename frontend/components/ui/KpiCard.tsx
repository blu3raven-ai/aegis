// Metric card — large tabular number + uppercase tracking label (see CLAUDE.md KpiCard spec).
import { cn } from "@/lib/shared/utils";

type Props = {
  label: string;
  value: number | string;
  hint?: React.ReactNode;
  status?: "neutral" | "success" | "warning" | "danger";
};

export function KpiCard({ label, value, hint, status = "neutral" }: Props) {
  const valueColor =
    status === "danger" ? "text-[var(--color-danger)]" :
    status === "warning" ? "text-[var(--color-warning)]" :
    status === "success" ? "text-[var(--color-success)]" :
    "text-[var(--color-text-primary)]";

  return (
    <div className="border border-[var(--color-border)] bg-[var(--color-surface-2)] rounded px-5 py-3">
      <div className={cn("text-2xl font-semibold leading-none tabular-nums", valueColor)}>
        {value}
      </div>
      <div className="mt-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)] whitespace-nowrap">
        {label}
      </div>
      {hint && <div className="mt-1 text-xs text-[var(--color-text-secondary)]">{hint}</div>}
    </div>
  );
}

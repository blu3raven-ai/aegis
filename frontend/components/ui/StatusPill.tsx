// Integration status pill — colored dot + text.
import { cn } from "@/lib/shared/utils";

export type Status = "healthy" | "warning" | "failing" | "stale" | "disabled";

const STYLES: Record<Status, { label: string; cls: string; dotCls: string }> = {
  healthy:  { label: "Healthy",  cls: "text-[var(--color-success)]", dotCls: "bg-[var(--color-success)]" },
  warning:  { label: "Warning",  cls: "text-[var(--color-warning)]", dotCls: "bg-[var(--color-warning)]" },
  failing:  { label: "Failing",  cls: "text-[var(--color-danger)]",  dotCls: "bg-[var(--color-danger)]" },
  stale:    { label: "Stale",    cls: "text-[var(--color-text-secondary)]", dotCls: "bg-[var(--color-muted)]" },
  disabled: { label: "Disabled", cls: "text-[var(--color-text-secondary)] opacity-60", dotCls: "bg-[var(--color-muted)]" },
};

export function StatusPill({ status, label }: { status: Status; label?: string }) {
  const style = STYLES[status];
  if (!style) return null;
  return (
    <span className={cn("inline-flex items-center gap-1.5 font-mono text-xs font-medium uppercase tracking-[0.04em] leading-none", style.cls)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", style.dotCls)} aria-hidden />
      {label ?? style.label}
    </span>
  );
}

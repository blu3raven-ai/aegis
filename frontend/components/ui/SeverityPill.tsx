// Severity chip — colored text + icon pill.
import { AlertCircle, AlertTriangle, ChevronDown, Info } from "lucide-react";
import { cn } from "@/lib/shared/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

const STYLES: Record<Severity, { label: string; bg: string; fg: string; Icon: typeof AlertCircle }> = {
  critical: {
    label: "Critical",
    bg: "bg-[var(--color-danger)]/15",
    fg: "text-[var(--color-danger)]",
    Icon: AlertCircle,
  },
  high: {
    label: "High",
    bg: "bg-[var(--color-danger)]/10",
    fg: "text-[var(--color-danger)]",
    Icon: AlertCircle,
  },
  medium: {
    label: "Medium",
    bg: "bg-[var(--color-warning)]/10",
    fg: "text-[var(--color-warning)]",
    Icon: AlertTriangle,
  },
  low: {
    label: "Low",
    bg: "bg-[var(--color-muted)]/10",
    fg: "text-[var(--color-text-secondary)]",
    Icon: ChevronDown,
  },
  info: {
    label: "Info",
    bg: "bg-[var(--color-muted)]/5",
    fg: "text-[var(--color-text-secondary)]",
    Icon: Info,
  },
};

type Props = {
  severity: Severity;
  count?: number;
  size?: "sm" | "md";
};

export function SeverityPill({ severity, count, size = "md" }: Props) {
  const style = STYLES[severity];
  if (!style) return null;
  const sizeClasses =
    size === "sm"
      ? "px-1.5 py-0.5 text-2xs gap-1"
      : "px-2 py-0.5 text-xs gap-1.5";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded font-semibold align-middle leading-none tabular-nums whitespace-nowrap",
        sizeClasses,
        style.bg,
        style.fg,
      )}
      aria-label={`${style.label}${count !== undefined ? ` (${count})` : ""}`}
    >
      <style.Icon className={size === "sm" ? "h-2.5 w-2.5" : "h-3 w-3"} aria-hidden />
      <span>{style.label}</span>
      {count !== undefined && (
        <span className={cn("border-l border-current/20 pl-1.5", size === "sm" ? "ml-0.5" : "ml-1")}>
          {count}
        </span>
      )}
    </span>
  );
}

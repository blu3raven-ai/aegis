// Pattern: Snyk projects list — project type label with icon.
// Reference: Snyk projects table → "Project Type" column.
import { Boxes, Cloud, Code2 } from "lucide-react";
import { cn } from "@/lib/shared/utils";

export type SourceType = "code" | "containers" | "cloud";

const STYLES: Record<SourceType, { label: string; Icon: typeof Code2 }> = {
  code:       { label: "Code",       Icon: Code2 },
  containers: { label: "Container",  Icon: Boxes },
  cloud:      { label: "Cloud",      Icon: Cloud },
};

export function TypeChip({ type }: { type: SourceType }) {
  const style = STYLES[type];
  if (!style) return null;
  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)]",
      "px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.06em] text-[var(--color-text-secondary)] whitespace-nowrap leading-none",
    )}>
      <style.Icon className="h-3 w-3" aria-hidden />
      {style.label}
    </span>
  );
}

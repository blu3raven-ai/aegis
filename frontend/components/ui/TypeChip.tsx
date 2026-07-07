// Source type label with icon.
import { Boxes, Cloud, Code2, Workflow } from "lucide-react";
import { cn } from "@/lib/shared/utils";

export type SourceType = "code" | "containers" | "cloud" | "ci";

const STYLES: Record<SourceType, { label: string; Icon: typeof Code2 }> = {
  code:       { label: "Code",       Icon: Code2 },
  containers: { label: "Container",  Icon: Boxes },
  cloud:      { label: "Cloud",      Icon: Cloud },
  ci:         { label: "CI",         Icon: Workflow },
};

export function TypeChip({ type }: { type: SourceType }) {
  const style = STYLES[type];
  if (!style) return null;
  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 rounded border border-[var(--color-border)] bg-[var(--color-surface-raised)]",
      "px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.06em] text-[var(--color-text-secondary)] whitespace-nowrap leading-none",
    )}>
      <style.Icon className="h-3 w-3" aria-hidden />
      {style.label}
    </span>
  );
}

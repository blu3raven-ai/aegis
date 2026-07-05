// Centered empty state — icon, title, description, and a single CTA.
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/shared/utils";

type Props = {
  icon: LucideIcon;
  title: string;
  description?: string;
  cta?: React.ReactNode;
};

export function EmptyState({ icon: Icon, title, description, cta }: Props) {
  return (
    <div className={cn(
      "flex flex-col items-center justify-center text-center",
      "rounded border border-dashed border-[var(--color-border)]",
      "py-16 px-6 bg-[var(--color-surface-2)]/30",
    )}>
      <Icon className="h-10 w-10 text-[var(--color-text-secondary)]" aria-hidden />
      <h3 className="mt-4 text-base font-semibold text-[var(--color-text-primary)]">{title}</h3>
      {description && (
        <p className="mt-1 max-w-md text-sm text-[var(--color-text-secondary)]">{description}</p>
      )}
      {cta && <div className="mt-4">{cta}</div>}
    </div>
  );
}

// Loading skeleton — n rows of pulsing gray bars shown during initial fetch.
import { cn } from "@/lib/shared/utils";

type Props = {
  rows?: number;
  columns?: number;
};

export function TableSkeleton({ rows = 6, columns = 5 }: Props) {
  return (
    <div className="border border-[var(--color-border)] rounded overflow-hidden">
      <div className="border-b border-[var(--color-border)] bg-[var(--color-surface-2)] px-4 py-2 flex gap-4">
        {Array.from({ length: columns }).map((_, i) => (
          <div key={i} className="h-3 flex-1 max-w-32 rounded bg-[var(--color-surface)] animate-pulse" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="border-b border-[var(--color-border)] px-4 py-3 flex gap-4 last:border-b-0">
          {Array.from({ length: columns }).map((_, c) => (
            <div
              key={c}
              className={cn(
                "h-3 flex-1 rounded animate-pulse",
                c === 0 ? "max-w-48 bg-[var(--color-surface-2)]" : "max-w-24 bg-[var(--color-surface-2)]",
              )}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

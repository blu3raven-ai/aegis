export default function Loading() {
  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]" aria-busy="true" aria-label="Loading releases">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
        <div className="h-9 w-9 rounded-lg bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        <div className="flex flex-col gap-1.5">
          <div className="h-5 w-28 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
          <div className="h-3 w-64 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        </div>
      </div>
      <div className="flex flex-col gap-4 p-6">
        <div className="h-9 w-72 rounded-lg bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)]">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className={`flex items-center gap-4 px-5 py-3.5 ${i === 0 ? "" : "border-t border-[var(--color-border)]"}`}
            >
              <div className="h-8 w-8 rounded-full bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              <div className="flex-1 space-y-1.5">
                <div className="h-3 w-32 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
                <div className="h-3 w-48 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              </div>
              <div className="h-3 w-20 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              <div className="h-3 w-16 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

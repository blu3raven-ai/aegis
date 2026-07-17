export default function Loading() {
  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]" aria-busy="true" aria-label="Loading rules">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
        <div className="h-9 w-9 rounded-lg bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        <div className="flex flex-col gap-1.5">
          <div className="h-5 w-24 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
          <div className="h-3 w-56 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-7 w-24 rounded-md bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        ))}
      </div>
      <div className="flex flex-1 flex-col gap-2 p-6">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-14 w-full rounded-md bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        ))}
      </div>
    </div>
  )
}

export default function Loading() {
  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]" aria-busy="true" aria-label="Loading compliance">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
        <div className="h-9 w-9 rounded-lg bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        <div className="flex flex-col gap-1.5">
          <div className="h-5 w-32 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
          <div className="h-3 w-64 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        </div>
      </div>
      <div className="flex flex-col gap-6 p-6">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-24 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] motion-safe:animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-32 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] motion-safe:animate-pulse" />
          ))}
        </div>
        <div className="h-72 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] motion-safe:animate-pulse" />
      </div>
    </div>
  )
}

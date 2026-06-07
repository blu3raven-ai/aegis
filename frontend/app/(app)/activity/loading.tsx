export default function Loading() {
  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]" aria-busy="true" aria-label="Loading activity">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
        <div className="h-9 w-9 rounded-lg bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        <div className="flex flex-col gap-1.5">
          <div className="h-5 w-24 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
          <div className="h-3 w-64 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        </div>
      </div>
      <div className="mx-auto w-full max-w-3xl px-4 py-6">
        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-20 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] motion-safe:animate-pulse" />
          ))}
        </div>
        <div className="mb-4 flex flex-wrap gap-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-7 w-20 rounded-full bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
          ))}
        </div>
        <div className="flex flex-col gap-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="h-16 w-full rounded-lg bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
          ))}
        </div>
      </div>
    </div>
  )
}

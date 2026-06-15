export default function Loading() {
  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]" aria-busy="true" aria-label="Loading release scan">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
        <div className="h-9 w-9 rounded-lg bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        <div className="flex flex-col gap-1.5">
          <div className="h-5 w-48 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
          <div className="h-3 w-64 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
        </div>
      </div>
      <div className="flex w-full flex-col gap-6 px-6 py-6">
        <div className="h-36 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] motion-safe:animate-pulse" />
        <div className="h-56 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] motion-safe:animate-pulse" />
        <div className="h-40 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] motion-safe:animate-pulse" />
      </div>
    </div>
  )
}

import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"

export default function Loading() {
  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]" aria-busy="true" aria-label="Loading insights">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
        <Skeleton className="h-9 w-9 rounded-lg" />
        <div className="flex flex-col gap-1.5">
          <Skeleton className="h-5 w-24" />
          <Skeleton className="h-3 w-64" />
        </div>
      </div>
      <div className="flex flex-col gap-6 p-6">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} padding="none" className="h-24 motion-safe:animate-pulse" />
          ))}
        </div>
        <Card padding="none" className="h-72 rounded-2xl motion-safe:animate-pulse" />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Card padding="none" className="h-56 rounded-2xl motion-safe:animate-pulse" />
          <Card padding="none" className="h-56 rounded-2xl motion-safe:animate-pulse" />
        </div>
      </div>
    </div>
  )
}

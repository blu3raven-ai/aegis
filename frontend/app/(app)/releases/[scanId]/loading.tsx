import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"

export default function Loading() {
  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]" aria-busy="true" aria-label="Loading release scan">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
        <Skeleton className="h-9 w-9 rounded-lg" />
        <div className="flex flex-col gap-1.5">
          <Skeleton className="h-5 w-48" />
          <Skeleton className="h-3 w-64" />
        </div>
      </div>
      <div className="flex w-full flex-col gap-6 px-6 py-6">
        <Card padding="none" className="h-36 rounded-md motion-safe:animate-pulse" />
        <Card padding="none" className="h-56 rounded-md motion-safe:animate-pulse" />
        <Card padding="none" className="h-40 rounded-md motion-safe:animate-pulse" />
      </div>
    </div>
  )
}

import { forwardRef, type HTMLAttributes } from "react"
import { cn } from "@/lib/shared/utils"

interface SkeletonProps extends HTMLAttributes<HTMLDivElement> {}

// Single source of truth for the loading-state placeholder. Always uses
// `motion-safe:animate-pulse` (respects `prefers-reduced-motion`) and the
// canonical raised-surface tint. Caller controls size/shape via className —
// width / height / radius / margin etc. all pass through.
//
// Examples:
//   <Skeleton className="h-4 w-1/2" />           text line
//   <Skeleton className="h-9 w-9 rounded-full" />  avatar
//   <Skeleton className="h-32 rounded-xl" />      card placeholder
export const Skeleton = forwardRef<HTMLDivElement, SkeletonProps>(function Skeleton(
  { className, ...rest },
  ref,
) {
  return (
    <div
      ref={ref}
      aria-hidden="true"
      className={cn(
        "motion-safe:animate-pulse rounded bg-[var(--color-surface-raised)]",
        className,
      )}
      {...rest}
    />
  )
})

export type { SkeletonProps }

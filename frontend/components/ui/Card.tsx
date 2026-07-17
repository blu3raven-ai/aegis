import { forwardRef, type HTMLAttributes } from "react"
import { cn } from "@/lib/shared/utils"

type CardPadding = "none" | "sm" | "md" | "lg"
type CardElevation = "none" | "sm"

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  /** Body padding. `none` = no padding (caller renders sub-sections), `sm` = p-3,
   *  `md` = p-5 (default — matches every dashboard card), `lg` = p-6. */
  padding?: CardPadding
  /** Drop shadow. `none` (default) for inline dashboard cards; `sm` adds the
   *  canonical card shadow token for slightly elevated cards. */
  elevation?: CardElevation
  /** Show row-hover affordance — for interactive list cards (used as a
   *  `<button>` or `<a>` wrapper target). */
  interactive?: boolean
  /** Use as an element other than `div` (e.g. `section`, `article`). */
  as?: "div" | "section" | "article" | "aside"
}

// Canonical dashboard card chrome. Every "rounded-lg border bg-surface" widget
// in the app should route through this so radius / border / background tokens
// stay in one place. For pop-ups / modals / floating menus, prefer Sheet or
// Dialog — Card is for static dashboard surfaces.

const base = "rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]"

const paddingClasses: Record<CardPadding, string> = {
  none: "",
  sm:   "p-3",
  md:   "p-5",
  lg:   "p-6",
}

const elevationClasses: Record<CardElevation, string> = {
  none: "",
  sm:   "shadow-[var(--shadow-card)]",
}

const interactiveClasses = "transition-colors hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-raised)]"

export const Card = forwardRef<HTMLDivElement, CardProps>(function Card(
  {
    padding = "md",
    elevation = "none",
    interactive = false,
    as = "div",
    className,
    ...rest
  },
  ref,
) {
  const Tag = as as "div"
  return (
    <Tag
      ref={ref as React.Ref<HTMLDivElement>}
      className={cn(
        base,
        paddingClasses[padding],
        elevationClasses[elevation],
        interactive && interactiveClasses,
        className,
      )}
      {...rest}
    />
  )
})

export type { CardProps, CardPadding, CardElevation }

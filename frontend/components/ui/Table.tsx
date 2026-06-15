import { forwardRef, type HTMLAttributes, type TdHTMLAttributes, type ThHTMLAttributes } from "react"
import { cn } from "@/lib/shared/utils"

// Thin wrappers around the native table tags so callers don't have to
// re-write `text-xs uppercase tracking-[0.14em] text-secondary` etc. every
// time. Each wrapper just sets the canonical chrome and merges any caller
// className via cn(), so per-column overrides (`text-right`, `font-mono`,
// `tabular-nums`, fixed widths) keep working.

interface TableProps extends HTMLAttributes<HTMLTableElement> {}

export const Table = forwardRef<HTMLTableElement, TableProps>(function Table(
  { className, ...rest },
  ref,
) {
  return (
    <table
      ref={ref}
      className={cn("w-full text-sm", className)}
      {...rest}
    />
  )
})

interface TheadProps extends HTMLAttributes<HTMLTableSectionElement> {}

// Canonical header chrome — used by every list/table surface in the app.
// `text-2xs font-semibold uppercase tracking-[0.14em]` keeps the eyebrow
// hierarchy consistent across surfaces; the underline lives on the cell
// row so sticky headers render correctly.
export const Thead = forwardRef<HTMLTableSectionElement, TheadProps>(function Thead(
  { className, ...rest },
  ref,
) {
  return (
    <thead
      ref={ref}
      className={cn(
        "border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]",
        className,
      )}
      {...rest}
    />
  )
})

interface TbodyProps extends HTMLAttributes<HTMLTableSectionElement> {
  /** Apply `divide-y` between rows (default true). */
  divided?: boolean
}

export const Tbody = forwardRef<HTMLTableSectionElement, TbodyProps>(function Tbody(
  { className, divided = true, ...rest },
  ref,
) {
  return (
    <tbody
      ref={ref}
      className={cn(divided && "divide-y divide-[var(--color-border-divider)]", className)}
      {...rest}
    />
  )
})

interface TrProps extends HTMLAttributes<HTMLTableRowElement> {
  /** Show a row-hover affordance — for tables whose rows are interactive (clickable, drawer trigger). */
  interactive?: boolean
}

export const Tr = forwardRef<HTMLTableRowElement, TrProps>(function Tr(
  { className, interactive = false, ...rest },
  ref,
) {
  return (
    <tr
      ref={ref}
      className={cn(
        interactive && "transition-colors hover:bg-[var(--color-bg-hover)]",
        className,
      )}
      {...rest}
    />
  )
})

interface ThProps extends ThHTMLAttributes<HTMLTableCellElement> {}

export const Th = forwardRef<HTMLTableCellElement, ThProps>(function Th(
  { className, ...rest },
  ref,
) {
  return (
    <th
      ref={ref}
      className={cn("px-4 py-3", className)}
      {...rest}
    />
  )
})

interface TdProps extends TdHTMLAttributes<HTMLTableCellElement> {}

export const Td = forwardRef<HTMLTableCellElement, TdProps>(function Td(
  { className, ...rest },
  ref,
) {
  return (
    <td
      ref={ref}
      className={cn("px-4 py-3", className)}
      {...rest}
    />
  )
})

export type { TableProps, TheadProps, TbodyProps, TrProps, ThProps, TdProps }

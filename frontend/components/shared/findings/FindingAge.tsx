import { cn } from "@/lib/shared/utils"

/**
 * A finding's age label. Single source of truth for the invariant that the age
 * string must never wrap: it lives in narrow right-aligned columns where a
 * value like "20m ago" would otherwise break onto two lines and make rows
 * uneven. Also uses tabular figures so ages line up vertically. Per-context
 * styling (size, colour, padding) comes via `className`; the no-wrap rule
 * cannot be overridden away by a call site, which is what let it regress before.
 */
export function FindingAge({ age, className }: { age: string; className?: string }) {
  return <span className={cn("whitespace-nowrap tabular-nums", className)}>{age}</span>
}

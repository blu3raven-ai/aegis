import { forwardRef, type SelectHTMLAttributes } from "react"
import { cn } from "@/lib/shared/utils"

type SelectSize = "sm" | "md"

interface SelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, "size"> {
  /** Visual size. `sm` = h-8 text-xs, `md` = h-10 text-sm (default). */
  size?: SelectSize
  /** Visible error state — paints the border red and matches focus-ring. */
  invalid?: boolean
}

const base =
  "w-full appearance-none rounded-md border bg-[var(--color-bg-input)] text-[var(--color-text-primary)] transition-colors " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-0 " +
  "disabled:cursor-not-allowed disabled:opacity-50 " +
  // Caret rendered via inline SVG background so the chrome matches across themes.
  "bg-no-repeat bg-[right_0.75rem_center]"

const sizeClasses: Record<SelectSize, string> = {
  sm: "h-8 pl-3 pr-7 text-xs",
  md: "h-10 pl-3 pr-9 text-sm",
}

const validityClasses = (invalid: boolean) =>
  invalid
    ? "border-[var(--color-severity-critical-border)] focus-visible:ring-[var(--color-severity-critical)]"
    // border-strong keeps the field readable against surface/well backgrounds in
    // dark mode, where the softer --color-border collapses into the card.
    : "border-[var(--color-border-strong)] focus-visible:ring-[var(--color-accent)]"

// Chevron SVG inlined as a background image so the select carries its own
// affordance without the caller having to wrap it in a relative parent.
// The chevron is baked with an explicit neutral-gray stroke, NOT currentColor:
// `currentColor` inside a data-URI background image doesn't inherit the element's
// text colour — it defaults to black, so on a dark select the caret vanished.
// #94a3b8 reads on both white (light) and dark field backgrounds, and only
// colours the caret — the selected value keeps its --color-text-primary.
const caretSvg = encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="#94a3b8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m4 6 4 4 4-4"/></svg>',
)
const caretStyle = {
  backgroundImage: `url("data:image/svg+xml;utf8,${caretSvg}")`,
  backgroundSize: "1rem",
}

// Native <select> with the canonical chrome — same focus ring, border,
// padding, and disabled state as <Input>. Use for any dropdown the user
// types or scrolls through. For multi-select chip rows prefer <FilterChip>.
export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { size = "md", invalid = false, className, children, ...rest },
  ref,
) {
  return (
    <select
      ref={ref}
      aria-invalid={invalid || undefined}
      className={cn(base, sizeClasses[size], validityClasses(invalid), className)}
      style={caretStyle}
      {...rest}
    >
      {children}
    </select>
  )
})

export type { SelectProps, SelectSize }

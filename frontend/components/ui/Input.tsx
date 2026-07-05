import { forwardRef, type InputHTMLAttributes, type ReactNode } from "react"
import { cn } from "@/lib/shared/utils"

type InputSize = "sm" | "md"

interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "size"> {
  /** Visual size. `sm` = h-8 text-xs (table-row filter), `md` = h-10 text-sm (page-level form, default). */
  size?: InputSize
  /** Optional leading icon (search glyph, link icon, etc.). Renders absolutely positioned. */
  leadingIcon?: ReactNode
  /** Optional trailing icon or addon. Renders absolutely positioned on the right. */
  trailingIcon?: ReactNode
  /** Visible error state — paints the border red and matches focus-ring. */
  invalid?: boolean
}

const base =
  "w-full rounded-md border bg-[var(--color-bg-input)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] transition-colors " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-0 " +
  "disabled:cursor-not-allowed disabled:opacity-50"

const sizeClasses: Record<InputSize, { input: string; iconLeft: string; iconRight: string; padLeft: string; padRight: string }> = {
  sm: {
    input: "h-8 text-xs",
    iconLeft: "left-2.5 h-3.5 w-3.5",
    iconRight: "right-2.5 h-3.5 w-3.5",
    padLeft: "pl-8",
    padRight: "pr-8",
  },
  md: {
    input: "h-10 text-sm",
    iconLeft: "left-3 h-4 w-4",
    iconRight: "right-3 h-4 w-4",
    padLeft: "pl-9",
    padRight: "pr-9",
  },
}

const validityClasses = (invalid: boolean) =>
  invalid
    ? "border-[var(--color-severity-critical-border)] focus-visible:ring-[var(--color-severity-critical)]"
    // border-strong keeps the field readable against surface/well backgrounds in
    // dark mode, where the softer --color-border collapses into the card.
    : "border-[var(--color-border-strong)] focus-visible:ring-[var(--color-accent)]"

// Single source of truth for input chrome. Use this for every text-style input
// (text/email/password/number/url/tel). For `type="search"` with a built-in
// clear button, the existing <SearchInput> wraps this same chrome.
export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  {
    size = "md",
    leadingIcon,
    trailingIcon,
    invalid = false,
    className,
    type = "text",
    ...rest
  },
  ref,
) {
  const cls = sizeClasses[size]
  const padX = cn(
    leadingIcon ? cls.padLeft : "pl-3",
    trailingIcon ? cls.padRight : "pr-3",
  )

  // No wrapper when there's nothing to overlay — keeps callers that pass
  // utility classes like `w-32 md:w-48` working without a parent div eating them.
  if (!leadingIcon && !trailingIcon) {
    return (
      <input
        ref={ref}
        type={type}
        aria-invalid={invalid || undefined}
        className={cn(base, cls.input, padX, validityClasses(invalid), className)}
        {...rest}
      />
    )
  }

  return (
    <div className="relative">
      {leadingIcon && (
        <span
          aria-hidden="true"
          className={cn(
            "pointer-events-none absolute top-1/2 -translate-y-1/2 text-[var(--color-text-tertiary)]",
            cls.iconLeft,
          )}
        >
          {leadingIcon}
        </span>
      )}
      <input
        ref={ref}
        type={type}
        aria-invalid={invalid || undefined}
        className={cn(base, cls.input, padX, validityClasses(invalid), className)}
        {...rest}
      />
      {trailingIcon && (
        <span
          aria-hidden="true"
          className={cn(
            "absolute top-1/2 -translate-y-1/2 text-[var(--color-text-tertiary)]",
            cls.iconRight,
          )}
        >
          {trailingIcon}
        </span>
      )}
    </div>
  )
})

export type { InputProps, InputSize }

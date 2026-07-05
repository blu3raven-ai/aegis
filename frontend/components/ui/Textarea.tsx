import { forwardRef, type TextareaHTMLAttributes } from "react"
import { cn } from "@/lib/shared/utils"

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  /** Visible error state — paints the border red and matches focus-ring. */
  invalid?: boolean
}

const base =
  "w-full rounded-md border bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] transition-colors " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-0 " +
  "disabled:cursor-not-allowed disabled:opacity-50 " +
  "resize-y"

const validityClasses = (invalid: boolean) =>
  invalid
    ? "border-[var(--color-severity-critical-border)] focus-visible:ring-[var(--color-severity-critical)]"
    : "border-[var(--color-border)] focus-visible:ring-[var(--color-accent)]"

// Multi-line input. Matches the <Input>/<Select> chrome family so forms
// don't drift across surfaces. resize-y by default; pass `className="resize-none"`
// to lock it when the height is meaningful (e.g. inside a Sheet footer).
export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { invalid = false, className, rows = 3, ...rest },
  ref,
) {
  return (
    <textarea
      ref={ref}
      rows={rows}
      aria-invalid={invalid || undefined}
      className={cn(base, validityClasses(invalid), className)}
      {...rest}
    />
  )
})

export type { TextareaProps }

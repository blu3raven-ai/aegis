import { type ReactNode, useId } from "react"
import { cn } from "@/lib/shared/utils"

interface FormFieldProps {
  /** Visible label text. Required so every field stays accessible. */
  label: ReactNode
  /** ID to bind the `<label>` to. If omitted, FormField generates one and
   *  expects the child input to spread it via `getInputProps()` — most
   *  callers pass it explicitly to match an existing `id={...}` on the
   *  underlying Input/Select/Textarea. */
  htmlFor?: string
  /** Optional helper text under the input. Hidden when `error` is set. */
  hint?: ReactNode
  /** Error message under the input. Renders in critical color and replaces
   *  the hint. Pair with `<Input invalid={!!error}>` on the child so the
   *  input chrome flips red in lockstep. */
  error?: ReactNode
  /** Render a `*` next to the label and forward `required` semantics to
   *  the form layer. Doesn't auto-validate — pass the child input `required`
   *  separately if you want HTML validation. */
  required?: boolean
  /** Suffix slot rendered right of the label (e.g. "Optional", "Show",
   *  "Reveal", a counter). Stays inline with the label baseline. */
  labelSuffix?: ReactNode
  /** Optional className passed to the outer wrapper. */
  className?: string
  /** The input itself — typically <Input>/<Select>/<Textarea>, but any
   *  control works. */
  children: ReactNode
}

// Single source of truth for the form-field shell: label + control + hint/error.
// Pairs naturally with <Input invalid>, <Select invalid>, <Textarea invalid>
// to keep error chrome in sync.
//
// Vertical rhythm: 6px between label and control (mb-1.5), 6px between
// control and hint/error (mt-1.5). Matches the spacing every settings
// modal had already converged on.
export function FormField({
  label,
  htmlFor,
  hint,
  error,
  required = false,
  labelSuffix,
  className,
  children,
}: FormFieldProps) {
  const generatedId = useId()
  const labelId = htmlFor ?? generatedId
  const hasError = error !== undefined && error !== null && error !== false

  return (
    <div className={cn("flex flex-col", className)}>
      <div className="mb-1.5 flex items-baseline justify-between gap-2">
        <label
          htmlFor={labelId}
          className="text-xs font-medium text-[var(--color-text-primary)]"
        >
          {label}
          {required && (
            <span
              aria-hidden="true"
              className="ml-0.5 text-[var(--color-severity-critical-text)]"
            >
              *
            </span>
          )}
        </label>
        {labelSuffix && (
          <span className="text-2xs text-[var(--color-text-tertiary)]">
            {labelSuffix}
          </span>
        )}
      </div>
      {children}
      {hasError ? (
        <p
          role="alert"
          className="mt-1.5 text-xs text-[var(--color-severity-critical-text)]"
        >
          {error}
        </p>
      ) : hint ? (
        <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
          {hint}
        </p>
      ) : null}
    </div>
  )
}

export type { FormFieldProps }

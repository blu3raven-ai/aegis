import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react"
import { cn } from "@/lib/shared/utils"

type ButtonVariant = "primary" | "secondary" | "ghost" | "destructive" | "link"
type ButtonSize = "xs" | "sm" | "md"

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  leadingIcon?: ReactNode
  trailingIcon?: ReactNode
  isLoading?: boolean
  iconOnly?: boolean
}

const base =
  "inline-flex items-center justify-center gap-1.5 rounded-md font-semibold transition-colors " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)] " +
  "disabled:cursor-not-allowed disabled:opacity-50 disabled:pointer-events-none"

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    "bg-[var(--color-accent)] text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)]",
  secondary:
    "border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] hover:bg-[var(--color-bg-hover)]",
  ghost:
    "bg-transparent text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]",
  destructive:
    "bg-[var(--color-severity-critical)] text-[var(--color-on-danger)] hover:opacity-90",
  // Borderless text-style action — for tiny inline triggers (Copy, Re-check,
  // Dismiss, etc.) that sit inside code blocks, table cells, or banners where
  // chrome buttons would be too tall. No height / padding; size prop only
  // affects text scale, not box height.
  link:
    "bg-transparent p-0 text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]",
}

const sizeClasses: Record<ButtonSize, string> = {
  xs: "h-7 px-2.5 text-xs",
  sm: "h-8 px-3 text-xs",
  md: "h-9 px-3.5 text-sm",
}

// link variant strips the box dimensions so it sits inline with surrounding
// text; the size prop only controls the font scale.
const linkSizeClasses: Record<ButtonSize, string> = {
  xs: "text-2xs",
  sm: "text-xs",
  md: "text-sm",
}

const iconOnlySizeClasses: Record<ButtonSize, string> = {
  xs: "h-7 w-7 p-0",
  sm: "h-8 w-8 p-0",
  md: "h-9 w-9 p-0",
}

const iconSize: Record<ButtonSize, string> = {
  xs: "h-3.5 w-3.5",
  sm: "h-3.5 w-3.5",
  md: "h-4 w-4",
}

// Shared with LinkButton so the two stay visually identical without a refactor
// every time the chrome ticks.
export function buttonClassName({
  variant,
  size,
  iconOnly = false,
}: {
  variant: ButtonVariant
  size: ButtonSize
  iconOnly?: boolean
}): string {
  const sizing =
    variant === "link"
      ? linkSizeClasses[size]
      : iconOnly
        ? iconOnlySizeClasses[size]
        : sizeClasses[size]
  return cn(base, variantClasses[variant], sizing)
}

export function buttonIconClassName(size: ButtonSize): string {
  return iconSize[size]
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = "secondary",
    size = "sm",
    leadingIcon,
    trailingIcon,
    isLoading,
    iconOnly,
    disabled,
    type = "button",
    className,
    children,
    ...rest
  },
  ref,
) {
  const isDisabled = disabled || isLoading

  return (
    <button
      ref={ref}
      type={type}
      disabled={isDisabled}
      className={cn(buttonClassName({ variant, size, iconOnly }), className)}
      {...rest}
    >
      {isLoading ? (
        <Spinner className={iconSize[size]} />
      ) : (
        leadingIcon && (
          <span className={cn("inline-flex shrink-0 items-center justify-center", iconSize[size])}>
            {leadingIcon}
          </span>
        )
      )}
      {!iconOnly && children}
      {!isLoading && trailingIcon && (
        <span className={cn("inline-flex shrink-0 items-center justify-center", iconSize[size])}>
          {trailingIcon}
        </span>
      )}
    </button>
  )
})

function Spinner({ className }: { className?: string }) {
  return (
    <svg
      className={cn("animate-spin", className)}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path
        d="M22 12a10 10 0 0 1-10 10"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  )
}

export type { ButtonProps, ButtonVariant, ButtonSize }

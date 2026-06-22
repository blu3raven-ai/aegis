import { forwardRef, type ReactNode } from "react"
import Link, { type LinkProps } from "next/link"
import { cn } from "@/lib/shared/utils"
import { buttonClassName, buttonIconClassName, type ButtonSize, type ButtonVariant } from "./Button"

interface LinkButtonProps extends Omit<LinkProps, "as" | "passHref"> {
  variant?: ButtonVariant
  size?: ButtonSize
  leadingIcon?: ReactNode
  trailingIcon?: ReactNode
  iconOnly?: boolean
  className?: string
  children?: ReactNode
  target?: string
  rel?: string
  "aria-label"?: string
}

// Anchor counterpart to <Button>. Same variants, sizes, and chrome — but the
// caller passes `href` and the rendered element is a Next/Link so client-side
// navigation, prefetching, and active-state work the same as every other link
// in the app.
export const LinkButton = forwardRef<HTMLAnchorElement, LinkButtonProps>(function LinkButton(
  {
    variant = "secondary",
    size = "sm",
    leadingIcon,
    trailingIcon,
    iconOnly = false,
    className,
    children,
    ...rest
  },
  ref,
) {
  const iconCls = buttonIconClassName(size)
  return (
    <Link
      ref={ref}
      className={cn(buttonClassName({ variant, size, iconOnly }), className)}
      {...rest}
    >
      {leadingIcon && <span className={cn("shrink-0", iconCls)}>{leadingIcon}</span>}
      {!iconOnly && children}
      {trailingIcon && <span className={cn("shrink-0", iconCls)}>{trailingIcon}</span>}
    </Link>
  )
})

export type { LinkButtonProps }

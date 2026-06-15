import type { ReactNode } from "react"
import { Button } from "@/components/ui/Button"

interface SettingsHeaderButtonProps {
  onClick: () => void
  icon: ReactNode
  children: ReactNode
}

export function SettingsHeaderButton({
  onClick,
  icon,
  children,
}: SettingsHeaderButtonProps) {
  return (
    <Button variant="primary" onClick={onClick} leadingIcon={icon}>
      {children}
    </Button>
  )
}

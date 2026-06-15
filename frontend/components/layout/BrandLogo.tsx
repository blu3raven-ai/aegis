"use client"

import { useBranding } from "@/lib/client/branding/client"

interface Props {
  className?: string
  fallbackClassName?: string
  size?: "sm" | "md" | "lg"
}

export function BrandLogo({ className, fallbackClassName, size = "md" }: Props) {
  const { logoSrc, name } = useBranding()
  const height = className ? "" : size === "sm" ? "h-6" : size === "lg" ? "h-12" : "h-8"
  const cls = className ?? fallbackClassName ?? ""

  return (
    <img
      src={logoSrc}
      alt={name ?? "Blu3Raven"}
      className={`${height} w-auto object-contain ${cls}`.trim()}
    />
  )
}

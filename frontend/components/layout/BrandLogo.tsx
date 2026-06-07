"use client"

interface Props {
  className?: string
  fallbackClassName?: string
  size?: "sm" | "md" | "lg"
}

export function BrandLogo({ className, fallbackClassName, size = "md" }: Props) {
  const height = className ? "" : size === "sm" ? "h-6" : size === "lg" ? "h-12" : "h-8"
  const cls = className ?? fallbackClassName ?? ""

  return (
    <img
      src="/logo-brand.png"
      alt="Blu3Raven"
      className={`${height} w-auto object-contain ${cls}`.trim()}
    />
  )
}

"use client"

import { useBranding } from "@/lib/client/branding/client"
import { BrandLogo } from "@/components/layout/BrandLogo"
import { LinkButton } from "@/components/ui/LinkButton"

export default function NotFound() {
  const { name: brandName, isVendor } = useBranding()

  return (
    <main className="flex min-h-dvh flex-col items-center justify-center px-6 py-16">
      <div className="flex w-full max-w-md flex-col items-center text-center">
        {/* Branding — vendor identity when name is NULL; customer name otherwise */}
        <BrandLogo className="h-16 w-16 shrink-0 object-contain" />
        <div className="mt-4 flex flex-col items-center">
          {isVendor ? (
            <>
              <span
                className="text-[0.65rem] font-bold uppercase tracking-[0.28em] text-[var(--color-text-secondary)]"
                style={{ fontFamily: "var(--font-space-grotesk)" }}
              >
                Raven Protocol
              </span>
              <span
                className="text-[1.6rem] font-bold leading-none tracking-[-0.04em] text-[var(--color-text-primary)]"
                style={{ fontFamily: "var(--font-space-grotesk)" }}
              >
                Blu3Raven
              </span>
              <span
                className="mt-1 text-xs text-[var(--color-text-secondary)]"
                style={{ fontFamily: "var(--font-manrope)" }}
              >
                Aegis — Vulnerability Management Portal
              </span>
            </>
          ) : (
            <span
              className="max-w-full truncate text-[1.6rem] font-bold leading-none tracking-[-0.04em] text-[var(--color-text-primary)]"
              style={{ fontFamily: "var(--font-space-grotesk)" }}
            >
              {brandName}
            </span>
          )}
        </div>

        {/* Divider keeps the brand and the error message as distinct tiers */}
        <div className="my-8 h-px w-12 bg-[var(--color-border)]" />

        <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          Error 404
        </p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[var(--color-text-primary)]">
          Page not found
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-[var(--color-text-secondary)]">
          The page you’re looking for doesn’t exist or may have moved.
        </p>

        <LinkButton href="/" variant="primary" size="sm" className="mt-8">
          Back to home
        </LinkButton>
      </div>
    </main>
  )
}

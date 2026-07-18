"use client"

import { useEffect } from "react"
import { useSession } from "@/lib/client/use-session"
import { useBranding } from "@/lib/client/branding/client"
import { LoginForm } from "./LoginForm"
import { BrandLogo } from "@/components/layout/BrandLogo"

export default function LoginPage() {
  const { user, loading } = useSession()
  const { name: brandName, isVendor } = useBranding()

  useEffect(() => {
    if (!loading && user) {
      window.location.assign("/")
    }
  }, [user, loading])

  // Show login form while loading or if not authenticated
  // FastAPI redirects authenticated users away from /login if they try accessing it
  return (
    <main 
      className="flex min-h-screen items-center justify-center px-4"
      style={{
        background: `
          repeating-linear-gradient(0deg, rgba(45, 127, 249, 0.02) 0px, rgba(45, 127, 249, 0.02) 1px, transparent 1px, transparent 2px),
          repeating-linear-gradient(90deg, rgba(45, 127, 249, 0.02) 0px, rgba(45, 127, 249, 0.02) 1px, transparent 1px, transparent 2px),
          repeating-linear-gradient(45deg, transparent, transparent 4px, rgba(45, 127, 249, 0.04) 4px, rgba(45, 127, 249, 0.04) 5px),
          radial-gradient(circle at 15% 20%, rgba(45, 127, 249, 0.08) 0%, transparent 40%),
          radial-gradient(circle at 85% 70%, rgba(45, 127, 249, 0.06) 0%, transparent 40%),
          linear-gradient(135deg, #0a0e17 0%, #0f1419 50%, #0a0e17 100%)
        `,
        backgroundSize: '100% 100%, 100% 100%, 100% 100%, 100% 100%, 100% 100%, 100% 100%',
      }}
    >
      <div className="w-full max-w-sm">
        <div className="overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)]">
          {/* Branding header — vendor identity when name is NULL; customer otherwise */}
          <div className="bg-[var(--color-accent-subtle)] px-8 pb-6 pt-8">
            <div className="flex items-center gap-4">
              <BrandLogo className="h-14 w-14 shrink-0 object-contain" />
              <div className="flex min-w-0 flex-col">
                {isVendor ? (
                  <>
                    <span
                      className="font-mono text-[0.65rem] font-bold uppercase tracking-[0.28em] text-[var(--color-text-secondary)]"
                      style={{ fontFamily: "var(--font-jetbrains-mono)" }}
                    >
                      Raven Protocol
                    </span>
                    <span
                      className="text-[1.6rem] font-bold leading-none tracking-[-0.04em] text-[var(--color-text-primary)]"
                      style={{ fontFamily: "var(--font-jetbrains-mono)" }}
                    >
                      Blu3Raven
                    </span>
                    <span
                      className="mt-0.5 text-xs text-[var(--color-text-secondary)]"
                      style={{ fontFamily: "var(--font-jetbrains-mono)" }}
                    >
                      Aegis — Vulnerability Management Portal
                    </span>
                  </>
                ) : (
                  <span
                    className="truncate text-[1.6rem] font-bold leading-none tracking-[-0.04em] text-[var(--color-text-primary)]"
                    style={{ fontFamily: "var(--font-jetbrains-mono)" }}
                  >
                    {brandName}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Login form */}
          <div className="px-8 pb-8 pt-6">
            <h1 className="mb-5 text-center text-lg font-semibold text-[var(--color-text-primary)]">
              Sign in to your account
            </h1>
            <LoginForm />
          </div>
        </div>
      </div>
    </main>
  )
}

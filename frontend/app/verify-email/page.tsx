import { Suspense } from "react"
import { VerifyEmailClient } from "./VerifyEmailClient"

export default function VerifyEmailPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-[var(--color-background)] px-4">
      <div className="w-full max-w-sm">
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 shadow-sm">
          <Suspense fallback={null}>
            <VerifyEmailClient />
          </Suspense>
        </div>
      </div>
    </main>
  )
}

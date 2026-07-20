import { VerifyForm } from "./VerifyForm"

export default function VerifyPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-[var(--color-background)] px-4">
      <div className="w-full max-w-sm">
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 shadow-sm">
          <div className="mb-6 text-center">
            <div className="mb-4 flex justify-center">
              <div className="rounded-xl bg-[var(--color-accent-subtle)] p-3">
                <svg
                  className="h-7 w-7 text-[var(--color-accent)]"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={1.5}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M10.5 1.5H8.25A2.25 2.25 0 0 0 6 3.75v16.5a2.25 2.25 0 0 0 2.25 2.25h7.5A2.25 2.25 0 0 0 18 20.25V3.75a2.25 2.25 0 0 0-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 8.25h3m-3 3.75h3m-6 3.75H9m1.5-12H9"
                  />
                </svg>
              </div>
            </div>
            <h1 className="text-xl font-bold text-[var(--color-text-primary)]">
              Two-factor authentication
            </h1>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              Enter the 6-digit code from your authenticator app.
            </p>
          </div>
          <VerifyForm />
        </div>
      </div>
    </main>
  )
}

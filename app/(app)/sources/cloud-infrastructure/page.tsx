import { requirePermission } from "@/lib/server/auth/server"
import { redirect } from "next/navigation"
import { PageHeader } from "@/components/layout/PageHeader"

export const metadata = { title: "Cloud Infrastructure — Sources" }

function CloudIcon() {
  return (
    <div className="p-1.5 bg-[var(--color-accent-subtle)] rounded-lg">
      <svg className="w-5 h-5 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M2.25 15a4.5 4.5 0 0 0 4.5 4.5H18a3.75 3.75 0 0 0 1.332-7.257 3 3 0 0 0-3.758-3.848 5.25 5.25 0 0 0-10.233 2.33A4.502 4.502 0 0 0 2.25 15Z" />
      </svg>
    </div>
  )
}

export default async function CloudInfrastructurePage() {
  const userOrResponse = await requirePermission("view_settings")
  if (userOrResponse instanceof Response) redirect("/")

  return (
    <>
      <PageHeader
        icon={<CloudIcon />}
        title="Cloud Infrastructure"
        org="No accounts connected"
      />
      <main className="mx-auto max-w-7xl px-6 py-8">
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8">
          <div className="max-w-lg">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
              In development
            </p>
            <h2 className="mt-3 text-base font-semibold text-[var(--color-text-primary)]">
              Cloud infrastructure scanning is not available yet
            </h2>
            <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
              This will let you connect AWS, Azure, or GCP accounts to scan for infrastructure misconfigurations and compliance issues. You can start with Git Repository or Container Registry sources in the meantime.
            </p>
          </div>
        </div>
      </main>
    </>
  )
}

import { redirect } from "next/navigation"
import { requireUser } from "@/lib/server/auth/server"
import { AccountContent } from "./AccountContent"

export default async function AccountSettingsPage() {
  const result = await requireUser()
  if (result instanceof Response) redirect("/login")

  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10 space-y-4">
      <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Account</h2>
      <AccountContent />
    </div>
  )
}

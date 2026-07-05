"use client"

import { useEffect } from "react"
import { useSession } from "@/lib/client/use-session"
import { LogoutButton } from "./LogoutButton"

export default function PendingPage() {
  const { user, loading } = useSession()

  useEffect(() => {
    if (loading) return
    if (!user) {
      window.location.assign("/login")
      return
    }
    if (user.status === "active") {
      window.location.assign("/")
    }
  }, [user, loading])

  if (loading) return null

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center px-6 py-16">
      <h1 className="text-3xl font-semibold text-[var(--color-text-primary)]">Access pending</h1>
      <p className="mt-4 text-sm text-[var(--color-text-secondary)]">
        You signed in successfully, but you do not yet have any assigned team resources.
      </p>
      <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
        An administrator can grant access by assigning you to the right teams and resources.
      </p>
      <div className="mt-8">
        <LogoutButton />
      </div>
    </main>
  )
}

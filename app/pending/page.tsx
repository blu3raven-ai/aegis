import { redirect } from "next/navigation"
import { getCurrentUser } from "@/lib/server/auth/server"

export default async function PendingPage() {
  const user = await getCurrentUser()
  if (!user) redirect("/login")
  if (user.status === "active") redirect("/")

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center px-6 py-16">
      <h1 className="text-3xl font-semibold text-[var(--color-text-primary)]">Access pending</h1>
      <p className="mt-4 text-sm text-[var(--color-text-secondary)]">
        You signed in successfully, but you do not yet have any assigned team resources.
      </p>
      <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
        An administrator can grant access by assigning you to the right teams and resources.
      </p>
      <form action="/api/logout" method="post" className="mt-8">
        <button className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)]">
          Log out
        </button>
      </form>
    </main>
  )
}

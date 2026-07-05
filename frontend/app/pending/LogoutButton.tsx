"use client"

import { apiClient } from "@/lib/client/api-client.ts"

export function LogoutButton() {
  async function handleLogout() {
    await apiClient("/api/v1/auth/logout", { method: "POST" }).catch(() => {})
    window.location.href = "/login"
  }

  return (
    <button
      type="button"
      onClick={handleLogout}
      className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)]"
    >
      Log out
    </button>
  )
}

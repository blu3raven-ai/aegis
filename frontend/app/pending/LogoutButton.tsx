"use client"

import { apiClient } from "@/lib/client/api-client.ts"
import { Button } from "@/components/ui/Button"

export function LogoutButton() {
  async function handleLogout() {
    await apiClient("/api/v1/auth/logout", { method: "POST" }).catch(() => {})
    window.location.href = "/login"
  }

  return (
    <Button variant="primary" size="sm" onClick={handleLogout}>
      Log out
    </Button>
  )
}

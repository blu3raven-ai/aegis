"use client"

import { useEffect, useState } from "react"
import { getSettings } from "@/lib/client/settings-api"
import { apiClient } from "@/lib/client/api-client.ts"
import type { RoleRecord } from "@/lib/shared/settings-types"
import { AppShell } from "./AppShell"
import { TimeZoneSync } from "@/components/layout/TimeZoneSync"

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarProps, setSidebarProps] = useState({
    dependenciesEnabled: false,
    container_scanningEnabled: false,
    secretsEnabled: false,
    code_scanningEnabled: false,
    iacEnabled: false,
    policy: null as any,
  })

  useEffect(() => {
    async function loadSidebarData() {
      try {
        const [settingsResult, meResult] = await Promise.allSettled([
          getSettings(),
          apiClient<{ user: { roleId?: string | null } }>("/api/v1/auth/me", {
            suppressUnauthorizedRedirect: false,
          }),
        ])

        const tools =
          settingsResult.status === "fulfilled" && settingsResult.value.ok
            ? settingsResult.value.data.tools
            : null

        let policy: RoleRecord | null = null
        if (meResult.status === "fulfilled" && meResult.value.user.roleId) {
          try {
            const roleData = await apiClient<{ role: RoleRecord }>(
              `/api/v1/workspace/roles/${encodeURIComponent(meResult.value.user.roleId)}`,
            )
            policy = roleData.role
          } catch {
            // policy stays null — fine, permission checks default to role-based
          }
        }

        setSidebarProps({
          dependenciesEnabled: tools?.dependencies_scanning?.enabled ?? false,
          container_scanningEnabled: tools?.container_scanning?.enabled ?? false,
          secretsEnabled: tools?.secret_scanning?.enabled ?? false,
          code_scanningEnabled: tools?.code_scanning?.enabled ?? false,
          iacEnabled: tools?.iac_scanning?.enabled ?? false,
          policy: policy as any,
        })
      } catch {
        // keep defaults — FastAPI auth gate will redirect if truly unauthed
      }
    }
    void loadSidebarData()
  }, [])

  return (
    <AppShell sidebarProps={sidebarProps}>
      <TimeZoneSync />
      {children}
    </AppShell>
  )
}

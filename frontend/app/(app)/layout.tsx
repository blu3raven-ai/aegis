"use client"

import { useEffect, useState } from "react"
import { getSettings } from "@/lib/client/settings-api"
import { apiClient } from "@/lib/client/api-client.ts"
import type { RoleRecord } from "@/lib/shared/settings-types"
import { AppShell } from "./AppShell"

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const [sidebarProps, setSidebarProps] = useState({
    dependenciesEnabled: false,
    containerScanningEnabled: false,
    secretsEnabled: false,
    codeScanningEnabled: false,
    iacEnabled: false,
    policy: null as any,
  })

  useEffect(() => {
    async function loadSidebarData() {
      try {
        const [settingsResult, meResult] = await Promise.allSettled([
          getSettings(),
          apiClient<{ user: { roleId?: string | null } }>("/auth/me", {
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
              `/settings/api/roles/${encodeURIComponent(meResult.value.user.roleId)}`,
            )
            policy = roleData.role
          } catch {
            // policy stays null — fine, permission checks default to role-based
          }
        }

        setSidebarProps({
          dependenciesEnabled: tools?.dependencies?.enabled ?? false,
          containerScanningEnabled: tools?.containerScanning?.enabled ?? false,
          secretsEnabled: tools?.secrets?.enabled ?? false,
          codeScanningEnabled: tools?.codeScanning?.enabled ?? false,
          iacEnabled: tools?.iacSecurity?.enabled ?? false,
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
      {children}
    </AppShell>
  )
}

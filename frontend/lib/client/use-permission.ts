"use client"

import { useEffect, useMemo, useState } from "react"
import { apiClient } from "./api-client.ts"
import { resolveEffectivePermissions } from "@/lib/shared/auth/roles"
import type { Permission } from "@/lib/shared/auth/permissions"

interface CachedPolicy {
  permissions: string[] | null
  pending: Promise<string[]> | null
}

const cache: CachedPolicy = {
  permissions: null,
  pending: null,
}

async function loadPolicy(): Promise<string[]> {
  if (cache.permissions !== null) return cache.permissions
  if (cache.pending !== null) return cache.pending

  cache.pending = (async () => {
    try {
      const me = await apiClient<{ user: { roleId?: string | null } }>(
        "/api/v1/auth/me",
        { suppressUnauthorizedRedirect: false },
      )
      const roleId = me.user.roleId
      if (!roleId) {
        cache.permissions = []
        return cache.permissions
      }
      const roleResp = await apiClient<{ role: { permissions: string[] } }>(
        `/api/v1/workspace/roles/${encodeURIComponent(roleId)}`,
      )
      cache.permissions = roleResp.role.permissions ?? []
      return cache.permissions
    } catch {
      cache.permissions = []
      return cache.permissions
    } finally {
      cache.pending = null
    }
  })()

  return cache.pending
}

export function useHasPermission(permission: string): {
  allowed: boolean
  loading: boolean
} {
  const [permissions, setPermissions] = useState<string[] | null>(cache.permissions)

  useEffect(() => {
    if (cache.permissions !== null) {
      setPermissions(cache.permissions)
      return
    }
    let cancelled = false
    void loadPolicy().then((p) => {
      if (!cancelled) setPermissions(p)
    })
    return () => {
      cancelled = true
    }
  }, [])

  // Resolve implied permissions (e.g. manage_settings implies manage_runners)
  // so a held parent permission satisfies a check against one of its children,
  // matching the backend's resolve_role_permissions expansion.
  const effective = useMemo(
    () => (permissions === null ? null : resolveEffectivePermissions(permissions)),
    [permissions],
  )

  return {
    allowed: effective?.has(permission as Permission) ?? false,
    loading: permissions === null,
  }
}

// Test-only helper. Lets unit tests reset the module-scope cache between
// cases without exposing the cache shape directly.
export function __resetPermissionCacheForTests(): void {
  cache.permissions = null
  cache.pending = null
}

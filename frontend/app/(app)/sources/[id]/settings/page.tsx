"use client"

import { use, useEffect, useState } from "react"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { getSourceConnection } from "@/lib/client/sources-api"
import { ScopeConfigContent } from "@/app/(app)/settings/sources/_components/ScopeConfigContent"
import type { SourceCategory } from "@/lib/shared/sources-types"

export default function SourceSettingsPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const { user } = useSession()
  const canEdit = user ? can(user.role as any, "manage_settings") : false
  const [category, setCategory] = useState<SourceCategory | null>(null)

  useEffect(() => {
    let cancelled = false
    getSourceConnection(id).then((r) => {
      if (!cancelled && r.ok) setCategory(r.data.connection.category)
    })
    return () => { cancelled = true }
  }, [id])

  if (!category) {
    return (
      <div className="px-6 py-6">
        <p className="text-sm text-[var(--color-text-secondary)]">Loading…</p>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-5xl px-6 py-6">
      <ScopeConfigContent
        category={category}
        connectionId={id}
        canEdit={canEdit}
        basePath="/sources"
      />
    </div>
  )
}

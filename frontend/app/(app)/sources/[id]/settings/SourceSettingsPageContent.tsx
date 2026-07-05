"use client"

import { useEffect, useState } from "react"
import { useHasPermission } from "@/lib/client/use-permission"
import { getSourceConnection } from "@/lib/client/source-connections-api"
import { useSourceId } from "@/lib/client/use-source-id"
import { ScopeConfigContent } from "@/app/(app)/settings/sources/_components/ScopeConfigContent"
import { SaveBarProvider } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import { GlobalSaveBar } from "@/app/(app)/settings/save-bar/GlobalSaveBar"
import { Skeleton } from "@/components/ui/Skeleton"
import type { SourceCategory } from "@/lib/shared/sources-types"

export function SourceSettingsPageContent() {
  const id = useSourceId()
  const { allowed: canEdit } = useHasPermission("manage_settings")
  const [category, setCategory] = useState<SourceCategory | null>(null)

  useEffect(() => {
    if (!id) return
    let cancelled = false
    getSourceConnection(id).then((r) => {
      if (!cancelled && r.ok) setCategory(r.data.connection.category)
    })
    return () => { cancelled = true }
  }, [id])

  if (!category) {
    return (
      <div className="px-6 py-6 space-y-4">
        <Skeleton className="h-7 w-48" />
        <Skeleton className="h-40 rounded-lg" />
        <Skeleton className="h-56 rounded-lg" />
      </div>
    )
  }

  return (
    <SaveBarProvider>
      <div className="px-6 py-6">
        <ScopeConfigContent
          category={category}
          connectionId={id}
          canEdit={canEdit}
          basePath="/sources"
          embedded
        />
      </div>
      <GlobalSaveBar />
    </SaveBarProvider>
  )
}

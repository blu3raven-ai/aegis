"use client"

import { useState, useEffect } from "react"
import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"
import { getSourceConnection } from "@/lib/client/source-connections-api"
import { useSourceId } from "@/lib/client/use-source-id"
import type { SourceConnection } from "@/lib/shared/sources-types"

export default function SourceFindingsBoard() {
  const id = useSourceId()
  const [connection, setConnection] = useState<SourceConnection | null>(null)

  useEffect(() => {
    if (!id) return
    let cancelled = false
    getSourceConnection(id).then((result) => {
      if (!cancelled && result.ok) setConnection(result.data.connection)
    })
    return () => { cancelled = true }
  }, [id])

  const scopeRepos = connection?.discoveredItems?.length
    ? connection.discoveredItems
    : undefined

  return (
    <FindingsBoardView
      hideHeader
      compactHeader
      pageTitle="Findings"
      pageIcon={<FindingsIcon />}
      scopeRepos={scopeRepos}
    />
  )
}

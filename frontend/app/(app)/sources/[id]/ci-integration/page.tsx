"use client"
import { use, useEffect, useState } from "react"
import { getSourceConnection } from "@/lib/client/sources-api"
import type { SourceConnection, SourceType } from "@/lib/shared/sources-types"
import { CiSnippetPicker, type ScmType } from "@/components/sources/CiSnippetPicker"

const SOURCE_TO_SCM: Record<SourceType, ScmType> = {
  "github":          "github",
  "gitlab":          "gitlab",
  "gitlab-registry": "gitlab",
  "bitbucket":       "bitbucket",
  "gitea":           "github",
  "docker-hub":      "github",
  "ghcr":            "github",
  "ecr":             "github",
  "acr":             "github",
  "gcr":             "github",
}

export default function SourceCiIntegrationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const [connection, setConnection] = useState<SourceConnection | null>(null)

  useEffect(() => {
    getSourceConnection(id).then(r => { if (r.ok) setConnection(r.data.connection) })
  }, [id])

  const defaultTab: ScmType = connection ? SOURCE_TO_SCM[connection.sourceType] : "github"

  return (
    <div className="max-w-3xl">
      <CiSnippetPicker sourceId={id} defaultTab={defaultTab} />
    </div>
  )
}

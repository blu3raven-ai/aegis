"use client"

import { useCallback, useEffect, useState } from "react"
import type { AppConfig } from "@/lib/server/app-config"
import { ToolSettingsForm } from "../ToolSettingsForm"
import { formatSettingsError, getSettings } from "@/lib/client/settings-api"
import { listSourceConnections } from "@/lib/client/sources-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { NoSourcesBanner } from "@/components/shared/NoSourcesBanner"
import { Button } from "@/components/ui/Button"

function getOrgsFromSources(connections: SourceConnection[]): string[] {
  const orgs = new Set<string>()
  for (const c of connections) {
    const org = c.auth.orgOrOwner || c.auth.groupOrProject || c.auth.username
    if (org) orgs.add(org)
  }
  return Array.from(orgs)
}

export function IacSecurityContent() {
  const [settings, setSettings] = useState<AppConfig | null>(null)
  const [sources, setSources] = useState<SourceConnection[]>([])
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const loadSettings = useCallback(async () => {
    setIsLoading(true)
    setError(null)

    try {
      const [settingsResult, sourcesResult] = await Promise.all([
        getSettings(),
        listSourceConnections("code-repositories"),
      ])
      if (settingsResult.ok) {
        setSettings(settingsResult.data)
      } else {
        setError(settingsResult.error)
      }
      if (sourcesResult.ok) {
        setSources(sourcesResult.data.connections)
      }
    } catch (loadError) {
      setError(formatSettingsError(loadError))
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadSettings()
  }, [loadSettings])

  if (isLoading) {
    return (
      <div className="space-y-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
        <div className="h-6 w-40 animate-pulse rounded bg-[var(--color-surface)]" />
        <div className="h-10 animate-pulse rounded-lg bg-[var(--color-surface)]" />
        <div className="h-28 animate-pulse rounded-lg bg-[var(--color-surface)]" />
      </div>
    )
  }

  if (!settings) {
    return (
      <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-3 text-sm text-[var(--color-severity-critical)]">
        <p>{error ?? "Could not load settings."}</p>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => void loadSettings()}
          className="mt-3 border-[var(--color-severity-critical-border)] bg-transparent text-[var(--color-severity-critical)] hover:border-[var(--color-severity-critical-border)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical)]"
        >
          Retry
        </Button>
      </div>
    )
  }

  const managedOrgs = getOrgsFromSources(sources)
  const hasManagedOrgs = managedOrgs.length > 0

  return (
    <div className="space-y-6">
      {!hasManagedOrgs ? (
        <NoSourcesBanner
          sourceLabel="Git Repository"
          sourceHref="/sources"
          toolLabel="IaC security scanning"
        />
      ) : (
      <ToolSettingsForm
        tool="iacSecurity"
        title="Infrastructure as Code (IaC) Security"
        description="Configure security scanning for infrastructure-as-code templates and configurations."
        enabled={settings.tools.iacSecurity.enabled}
        initialValues={{}}
        fields={[]}
      />
      )}
    </div>
  )
}


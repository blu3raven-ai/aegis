"use client"

import { useCallback, useEffect, useState } from "react"
import type { AppConfig } from "@/lib/server/app-config"
import { formatSettingsError, getSettings } from "@/lib/client/settings-api"
import { listSourceConnections } from "@/lib/client/source-connections-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { SecretsSetupForm } from "./SecretsSetupForm"
import { NoSourcesBanner } from "@/components/shared/NoSourcesBanner"
import { Button } from "@/components/ui/Button"
import { useSecretsPrerequisites } from "../PrerequisitePanel"

function getOrgsFromSources(connections: SourceConnection[]): string[] {
  const orgs = new Set<string>()
  for (const c of connections) {
    const org = c.auth.orgOrOwner || c.auth.groupOrProject || c.auth.username
    if (org) orgs.add(org)
  }
  return Array.from(orgs)
}

export function SecretsContent({ canEdit = true }: { canEdit?: boolean }) {
  const [settings, setSettings] = useState<AppConfig | null>(null)
  const [sources, setSources] = useState<SourceConnection[]>([])
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const {
    items: prereqItems,
    isRefreshing: prereqRefreshing,
    refresh: refreshPrereqs,
    canEnable,
  } = useSecretsPrerequisites()

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
      <div className="space-y-3 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
        <div className="h-6 w-32 animate-pulse rounded bg-[var(--color-surface)]" />
        <div className="h-10 animate-pulse rounded-md bg-[var(--color-surface)]" />
        <div className="h-28 animate-pulse rounded-md bg-[var(--color-surface)]" />
      </div>
    )
  }

  if (!settings) {
    return (
      <div className="rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-3 text-sm text-[var(--color-severity-critical)]">
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
          toolLabel="Secret scanning"
        />
      ) : (
      <SecretsSetupForm
        initialValues={{
          scanConcurrency: settings.tools.secret_scanning.scanConcurrency,
          scanDepth: settings.tools.secret_scanning.scanDepth,
          scanHistoryWindow: settings.tools.secret_scanning.scanHistoryWindow,
          autoRerunEnabled: settings.tools.secret_scanning.autoRerunEnabled,
          rerunScheduleType: settings.tools.secret_scanning.rerunScheduleType,
          rerunScheduleValue: settings.tools.secret_scanning.rerunScheduleValue,
        }}
        prereqItems={prereqItems}
        prereqRefreshing={prereqRefreshing}
        refreshPrereqs={refreshPrereqs}
        canEnable={canEnable}
        canEdit={canEdit}
      />
      )}
    </div>
  )
}


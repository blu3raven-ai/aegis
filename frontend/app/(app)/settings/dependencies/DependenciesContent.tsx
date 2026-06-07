"use client"

import { useCallback, useEffect, useState } from "react"
import type { AppConfig } from "@/lib/server/app-config"
import { useDependenciesPrerequisites } from "../PrerequisitePanel"
import { formatSettingsError, getSettings } from "@/lib/client/settings-api"
import { listSourceConnections } from "@/lib/client/sources-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { DependenciesSetupForm } from "./DependenciesSetupForm"
import { NoSourcesBanner } from "@/components/shared/NoSourcesBanner"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"

function getOrgsFromSources(connections: SourceConnection[]): string[] {
  const orgs = new Set<string>()
  for (const c of connections) {
    const org = c.auth.orgOrOwner || c.auth.groupOrProject || c.auth.username
    if (org) orgs.add(org)
  }
  return Array.from(orgs)
}

export function DependenciesContent({ canEdit = true }: { canEdit?: boolean }) {
  const [settings, setSettings] = useState<AppConfig | null>(null)
  const [sources, setSources] = useState<SourceConnection[]>([])
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const {
    items: prereqItems,
    isRefreshing: prereqRefreshing,
    refresh: refreshPrereqs,
    canEnable,
    passingCount,
    totalCount,
  } = useDependenciesPrerequisites()

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
        <div className="h-6 w-32 animate-pulse rounded bg-[var(--color-surface)]" />
        <div className="h-10 animate-pulse rounded-lg bg-[var(--color-surface)]" />
        <div className="h-28 animate-pulse rounded-lg bg-[var(--color-surface)]" />
      </div>
    )
  }

  if (!settings) {
    return (
      <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-3 text-sm text-[var(--color-severity-critical)]">
        <p>{error ?? "Could not load settings."}</p>
        <button
          type="button"
          onClick={() => void loadSettings()}
          className="mt-3 rounded-lg border border-[var(--color-severity-critical-border)] px-3 py-2 text-sm font-medium text-[var(--color-severity-critical)] transition-colors hover:bg-[var(--color-severity-critical-subtle)]"
        >
          Retry
        </button>
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
          sourceHref="/repos"
          toolLabel="Dependency scanning"
        />
      ) : (
      <DependenciesSetupForm
        initialAutoRerunEnabled={settings.tools.dependencies.autoRerunEnabled}
        initialRerunScheduleType={settings.tools.dependencies.rerunScheduleType}
        initialRerunScheduleValue={settings.tools.dependencies.rerunScheduleValue}
        initialScanConcurrency={settings.tools.dependencies.scanConcurrency}
        prereqItems={prereqItems}
        prereqRefreshing={prereqRefreshing}
        refreshPrereqs={refreshPrereqs}
        canEnable={canEnable}
        passingCount={passingCount}
        totalCount={totalCount}
        canEdit={canEdit}
        initialNvdEnabled={settings.tools.dependencies.nvdEnabled ?? true}
        initialNvdApiKey={settings.tools.dependencies.nvdApiKey ?? ""}
        initialNvdApiKeyHint={settings.tools.dependencies.nvdApiKeyHint ?? ""}
        initialGhsaEnabled={settings.tools.dependencies.ghsaEnabled ?? false}
        initialGhsaApiKey={settings.tools.dependencies.ghsaApiKey ?? ""}
        initialGhsaApiKeyHint={settings.tools.dependencies.ghsaApiKeyHint ?? ""}
        initialArgusEnabled={false}
        initialArgusApiKey=""
        initialArgusApiKeyHint=""
        containerAdvisoryConfig={{
          nvdEnabled: settings.tools.containerScanning.nvdEnabled ?? false,
          ghsaEnabled: settings.tools.containerScanning.ghsaEnabled ?? false,
        }}
        containerHasAdvisory={
          ((settings.tools.containerScanning.nvdEnabled ?? false) && !!(settings.tools.containerScanning.nvdApiKeyHint || settings.tools.containerScanning.nvdApiKey || "")) ||
          ((settings.tools.containerScanning.ghsaEnabled ?? false) && !!(settings.tools.containerScanning.ghsaApiKeyHint || settings.tools.containerScanning.ghsaApiKey || ""))
        }
        onCopyAdvisory={async () => {
          try {
            await apiClient("/settings/api/copy-advisory-sources", {
              method: "POST",
              body: { source: "containerScanning", target: "dependencies" },
            })
          } catch (err) {
            if (err instanceof ApiClientError) {
              const body = err.body as { error?: string } | null
              throw new Error(body?.error || "Copy failed")
            }
            throw err
          }
          await loadSettings()
        }}
      />
      )}
    </div>
  )
}


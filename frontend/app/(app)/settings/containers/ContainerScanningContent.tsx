"use client"

import { useCallback, useEffect, useState } from "react"
import type { AppConfig } from "@/lib/server/app-config"
import { useContainerScanningPrerequisites } from "../PrerequisitePanel"
import { formatSettingsError, getSettings } from "@/lib/client/settings-api"
import { listSourceConnections } from "@/lib/client/source-connections-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { ContainerScanningSetupForm } from "./ContainerScanningSetupForm"
import { NoSourcesBanner } from "@/components/shared/NoSourcesBanner"
import { Button } from "@/components/ui/Button"
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

export function ContainerScanningContent({ canEdit = true }: { canEdit?: boolean }) {
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
  } = useContainerScanningPrerequisites()

  const loadSettings = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const [settingsResult, sourcesResult] = await Promise.all([
        getSettings(),
        listSourceConnections("container-registry"),
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
          sourceLabel="Container Registry"
          sourceHref="/sources"
          toolLabel="Container scanning"
        />
      ) : (
      <ContainerScanningSetupForm
        initialAutoRerunEnabled={settings.tools.container_scanning.autoRerunEnabled}
        initialRerunScheduleType={settings.tools.container_scanning.rerunScheduleType}
        initialRerunScheduleValue={settings.tools.container_scanning.rerunScheduleValue}
        initialScanConcurrency={settings.tools.container_scanning.scanConcurrency}
        prereqItems={prereqItems}
        prereqRefreshing={prereqRefreshing}
        refreshPrereqs={refreshPrereqs}
        canEnable={canEnable}
        passingCount={passingCount}
        totalCount={totalCount}
        canEdit={canEdit}
        initialNvdEnabled={settings.tools.container_scanning.nvdEnabled ?? true}
        initialNvdApiKey={settings.tools.container_scanning.nvdApiKey ?? ""}
        initialNvdApiKeyHint={settings.tools.container_scanning.nvdApiKeyHint ?? ""}
        initialGhsaEnabled={settings.tools.container_scanning.ghsaEnabled ?? false}
        initialGhsaApiKey={settings.tools.container_scanning.ghsaApiKey ?? ""}
        initialGhsaApiKeyHint={settings.tools.container_scanning.ghsaApiKeyHint ?? ""}
        initialArgusEnabled={false}
        initialArgusApiKey=""
        initialArgusApiKeyHint=""
        scaAdvisoryConfig={{
          nvdEnabled: settings.tools.dependencies_scanning.nvdEnabled ?? false,
          ghsaEnabled: settings.tools.dependencies_scanning.ghsaEnabled ?? false,
        }}
        scaHasAdvisory={
          ((settings.tools.dependencies_scanning.nvdEnabled ?? false) && !!(settings.tools.dependencies_scanning.nvdApiKeyHint || settings.tools.dependencies_scanning.nvdApiKey || "")) ||
          ((settings.tools.dependencies_scanning.ghsaEnabled ?? false) && !!(settings.tools.dependencies_scanning.ghsaApiKeyHint || settings.tools.dependencies_scanning.ghsaApiKey || ""))
        }
        onCopyAdvisory={async () => {
          try {
            await apiClient("/api/v1/enrichment/advisory-sources/copy", {
              method: "POST",
              body: { source: "dependencies_scanning", target: "container_scanning" },
            })
          } catch (err) {
            if (err instanceof ApiClientError) {
              const body = err.body as { detail?: string; error?: string } | null
              throw new Error(body?.detail || body?.error || "Copy failed")
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

"use client"

import { useCallback, useEffect, useState } from "react"
import type { AppConfig } from "@/lib/server/app-config"
import { useContainerScanningPrerequisites } from "../PrerequisitePanel"
import { formatSettingsError, getSettings } from "@/lib/client/settings-api"
import { listSourceConnections } from "@/lib/client/sources-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { ContainerScanningSetupForm } from "./ContainerScanningSetupForm"
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
          sourceLabel="Container Registry"
          sourceHref="/images"
          toolLabel="Container scanning"
        />
      ) : (
      <ContainerScanningSetupForm
        initialAutoRerunEnabled={settings.tools.containerScanning.autoRerunEnabled}
        initialRerunScheduleType={settings.tools.containerScanning.rerunScheduleType}
        initialRerunScheduleValue={settings.tools.containerScanning.rerunScheduleValue}
        initialScanConcurrency={settings.tools.containerScanning.scanConcurrency}
        prereqItems={prereqItems}
        prereqRefreshing={prereqRefreshing}
        refreshPrereqs={refreshPrereqs}
        canEnable={canEnable}
        passingCount={passingCount}
        totalCount={totalCount}
        canEdit={canEdit}
        initialNvdEnabled={settings.tools.containerScanning.nvdEnabled ?? true}
        initialNvdApiKey={settings.tools.containerScanning.nvdApiKey ?? ""}
        initialNvdApiKeyHint={settings.tools.containerScanning.nvdApiKeyHint ?? ""}
        initialGhsaEnabled={settings.tools.containerScanning.ghsaEnabled ?? false}
        initialGhsaApiKey={settings.tools.containerScanning.ghsaApiKey ?? ""}
        initialGhsaApiKeyHint={settings.tools.containerScanning.ghsaApiKeyHint ?? ""}
        initialArgusEnabled={false}
        initialArgusApiKey=""
        initialArgusApiKeyHint=""
        scaAdvisoryConfig={{
          nvdEnabled: settings.tools.dependencies.nvdEnabled ?? false,
          ghsaEnabled: settings.tools.dependencies.ghsaEnabled ?? false,
        }}
        scaHasAdvisory={
          ((settings.tools.dependencies.nvdEnabled ?? false) && !!(settings.tools.dependencies.nvdApiKeyHint || settings.tools.dependencies.nvdApiKey || "")) ||
          ((settings.tools.dependencies.ghsaEnabled ?? false) && !!(settings.tools.dependencies.ghsaApiKeyHint || settings.tools.dependencies.ghsaApiKey || ""))
        }
        onCopyAdvisory={async () => {
          try {
            await apiClient("/settings/api/copy-advisory-sources", {
              method: "POST",
              body: { source: "dependencies", target: "containerScanning" },
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

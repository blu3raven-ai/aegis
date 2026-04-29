"use client"

import { useCallback, useEffect, useState } from "react"
import type { AppConfig } from "@/lib/server/app-config"
import { useContainerScanningPrerequisites } from "../PrerequisitePanel"
import { formatSettingsError, getSettings } from "@/lib/client/settings-api"
import { listSourceConnections } from "@/lib/client/sources-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { ContainerScanningSetupForm } from "./ContainerScanningSetupForm"
import { NoSourcesBanner } from "@/components/shared/NoSourcesBanner"

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
      <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/30 dark:text-red-400">
        <p>{error ?? "Could not load settings."}</p>
        <button
          type="button"
          onClick={() => void loadSettings()}
          className="mt-3 rounded-lg border border-red-200 px-3 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100 dark:border-red-800 dark:text-red-300 dark:hover:bg-red-900/40"
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
          sourceHref="/sources/container-registry"
          toolLabel="Container scanning"
        />
      ) : (
      <ContainerScanningSetupForm
        initialAutoRerunEnabled={settings.tools.containerScanning.autoRerunEnabled}
        initialRerunScheduleType={settings.tools.containerScanning.rerunScheduleType}
        initialRerunScheduleValue={settings.tools.containerScanning.rerunScheduleValue}
        initialScanConcurrency={settings.tools.containerScanning.scanConcurrency}
        initialRetentionDays={settings.tools.containerScanning.retentionDays ?? 7}
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
          const res = await fetch("/api/settings/copy-advisory-sources", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ source: "dependencies", target: "containerScanning" }),
          })
          if (!res.ok) {
            const data = await res.json().catch(() => ({}))
            throw new Error(data.error || "Copy failed")
          }
          await loadSettings()
        }}
      />
      )}
    </div>
  )
}

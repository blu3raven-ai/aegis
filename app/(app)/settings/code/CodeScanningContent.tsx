"use client"

import { useCallback, useEffect, useState } from "react"
import type { AppConfig } from "@/lib/server/app-config"
import { formatSettingsError, getSettings } from "@/lib/client/settings-api"
import { listSourceConnections } from "@/lib/client/sources-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { CodeScanningSetupForm } from "./CodeScanningSetupForm"
import { NoSourcesBanner } from "@/components/shared/NoSourcesBanner"
import { useCodeScanningPrerequisites } from "../PrerequisitePanel"

function getOrgsFromSources(connections: SourceConnection[]): string[] {
  const orgs = new Set<string>()
  for (const c of connections) {
    const org = c.auth.orgOrOwner || c.auth.groupOrProject || c.auth.username
    if (org) orgs.add(org)
  }
  return Array.from(orgs)
}

const DEEP_LANGUAGES = [
  "Python", "JavaScript", "TypeScript", "Java", "Go",
  "Ruby", "PHP", "C", "C++", "Kotlin", "Swift", "Rust",
]

const FRAMEWORK_LANGUAGES = [
  "Django", "Flask", "Express", "React", "Spring",
]

const BASIC_LANGUAGES = [
  "Bash", "Dockerfile", "HCL", "YAML", "Scala", "Visual Basic",
]

function LanguageSupport() {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
      <p className="mb-1 text-sm font-semibold text-[var(--color-text-primary)]">Language Support</p>
      <p className="mb-4 text-xs text-[var(--color-text-secondary)]">
        Deep analysis languages receive taint flow tracing and import-aware AI review.
        Pattern matching languages use code window context only.
      </p>
      <div className="space-y-3">
        <div>
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-[var(--color-text-secondary)]">
            Deep Analysis
          </p>
          <div className="flex flex-wrap gap-1.5">
            {DEEP_LANGUAGES.map((lang) => (
              <span
                key={lang}
                className="inline-flex items-center rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400"
              >
                {lang}
              </span>
            ))}
          </div>
        </div>
        <div>
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-[var(--color-text-secondary)]">
            Frameworks
          </p>
          <div className="flex flex-wrap gap-1.5">
            {FRAMEWORK_LANGUAGES.map((lang) => (
              <span
                key={lang}
                className="inline-flex items-center rounded-full bg-[var(--color-accent-subtle)] px-2.5 py-0.5 text-xs font-medium text-[var(--color-accent)]"
              >
                {lang}
              </span>
            ))}
          </div>
        </div>
        <div>
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-[var(--color-text-secondary)]">
            Pattern Matching
          </p>
          <div className="flex flex-wrap gap-1.5">
            {BASIC_LANGUAGES.map((lang) => (
              <span
                key={lang}
                className="inline-flex items-center rounded-full border border-[var(--color-border)] px-2.5 py-0.5 text-xs font-medium text-[var(--color-text-secondary)]"
              >
                {lang}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export function CodeScanningContent({ canEdit = true }: { canEdit?: boolean }) {
  const {
    items: prereqItems,
    isRefreshing: prereqRefreshing,
    refresh: refreshPrereqs,
    canEnable,
    passingCount,
    totalCount,
  } = useCodeScanningPrerequisites()

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
          sourceLabel="Git Repository"
          sourceHref="/sources/code-repositories"
          toolLabel="Code scanning (SAST)"
        />
      ) : (<>
      <CodeScanningSetupForm
        initialScanConcurrency={settings.tools.codeScanning.scanConcurrency}
        initialRulesets={Array.isArray(settings.tools.codeScanning.rulesets) ? settings.tools.codeScanning.rulesets.join(",") : settings.tools.codeScanning.rulesets}
        initialAiReviewEnabled={settings.tools.codeScanning.aiReviewEnabled}
        initialAiApiKey={settings.tools.codeScanning.aiApiKey}
        initialAiBaseUrl={settings.tools.codeScanning.aiBaseUrl}
        initialAiModelName={settings.tools.codeScanning.aiModelName}
        initialAiAutoClassifyOnScan={settings.tools.codeScanning.aiAutoClassifyOnScan}
        initialAutoRerunEnabled={settings.tools.codeScanning.autoRerunEnabled}
        initialRerunScheduleType={settings.tools.codeScanning.rerunScheduleType}
        initialRerunScheduleValue={settings.tools.codeScanning.rerunScheduleValue}
        initialRetentionDays={settings.tools.codeScanning.retentionDays ?? 7}
        prereqItems={prereqItems}
        prereqRefreshing={prereqRefreshing}
        refreshPrereqs={refreshPrereqs}
        canEnable={canEnable}
        passingCount={passingCount}
        totalCount={totalCount}
        canEdit={canEdit}
        languageSupport={<LanguageSupport />}
      />
      </>)}
    </div>
  )
}

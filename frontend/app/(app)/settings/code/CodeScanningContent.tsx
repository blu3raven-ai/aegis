"use client"

import { useCallback, useEffect, useState } from "react"
import type { AppConfig } from "@/lib/server/app-config"
import { formatSettingsError, getSettings } from "@/lib/client/settings-api"
import { listSourceConnections } from "@/lib/client/source-connections-api"
import type { SourceConnection } from "@/lib/shared/sources-types"
import { CodeScanningSetupForm } from "./CodeScanningSetupForm"
import { NoSourcesBanner } from "@/components/shared/NoSourcesBanner"
import { Button } from "@/components/ui/Button"
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
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
      <p className="mb-1 text-sm font-semibold text-[var(--color-text-primary)]">Language Support</p>
      <p className="mb-4 text-xs text-[var(--color-text-secondary)]">
        Deep analysis languages receive taint flow tracing and reachability analysis.
        Pattern matching languages use code window context only.
      </p>
      <div className="space-y-3">
        <div>
          <p className="mb-2 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Deep Analysis
          </p>
          <div className="flex flex-wrap gap-1.5">
            {DEEP_LANGUAGES.map((lang) => (
              <span
                key={lang}
                className="inline-flex items-center rounded-full bg-[var(--color-status-ok-subtle)] px-2.5 py-0.5 text-xs font-medium text-[var(--color-status-ok)]"
              >
                {lang}
              </span>
            ))}
          </div>
        </div>
        <div>
          <p className="mb-2 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
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
          <p className="mb-2 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
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
          toolLabel="Code scanning (SAST)"
        />
      ) : (<>
      <CodeScanningSetupForm
        initialScanConcurrency={settings.tools.code_scanning.scanConcurrency}
        initialRulesets={Array.isArray(settings.tools.code_scanning.rulesets) ? settings.tools.code_scanning.rulesets.join(",") : settings.tools.code_scanning.rulesets}
        initialAutoRerunEnabled={settings.tools.code_scanning.autoRerunEnabled}
        initialRerunScheduleType={settings.tools.code_scanning.rerunScheduleType}
        initialRerunScheduleValue={settings.tools.code_scanning.rerunScheduleValue}
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

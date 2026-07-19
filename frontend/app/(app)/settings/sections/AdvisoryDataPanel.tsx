"use client"

import { useCallback, useEffect, useState } from "react"

import { useHasPermission } from "@/lib/client/use-permission"
import { getSettings, saveToolSettings } from "@/lib/client/settings-api"
import {
  getEnrichmentStatus,
  refreshOsvMirror,
  type EnrichmentStatus,
} from "@/lib/client/enrichment-api"
import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import { relativeTime } from "@/lib/shared/relative-time"
import { SettingsCard } from "@/components/shared/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import { Button } from "@/components/ui/Button"
import { AdvisorySourcesGrid } from "../_components/AdvisorySourcesGrid"
import { ArgusConnectionContent } from "../llm/ArgusConnectionContent"
import type { DetailComponentProps } from "../registry"

/**
 * Advisory Data settings: the shared advisory feeds that drive vulnerability
 * matching and enrichment for every scanner. Three parts:
 *   1. Advisory mirror — freshness/size of the built-in OSV/EPSS/KEV feeds and
 *      an on-demand refresh (the feeds also refresh nightly).
 *   2. Advisory sources — optional NVD/GHSA keys that enrich CVE detail. Applied
 *      to both dependency and container matching, so they live here once.
 *   3. Argus — the hosted threat-intel add-on, offered as a plugin on top.
 */
export function AdvisoryDataDetail({ onChanged }: DetailComponentProps) {
  const { allowed: canEdit, loading: permLoading } = useHasPermission("manage_settings")
  return (
    <div className="flex flex-col gap-6">
      <AdvisoryMirrorCard canRefresh={canEdit} />
      <AdvisorySourcesCard canEdit={canEdit} />
      <SettingsCard
        eyebrow="Suggested add-on"
        title="Argus — Hosted Threat Intelligence"
        subtitle="Layer exploit availability, chain risk, and advisory context on top of the built-in feeds above."
      >
        <ArgusConnectionContent
          canEdit={canEdit}
          sessionLoading={permLoading}
          onActiveChange={() => onChanged?.()}
        />
      </SettingsCard>
    </div>
  )
}

interface FeedRowProps {
  name: string
  detail: string
  count: number
  lastRefreshedAt: string | null
  error?: string | null
}

function FeedRow({ name, detail, count, lastRefreshedAt, error }: FeedRowProps) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5">
      <div className="min-w-0">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">{name}</p>
        <p className="text-xs text-[var(--color-text-secondary)]">{detail}</p>
      </div>
      <div className="shrink-0 text-right">
        <p className="text-sm tabular-nums text-[var(--color-text-primary)]">
          {count.toLocaleString()}
        </p>
        <p className="text-xs text-[var(--color-text-tertiary)]">
          {error
            ? "Last refresh failed"
            : lastRefreshedAt
              ? `updated ${relativeTime(lastRefreshedAt)}`
              : "never refreshed"}
        </p>
      </div>
    </div>
  )
}

function AdvisoryMirrorCard({ canRefresh }: { canRefresh: boolean }) {
  const [status, setStatus] = useState<EnrichmentStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setStatus(await getEnrichmentStatus())
      setError(null)
    } catch {
      setError("Couldn't load advisory-mirror status.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function handleRefresh() {
    setRefreshing(true)
    setError(null)
    try {
      await refreshOsvMirror()
      // The refresh runs in the background; re-read so the card reflects the run
      // that just started (and any advisory count already committed).
      await load()
    } catch {
      setError("Couldn't start the refresh. Try again.")
    } finally {
      setRefreshing(false)
    }
  }

  const emptyMirror = !loading && (status?.osv.advisories ?? 0) === 0

  return (
    <SettingsCard
      eyebrow="Advisory Mirror"
      title="Built-in Vulnerability Feeds"
      subtitle="Central advisory data every scanner matches against. Refreshes automatically each night; refresh on demand to bootstrap or pull the latest."
    >
      <div className="space-y-4">
        {loading ? (
          <div className="space-y-2">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-10 animate-pulse rounded-md bg-[var(--color-surface)]" />
            ))}
          </div>
        ) : status ? (
          <div className="divide-y divide-[var(--color-border)]">
            <FeedRow
              name="OSV catalog"
              detail="Open-source vulnerability advisories. Drives dependency & container matching"
              count={status.osv.advisories}
              lastRefreshedAt={status.osv.lastRefreshedAt}
              error={status.osv.error}
            />
            <FeedRow
              name="EPSS scores"
              detail="Exploit-prediction probabilities from FIRST.org"
              count={status.epss.scores}
              lastRefreshedAt={status.epss.lastRefreshedAt}
            />
            <FeedRow
              name="KEV catalog"
              detail="CISA Known Exploited Vulnerabilities"
              count={status.kev.entries}
              lastRefreshedAt={status.kev.lastRefreshedAt}
            />
          </div>
        ) : null}

        {emptyMirror && (
          <div className="rounded-md border border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)] px-3 py-2.5 text-xs text-[var(--color-state-pending-text)]">
            The advisory mirror hasn&apos;t been populated yet. Dependency and container scans
            produce no findings until the first refresh completes. Refresh now to bootstrap it.
          </div>
        )}

        {status?.osv.error && (
          <div className="rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2.5 text-xs text-[var(--color-severity-critical-text)]">
            Last OSV refresh failed: {status.osv.error}
          </div>
        )}

        {error && (
          <p className="text-xs text-[var(--color-severity-critical-text)]">{error}</p>
        )}

        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleRefresh}
            isLoading={refreshing}
            disabled={!canRefresh || refreshing}
          >
            {refreshing ? "Refreshing…" : "Refresh now"}
          </Button>
          {!canRefresh && (
            <span className="text-xs text-[var(--color-text-tertiary)]">
              Only admins can trigger a refresh.
            </span>
          )}
        </div>
      </div>
    </SettingsCard>
  )
}

type AdvisorySourceDraft = {
  enabled: boolean
  apiKey: string
  showKey: boolean
  editingKey: boolean
}

function AdvisorySourcesCard({ canEdit }: { canEdit: boolean }) {
  const [loaded, setLoaded] = useState(false)
  const [initialNvd, setInitialNvd] = useState({ enabled: true, apiKey: "", hint: "" })
  const [initialGhsa, setInitialGhsa] = useState({ enabled: false, apiKey: "", hint: "" })
  const [nvd, setNvd] = useState<AdvisorySourceDraft>({ enabled: true, apiKey: "", showKey: false, editingKey: true })
  const [ghsa, setGhsa] = useState<AdvisorySourceDraft>({ enabled: false, apiKey: "", showKey: false, editingKey: true })
  const [initialReleaseAge, setInitialReleaseAge] = useState({ enabled: false, thresholdDays: "90" })
  const [releaseAge, setReleaseAge] = useState({ enabled: false, thresholdDays: "90" })
  const [initialBaseImageTags, setInitialBaseImageTags] = useState(false)
  const [baseImageTags, setBaseImageTags] = useState(false)
  const [initialBaseImageRecommend, setInitialBaseImageRecommend] = useState(false)
  const [baseImageRecommend, setBaseImageRecommend] = useState(false)
  // Each scanner's current enablement, so advisory saves preserve it rather than
  // force-enabling the tool (and tripping its runner prerequisite).
  const [toolEnabled, setToolEnabled] = useState<Record<string, boolean>>({
    dependencies_scanning: false,
    container_scanning: false,
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    const result = await getSettings()
    if (!result.ok) {
      setError(result.error)
      setLoaded(true)
      return
    }
    // Advisory sources are shared across scanners; read the dependency tool as
    // the source of truth (both tools are written together on save).
    const t = result.data.tools.dependencies_scanning
    setInitialNvd({ enabled: t.nvdEnabled ?? true, apiKey: t.nvdApiKey ?? "", hint: t.nvdApiKeyHint ?? "" })
    setInitialGhsa({ enabled: t.ghsaEnabled ?? false, apiKey: t.ghsaApiKey ?? "", hint: t.ghsaApiKeyHint ?? "" })
    setNvd({ enabled: t.nvdEnabled ?? true, apiKey: t.nvdApiKey ?? "", showKey: false, editingKey: !(t.nvdApiKey ?? "") })
    setGhsa({ enabled: t.ghsaEnabled ?? false, apiKey: t.ghsaApiKey ?? "", showKey: false, editingKey: !(t.ghsaApiKey ?? "") })
    const ra = { enabled: t.releaseAgeEnabled ?? false, thresholdDays: String(t.releaseAgeThresholdDays ?? "90") }
    setInitialReleaseAge(ra)
    setReleaseAge(ra)
    // Base-image tag listing is container-only.
    const bit = result.data.tools.container_scanning.baseImageTagsEnabled ?? false
    setInitialBaseImageTags(bit)
    setBaseImageTags(bit)
    const bir = result.data.tools.container_scanning.baseImageRecommendEnabled ?? false
    setInitialBaseImageRecommend(bir)
    setBaseImageRecommend(bir)
    setToolEnabled({
      dependencies_scanning: result.data.tools.dependencies_scanning.enabled ?? false,
      container_scanning: result.data.tools.container_scanning.enabled ?? false,
    })
    setLoaded(true)
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const isDirty =
    nvd.enabled !== initialNvd.enabled ||
    nvd.apiKey !== initialNvd.apiKey ||
    ghsa.enabled !== initialGhsa.enabled ||
    ghsa.apiKey !== initialGhsa.apiKey ||
    releaseAge.enabled !== initialReleaseAge.enabled ||
    releaseAge.thresholdDays !== initialReleaseAge.thresholdDays ||
    baseImageTags !== initialBaseImageTags ||
    baseImageRecommend !== initialBaseImageRecommend

  const handleSave = useCallback(async () => {
    setError(null)
    if (ghsa.enabled && !ghsa.apiKey.trim() && ghsa.editingKey) {
      setError("A GitHub PAT is required when the GitHub Advisory Database is enabled.")
      return
    }
    setSaving(true)
    // Shared config: write both scanners so advisory sources stay in lockstep.
    // The tool PATCH merges, so this leaves each scanner's scheduling untouched.
    const advisory: Record<string, string> = {
      nvdEnabled: nvd.enabled ? "true" : "false",
      nvdApiKey: nvd.editingKey ? nvd.apiKey : initialNvd.apiKey,
      ghsaEnabled: ghsa.enabled ? "true" : "false",
      ghsaApiKey: ghsa.editingKey ? ghsa.apiKey : initialGhsa.apiKey,
      releaseAgeEnabled: releaseAge.enabled ? "true" : "false",
      releaseAgeThresholdDays: releaseAge.thresholdDays,
      baseImageTagsEnabled: baseImageTags ? "true" : "false",
      baseImageRecommendEnabled: baseImageRecommend ? "true" : "false",
    }
    try {
      for (const tool of ["dependencies_scanning", "container_scanning"] as const) {
        const result = await saveToolSettings({ tool, enabled: toolEnabled[tool] ?? false, settings: advisory })
        if (!result.ok) {
          setError(result.error)
          return
        }
      }
      await load()
    } finally {
      setSaving(false)
    }
  }, [nvd, ghsa, releaseAge, baseImageTags, baseImageRecommend, initialNvd, initialGhsa, toolEnabled, load])

  const handleDiscard = useCallback(() => {
    setNvd({ enabled: initialNvd.enabled, apiKey: initialNvd.apiKey, showKey: false, editingKey: !initialNvd.apiKey })
    setGhsa({ enabled: initialGhsa.enabled, apiKey: initialGhsa.apiKey, showKey: false, editingKey: !initialGhsa.apiKey })
    setReleaseAge(initialReleaseAge)
    setBaseImageTags(initialBaseImageTags)
    setBaseImageRecommend(initialBaseImageRecommend)
    setError(null)
  }, [initialNvd, initialGhsa, initialReleaseAge, initialBaseImageTags, initialBaseImageRecommend])

  useSaveBarSection({
    id: "advisory-sources",
    dirty: isDirty,
    saving,
    count: Number(isDirty),
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  return (
    <SettingsCard
      eyebrow="Advisory Sources"
      title="Optional Enrichment API Keys"
      subtitle="Optional API keys that enrich matched vulnerabilities with CVSS scores, fix versions, and advisory detail. Applied to both dependency and container scanning."
    >
      <fieldset disabled={!canEdit || !loaded} className="disabled:opacity-50">
        <AdvisorySourcesGrid
          canEdit={canEdit}
          includeArgus={false}
          values={{
            nvd: { enabled: nvd.enabled, apiKey: nvd.apiKey, initialApiKey: initialNvd.apiKey, initialApiKeyHint: initialNvd.hint, showKey: nvd.showKey, editingKey: nvd.editingKey },
            ghsa: { enabled: ghsa.enabled, apiKey: ghsa.apiKey, initialApiKey: initialGhsa.apiKey, initialApiKeyHint: initialGhsa.hint, showKey: ghsa.showKey, editingKey: ghsa.editingKey },
          }}
          onChange={{
            nvd: {
              setEnabled: (v) => setNvd((s) => ({ ...s, enabled: v })),
              setApiKey: (v) => setNvd((s) => ({ ...s, apiKey: v })),
              setShowKey: (v) => setNvd((s) => ({ ...s, showKey: v })),
              setEditingKey: (v) => setNvd((s) => ({ ...s, editingKey: v })),
            },
            ghsa: {
              setEnabled: (v) => setGhsa((s) => ({ ...s, enabled: v })),
              setApiKey: (v) => setGhsa((s) => ({ ...s, apiKey: v })),
              setShowKey: (v) => setGhsa((s) => ({ ...s, showKey: v })),
              setEditingKey: (v) => setGhsa((s) => ({ ...s, editingKey: v })),
            },
          }}
        />
        <div className="mt-6 border-t border-[var(--color-border)] pt-6">
          <SettingsRow
            label="Flag recently published versions"
            description="Look up each dependency version's publish date (via deps.dev) to flag supply-chain-fresh releases. Off by default: sends package names to deps.dev, so leave off for air-gapped installs."
          >
            <ToggleSwitch
              label="Toggle release-age enrichment"
              checked={releaseAge.enabled}
              disabled={!canEdit}
              onChange={(next) => setReleaseAge((s) => ({ ...s, enabled: next }))}
            />
          </SettingsRow>
          {releaseAge.enabled && (
            <SettingsRow
              label="Recent threshold (days)"
              description="A version published within this many days of a scan is flagged as recent."
            >
              <input
                type="number"
                min={1}
                max={3650}
                value={releaseAge.thresholdDays}
                disabled={!canEdit}
                onChange={(e) => setReleaseAge((s) => ({ ...s, thresholdDays: e.target.value }))}
                className="h-8 w-24 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 text-sm tabular-nums text-[var(--color-text-primary)]"
              />
            </SettingsRow>
          )}
          <SettingsRow
            label="Recommend newer base-image tags"
            description="List a scanned image's tags from its registry to surface newer versions on container findings. Off by default: reaches the image registry, so leave off for air-gapped installs."
          >
            <ToggleSwitch
              label="Toggle base-image tag recommendations"
              checked={baseImageTags}
              disabled={!canEdit}
              onChange={setBaseImageTags}
            />
          </SettingsRow>
          <SettingsRow
            label="Recommend proven base-image upgrades"
            description="SBOM-scan the newest available tag of each image and recommend it when it has fewer vulnerabilities. Off by default: runs an extra scan per image and reaches the registry, so leave off for air-gapped installs."
          >
            <ToggleSwitch
              label="Toggle base-image upgrade recommendations"
              checked={baseImageRecommend}
              disabled={!canEdit}
              onChange={setBaseImageRecommend}
            />
          </SettingsRow>
        </div>
      </fieldset>
    </SettingsCard>
  )
}

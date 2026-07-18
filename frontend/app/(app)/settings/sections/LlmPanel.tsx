"use client"

import { useEffect, useState } from "react"
import Link from "next/link"

import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import { TestConnectionButton } from "@/components/shared/settings/llm/TestConnectionButton"
import { ApiClientError } from "@/lib/client/api-client.types.ts"
import { useHasPermission } from "@/lib/client/use-permission"
import {
  deleteLlmConfig,
  getLlmConfig,
  updateLlmConfig,
  type LlmPublicConfig,
} from "@/lib/client/llm-settings-api"
import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import type { DetailComponentProps } from "../registry"

interface ByoForm {
  api_key: string
  api_base_url: string
  model: string
  scan_token_budget: number
  daily_token_budget: number
}

const DEFAULT_BYO: ByoForm = {
  api_key: "",
  api_base_url: "https://api.openai.com/v1",
  model: "gpt-4o-mini",
  scan_token_budget: 100_000,
  daily_token_budget: 1_000_000,
}

/** Non-secret fields tracked for dirty detection (api_key is write-only). */
type LlmBaseline = Pick<ByoForm, "api_base_url" | "model" | "scan_token_budget" | "daily_token_budget"> & {
  enabled: boolean
}

const DEFAULT_BASELINE: LlmBaseline = {
  api_base_url: DEFAULT_BYO.api_base_url,
  model: DEFAULT_BYO.model,
  scan_token_budget: DEFAULT_BYO.scan_token_budget,
  daily_token_budget: DEFAULT_BYO.daily_token_budget,
  enabled: false,
}

function baselineOf(cfg: LlmPublicConfig): LlmBaseline {
  return {
    api_base_url: cfg.api_base_url,
    model: cfg.model,
    scan_token_budget: cfg.scan_token_budget,
    daily_token_budget: cfg.daily_token_budget,
    enabled: cfg.enabled,
  }
}

function applyConfig(setByo: (fn: (f: ByoForm) => ByoForm) => void, cfg: LlmPublicConfig): void {
  setByo((f) => ({
    ...f,
    api_base_url: cfg.api_base_url,
    model: cfg.model,
    scan_token_budget: cfg.scan_token_budget,
    daily_token_budget: cfg.daily_token_budget,
  }))
}

/**
 * Bring-your-own-model verification config. The verifier reads scanner findings
 * and confirms real exploits / rules out false positives, tightening precision.
 * The API key is write-only: it's never returned, so an existing key shows as
 * stored and must be re-entered to change the config.
 */
export function LlmDetail({ onChanged }: DetailComponentProps) {
  const { allowed: canEdit, loading: permLoading } = useHasPermission("manage_settings")

  const [byo, setByo] = useState<ByoForm>(DEFAULT_BYO)
  const [enabled, setEnabled] = useState(false)
  const [baseline, setBaseline] = useState<LlmBaseline>(DEFAULT_BASELINE)
  const [keyConfigured, setKeyConfigured] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        // Don't collapse a load failure into "off" — a forbidden/errored read is
        // not the same as "verification is disabled".
        const llm = await getLlmConfig()
        if (cancelled) return
        if (llm) {
          setKeyConfigured(llm.configured)
          setEnabled(llm.enabled)
          applyConfig(setByo, llm)
          setBaseline(baselineOf(llm))
        }
      } catch (e) {
        if (cancelled) return
        setLoadError(
          e instanceof ApiClientError && e.status === 403
            ? "You don't have permission to manage verification."
            : "Couldn't load verification settings.",
        )
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  // A save needs either a freshly entered key or an already-stored one.
  const canSave = byo.api_key.trim().length > 0 || keyConfigured

  const isDirty =
    byo.api_key.trim().length > 0 ||
    byo.api_base_url !== baseline.api_base_url ||
    byo.model !== baseline.model ||
    byo.scan_token_budget !== baseline.scan_token_budget ||
    byo.daily_token_budget !== baseline.daily_token_budget ||
    enabled !== baseline.enabled

  const handleSave = async () => {
    if (!canSave) {
      setError("Enter an API key to save.")
      return
    }
    setSaving(true)
    setError(null)
    try {
      const updated = await updateLlmConfig({ ...byo, enabled })
      setKeyConfigured(updated.configured)
      applyConfig(setByo, updated)
      setBaseline(baselineOf(updated))
      // Drop the entered secret — it's write-only and now stored; the field
      // shows "stored" until the user types a replacement.
      setByo((f) => ({ ...f, api_key: "" }))
      onChanged?.()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save.")
    } finally {
      setSaving(false)
    }
  }

  const handleDiscard = () => {
    setByo({ ...DEFAULT_BYO, ...baseline, api_key: "" })
    setEnabled(baseline.enabled)
    setError(null)
  }

  const remove = async () => {
    setSaving(true)
    setError(null)
    try {
      await deleteLlmConfig()
      setKeyConfigured(false)
      setEnabled(false)
      setByo(DEFAULT_BYO)
      setBaseline(DEFAULT_BASELINE)
      onChanged?.()
    } catch (e) {
      // A 404 means the config is already gone — desired end state, not an error.
      if (e instanceof ApiClientError && e.status === 404) {
        setKeyConfigured(false)
        setEnabled(false)
        onChanged?.()
      } else {
        setError(e instanceof Error ? e.message : "Failed to remove the model.")
      }
    } finally {
      setSaving(false)
    }
  }

  // Register with the page-level save bar so LLM edits are saved/discarded
  // through the same shared bar as the other settings sections.
  useSaveBarSection({
    id: "llm-verification",
    dirty: canEdit && isDirty,
    saving,
    count: Number(canEdit && isDirty),
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  if (loading || permLoading) {
    return <p className="text-sm text-[var(--color-text-tertiary)]">Loading…</p>
  }

  if (loadError) {
    return <p className="text-sm text-[var(--color-severity-critical-text)]">{loadError}</p>
  }

  if (!canEdit) {
    return (
      <div className="flex flex-col gap-4">
        <p className="text-sm text-[var(--color-text-secondary)]">
          {enabled ? `Verification is on using ${byo.model}.` : "Verification is off."}
        </p>
        <p className="text-xs text-[var(--color-text-secondary)]">
          Configuring the verifier needs <span className="font-mono">manage_settings</span> permission. Ask an admin to
          update it.
        </p>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <p className="text-sm text-[var(--color-text-secondary)]">
        Connect your own OpenAI-compatible model to verify scanner findings, confirming real exploits with a cited
        evidence chain and ruling out false positives. Independent of threat-intel enrichment.
      </p>

      <SettingsCard heading="Model">
        <SettingsRow
          label="API key"
          description={
            keyConfigured
              ? "A key is stored. Re-enter it to save changes."
              : "Your provider's secret key. Stored encrypted; never shown again."
          }
        >
          <Input
            type="password"
            size="sm"
            autoComplete="off"
            placeholder={keyConfigured ? "•••• stored" : "sk-…"}
            value={byo.api_key}
            onChange={(e) => setByo((f) => ({ ...f, api_key: e.target.value }))}
          />
        </SettingsRow>
        <SettingsRow label="Base URL" description="OpenAI-compatible endpoint">
          <Input
            size="sm"
            value={byo.api_base_url}
            onChange={(e) => setByo((f) => ({ ...f, api_base_url: e.target.value }))}
          />
        </SettingsRow>
        <SettingsRow label="Model" description="Model identifier">
          <Input size="sm" value={byo.model} onChange={(e) => setByo((f) => ({ ...f, model: e.target.value }))} />
        </SettingsRow>
        <SettingsRow label="Per-scan token budget">
          <Input
            type="number"
            size="sm"
            value={byo.scan_token_budget}
            onChange={(e) => setByo((f) => ({ ...f, scan_token_budget: Number(e.target.value) }))}
          />
        </SettingsRow>
        <SettingsRow label="Daily token budget">
          <Input
            type="number"
            size="sm"
            value={byo.daily_token_budget}
            onChange={(e) => setByo((f) => ({ ...f, daily_token_budget: Number(e.target.value) }))}
          />
        </SettingsRow>
      </SettingsCard>

      <SettingsCard heading="Activation">
        <SettingsRow
          label="Enable LLM verification"
          description="When on, findings from verifiable scanners (SAST, secrets, IaC) are verified by your model and tagged with a verdict (confirmed / needs verify / possible / ruled out)."
        >
          <ToggleSwitch
            checked={enabled}
            onChange={setEnabled}
            label="Enable LLM verification"
          />
        </SettingsRow>
      </SettingsCard>

      {keyConfigured && (
        <p className="text-xs text-[var(--color-text-secondary)]">
          Token spend and daily usage are shown in{" "}
          <Link
            href="/insights?tab=usage"
            className="font-medium text-[var(--color-accent)] hover:underline"
          >
            Insights → Usage
          </Link>
          .
        </p>
      )}

      {keyConfigured && (
        <div className="flex flex-wrap items-center gap-3">
          <TestConnectionButton />
          <Button
            variant="ghost"
            size="md"
            onClick={remove}
            className="text-[var(--color-severity-critical-text)]"
          >
            Remove model
          </Button>
        </div>
      )}
    </div>
  )
}

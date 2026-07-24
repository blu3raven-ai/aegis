"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Pencil } from "lucide-react"

import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Sheet } from "@/components/ui/Sheet"
import { StatusPill } from "@/components/ui/StatusPill"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import { ApiClientError } from "@/lib/client/api-client.types.ts"
import { useHasPermission } from "@/lib/client/use-permission"
import {
  deleteLlmConfig,
  getLlmConfig,
  updateLlmConfig,
  testLlmConnection,
  DEFAULT_LLM_TRANSPORT,
  LLM_TRANSPORTS,
  type LlmConfigUpdate,
  type LlmPublicConfig,
  type LlmTransport,
} from "@/lib/client/llm-settings-api"
import type { DetailComponentProps } from "../registry"

interface ByoForm {
  api_key: string
  api_base_url: string
  model: string
  scan_token_budget: number
  daily_token_budget: number
  transport: LlmTransport
  anthropic_base_url: string
}

const DEFAULT_BYO: ByoForm = {
  api_key: "",
  api_base_url: "https://api.openai.com/v1",
  model: "gpt-4o-mini",
  scan_token_budget: 100_000,
  daily_token_budget: 1_000_000,
  transport: DEFAULT_LLM_TRANSPORT,
  anthropic_base_url: "",
}

/** Persisted, non-secret config used to render the summary and rehydrate the
 *  modal. The api_key is write-only so it never lives here. */
type LlmBaseline = Pick<
  ByoForm,
  "api_base_url" | "model" | "scan_token_budget" | "daily_token_budget" | "transport" | "anthropic_base_url"
>

const DEFAULT_BASELINE: LlmBaseline = {
  api_base_url: DEFAULT_BYO.api_base_url,
  model: DEFAULT_BYO.model,
  scan_token_budget: DEFAULT_BYO.scan_token_budget,
  daily_token_budget: DEFAULT_BYO.daily_token_budget,
  transport: DEFAULT_BYO.transport,
  anthropic_base_url: DEFAULT_BYO.anthropic_base_url,
}

function baselineOf(cfg: LlmPublicConfig): LlmBaseline {
  return {
    api_base_url: cfg.api_base_url,
    model: cfg.model,
    scan_token_budget: cfg.scan_token_budget,
    daily_token_budget: cfg.daily_token_budget,
    transport: cfg.transport ?? DEFAULT_LLM_TRANSPORT,
    anthropic_base_url: cfg.anthropic_base_url ?? "",
  }
}

function applyConfig(setByo: (fn: (f: ByoForm) => ByoForm) => void, cfg: LlmPublicConfig): void {
  setByo((f) => ({
    ...f,
    api_base_url: cfg.api_base_url,
    model: cfg.model,
    scan_token_budget: cfg.scan_token_budget,
    daily_token_budget: cfg.daily_token_budget,
    transport: cfg.transport ?? DEFAULT_LLM_TRANSPORT,
    anthropic_base_url: cfg.anthropic_base_url ?? "",
  }))
}

function transportLabel(t: LlmTransport): string {
  return LLM_TRANSPORTS.find((x) => x.id === t)?.label ?? t
}

/**
 * Bring-your-own-model verification config. The verifier reads scanner findings
 * and confirms real exploits / rules out false positives, tightening precision.
 *
 * A single enable toggle is the primary control; editing happens in a modal that
 * tests the connection before it takes effect. The API key is write-only: it is
 * never returned, so an existing key shows as stored and an empty key on save
 * means "keep the stored key".
 */
export function LlmDetail({ onChanged }: DetailComponentProps) {
  const { allowed: canEdit, loading: permLoading } = useHasPermission("manage_settings")

  const [byo, setByo] = useState<ByoForm>(DEFAULT_BYO)
  const [enabled, setEnabled] = useState(false)
  const [baseline, setBaseline] = useState<LlmBaseline>(DEFAULT_BASELINE)
  const [keyConfigured, setKeyConfigured] = useState(false)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  // Summary-level state (toggle test/disable and remove).
  const [toggleBusy, setToggleBusy] = useState(false)
  const [summaryError, setSummaryError] = useState<string | null>(null)

  // Modal state.
  const [modalOpen, setModalOpen] = useState(false)
  const [testing, setTesting] = useState(false)
  const [modalError, setModalError] = useState<string | null>(null)
  const [modalOk, setModalOk] = useState(false)

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

  // A row with a stored key and the required endpoint fields is "configured" —
  // enough to test/enable without reopening the editor.
  const isConfigured =
    keyConfigured && baseline.model.trim().length > 0 && baseline.api_base_url.trim().length > 0

  // Build a PUT body from the persisted config (no unsaved form edits) with an
  // empty api_key so the stored secret is preserved.
  function persistedPayload(nextEnabled: boolean): LlmConfigUpdate {
    return {
      api_key: "",
      api_base_url: baseline.api_base_url,
      model: baseline.model,
      scan_token_budget: baseline.scan_token_budget,
      daily_token_budget: baseline.daily_token_budget,
      enabled: nextEnabled,
      transport: baseline.transport,
      anthropic_base_url: baseline.anthropic_base_url,
    }
  }

  function openModal() {
    // Pre-fill from persisted config; the secret starts blank (stored placeholder).
    setByo({ ...DEFAULT_BYO, ...baseline, api_key: "" })
    setModalError(null)
    setModalOk(false)
    setSummaryError(null)
    setModalOpen(true)
  }

  const describeError = (e: unknown, fallback: string) =>
    e instanceof Error ? e.message : fallback

  // Enable toggle — three cases:
  //  off -> immediately persist enabled=false (no test, no modal);
  //  on + not configured -> open the editor, do not enable yet;
  //  on + configured -> test first, only enable on success.
  const handleToggle = async (next: boolean) => {
    setSummaryError(null)
    if (!next) {
      setToggleBusy(true)
      try {
        await updateLlmConfig(persistedPayload(false))
        setEnabled(false)
        onChanged?.()
      } catch (e) {
        setSummaryError(describeError(e, "Failed to disable verification."))
      } finally {
        setToggleBusy(false)
      }
      return
    }

    if (!isConfigured) {
      openModal()
      return
    }

    setToggleBusy(true)
    try {
      const result = await testLlmConnection()
      if (!result.ok) {
        setSummaryError(result.detail || result.error || "Connection test failed.")
        return
      }
      await updateLlmConfig(persistedPayload(true))
      setEnabled(true)
      onChanged?.()
    } catch (e) {
      setSummaryError(describeError(e, "Couldn't enable verification."))
    } finally {
      setToggleBusy(false)
    }
  }

  // Modal primary action: persist the edits, then test the live connection.
  // On success enable and close; on failure keep the modal open with the error.
  const canSubmit =
    byo.model.trim().length > 0 &&
    byo.api_base_url.trim().length > 0 &&
    (keyConfigured || byo.api_key.trim().length > 0)

  const handleTestAndSave = async () => {
    if (!canSubmit) {
      setModalError(keyConfigured ? "Model and base URL are required." : "Enter an API key to connect.")
      return
    }
    setTesting(true)
    setModalError(null)
    setModalOk(false)
    try {
      // Persist first (with whatever enabled currently is) so the test runs
      // against the just-saved config. Only flip enabled=true once it passes.
      const saved = await updateLlmConfig({ ...byo, enabled })
      const result = await testLlmConnection()
      if (!result.ok) {
        // Config is stored, but leave verification off until a test passes.
        setKeyConfigured(saved.configured)
        setBaseline(baselineOf(saved))
        applyConfig(setByo, saved)
        setByo((f) => ({ ...f, api_key: "" }))
        setModalError(result.detail || result.error || "Connection test failed.")
        return
      }
      const finalCfg = saved.enabled ? saved : await updateLlmConfig({ ...byo, api_key: "", enabled: true })
      setKeyConfigured(finalCfg.configured)
      setBaseline(baselineOf(finalCfg))
      applyConfig(setByo, finalCfg)
      setByo((f) => ({ ...f, api_key: "" }))
      setEnabled(true)
      setModalOk(true)
      onChanged?.()
      window.setTimeout(() => {
        setModalOpen(false)
        setModalOk(false)
      }, 900)
    } catch (e) {
      setModalError(describeError(e, "Failed to save."))
    } finally {
      setTesting(false)
    }
  }

  const remove = async () => {
    setToggleBusy(true)
    setSummaryError(null)
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
        setSummaryError(describeError(e, "Failed to remove the model."))
      }
    } finally {
      setToggleBusy(false)
    }
  }

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
          {enabled ? `Verification is on using ${baseline.model}.` : "Verification is off."}
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

      <SettingsCard heading="Verification">
        <SettingsRow
          label="Enable LLM verification"
          description="When on, findings from verifiable scanners (SAST, secrets, IaC) are verified by your model and tagged with a verdict (confirmed / needs verify / possible / ruled out)."
        >
          <ToggleSwitch
            checked={enabled}
            onChange={handleToggle}
            disabled={toggleBusy}
            label="Enable LLM verification"
          />
        </SettingsRow>

        <div className="px-4 py-4">
          {isConfigured ? (
            <div className="flex items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3">
              <button
                type="button"
                onClick={openModal}
                className="min-w-0 flex-1 rounded-md text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
              >
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium text-[var(--color-text-primary)]" title={baseline.model}>
                    {baseline.model}
                  </span>
                  <StatusPill
                    status={enabled ? "healthy" : "disabled"}
                    label={enabled ? "Verification on" : "Off"}
                  />
                </div>
                <dl className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--color-text-secondary)]">
                  <span className="max-w-[16rem] truncate" title={baseline.api_base_url}>
                    {baseline.api_base_url}
                  </span>
                  <span>{transportLabel(baseline.transport)}</span>
                  <span className="tabular-nums">
                    {baseline.scan_token_budget.toLocaleString()} / scan
                  </span>
                  <span className="tabular-nums">
                    {baseline.daily_token_budget.toLocaleString()} / day
                  </span>
                </dl>
              </button>
              <Button
                variant="ghost"
                size="sm"
                iconOnly
                aria-label="Edit LLM configuration"
                leadingIcon={<Pencil />}
                onClick={openModal}
              />
            </div>
          ) : (
            <div className="rounded-lg border border-dashed border-[var(--color-border)] px-4 py-3 text-xs text-[var(--color-text-secondary)]">
              Not configured - enable to connect your model
            </div>
          )}

          {summaryError && (
            <p role="alert" aria-live="assertive" className="mt-2 text-xs text-[var(--color-severity-critical-text)]">
              {summaryError}
            </p>
          )}
        </div>
      </SettingsCard>

      {isConfigured && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-[var(--color-text-secondary)]">
            Token spend and daily usage are shown in{" "}
            <Link href="/insights?tab=usage" className="font-medium text-[var(--color-accent)] hover:underline">
              Insights → Usage
            </Link>
            .
          </p>
          <Button
            variant="ghost"
            size="sm"
            onClick={remove}
            disabled={toggleBusy}
            className="text-[var(--color-severity-critical-text)]"
          >
            Remove model
          </Button>
        </div>
      )}

      <Sheet
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        variant="modal"
        size="lg"
        title="Configure LLM verification"
        description="Connect your OpenAI-compatible model. The connection is tested before verification turns on."
        footer={
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0 flex-1">
              {modalError && (
                <p role="alert" aria-live="assertive" className="truncate text-xs font-medium text-[var(--color-severity-critical-text)]" title={modalError}>
                  ✕ {modalError}
                </p>
              )}
              {modalOk && (
                <p role="status" aria-live="polite" className="text-xs font-medium text-[var(--color-status-ok-text)]">
                  ✓ Connected
                </p>
              )}
            </div>
            <Button variant="secondary" size="md" onClick={() => setModalOpen(false)} disabled={testing}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="md"
              onClick={handleTestAndSave}
              disabled={testing || !canSubmit}
              isLoading={testing}
              aria-busy={testing}
            >
              {testing ? "Testing connection…" : "Test & save"}
            </Button>
          </div>
        }
      >
        <div className="flex flex-col gap-4">
          <SettingsCard heading="Model">
            <SettingsRow
              label="API key"
              description={
                keyConfigured
                  ? "A key is stored. Leave blank to keep it, or re-enter to replace."
                  : "Your provider's secret key. Stored encrypted; never shown again."
              }
              layout="stack"
            >
              <Input
                type="password"
                size="sm"
                autoComplete="off"
                placeholder={keyConfigured ? "•••• stored (leave blank to keep)" : "sk-…"}
                value={byo.api_key}
                onChange={(e) => setByo((f) => ({ ...f, api_key: e.target.value }))}
              />
            </SettingsRow>
            <SettingsRow label="Base URL" description="OpenAI-compatible endpoint" layout="stack">
              <Input
                size="sm"
                value={byo.api_base_url}
                onChange={(e) => setByo((f) => ({ ...f, api_base_url: e.target.value }))}
              />
            </SettingsRow>
            <SettingsRow label="Model" description="Model identifier" layout="stack">
              <Input size="sm" value={byo.model} onChange={(e) => setByo((f) => ({ ...f, model: e.target.value }))} />
            </SettingsRow>
            <SettingsRow
              label="Verification transport"
              description="Auto tries the best supported path for your endpoint and falls back to chat completions. The others force a specific API."
              layout="stack"
            >
              <Select
                size="sm"
                value={byo.transport}
                onChange={(e) => setByo((f) => ({ ...f, transport: e.target.value as LlmTransport }))}
              >
                {LLM_TRANSPORTS.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.label}
                  </option>
                ))}
              </Select>
            </SettingsRow>
            {byo.transport === "anthropic" && (
              <SettingsRow
                label="Anthropic base URL"
                description="Only needed for the Anthropic messages transport."
                layout="stack"
              >
                <Input
                  size="sm"
                  placeholder="https://host/anthropic/v1"
                  value={byo.anthropic_base_url}
                  onChange={(e) => setByo((f) => ({ ...f, anthropic_base_url: e.target.value }))}
                />
              </SettingsRow>
            )}
            <SettingsRow label="Per-scan token budget" layout="stack">
              <Input
                type="number"
                size="sm"
                value={byo.scan_token_budget}
                onChange={(e) => setByo((f) => ({ ...f, scan_token_budget: Number(e.target.value) }))}
              />
            </SettingsRow>
            <SettingsRow label="Daily token budget" layout="stack">
              <Input
                type="number"
                size="sm"
                value={byo.daily_token_budget}
                onChange={(e) => setByo((f) => ({ ...f, daily_token_budget: Number(e.target.value) }))}
              />
            </SettingsRow>
          </SettingsCard>
        </div>
      </Sheet>
    </div>
  )
}

"use client"

import { useEffect, useMemo, useState } from "react"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import { CostChart } from "@/components/shared/settings/llm/CostChart"
import { TestConnectionButton } from "@/components/shared/settings/llm/TestConnectionButton"
import { UsageMeter } from "@/components/shared/settings/llm/UsageMeter"
import { apiClient } from "@/lib/client/api-client"

type ProviderId = "anthropic" | "openai" | "azure_openai" | "custom"

interface ProviderPreset {
  id: ProviderId
  name: string
  description: string
  apiBaseUrl: string
  /** Editable in the UI? Azure + custom expose the base URL field; the
   *  hosted providers lock it down. */
  baseUrlEditable: boolean
  /** Known model identifiers. The Model field renders as a `<Select>` when
   *  this is populated, otherwise as a free-text `<Input>` for custom
   *  / Azure deployments. */
  models: { id: string; label: string }[]
}

const PROVIDERS: ProviderPreset[] = [
  {
    id: "anthropic",
    name: "Anthropic",
    description: "Claude family — recommended for SAST and secrets verification.",
    apiBaseUrl: "https://api.anthropic.com/v1",
    baseUrlEditable: false,
    models: [
      { id: "claude-opus-4-7", label: "Claude Opus 4.7 — highest accuracy" },
      { id: "claude-sonnet-4-6", label: "Claude Sonnet 4.6 — balanced (recommended)" },
      { id: "claude-haiku-4-5-20251001", label: "Claude Haiku 4.5 — fastest, lowest cost" },
    ],
  },
  {
    id: "openai",
    name: "OpenAI",
    description: "GPT family — broad model coverage.",
    apiBaseUrl: "https://api.openai.com/v1",
    baseUrlEditable: false,
    models: [
      { id: "gpt-4o",      label: "GPT-4o — broad coverage" },
      { id: "gpt-4o-mini", label: "GPT-4o mini — low cost" },
      { id: "o3",          label: "o3 — deep reasoning" },
      { id: "o1",          label: "o1 — extended reasoning" },
      { id: "o1-mini",     label: "o1 mini — fast reasoning" },
    ],
  },
  {
    id: "azure_openai",
    name: "Azure OpenAI",
    description: "Self-hosted Azure deployment. Use your deployment name as the model.",
    apiBaseUrl: "https://YOUR-RESOURCE.openai.azure.com/openai/deployments",
    baseUrlEditable: true,
    models: [],
  },
  {
    id: "custom",
    name: "Custom (OpenAI-compatible)",
    description: "Any OpenAI-compatible endpoint — vLLM, Ollama, LiteLLM, etc.",
    apiBaseUrl: "https://your-endpoint.example.com/v1",
    baseUrlEditable: true,
    models: [],
  },
]

function inferProvider(apiBaseUrl: string): ProviderId {
  for (const p of PROVIDERS) {
    if (p.baseUrlEditable) continue
    if (apiBaseUrl.startsWith(p.apiBaseUrl)) return p.id
  }
  if (apiBaseUrl.includes("openai.azure.com")) return "azure_openai"
  return "custom"
}

type LlmConfig = {
  api_base_url: string
  model: string
  scan_token_budget: number
  daily_token_budget: number
  enabled: boolean
  configured: boolean
}

type DayUsage = {
  date: string
  tokens_in: number
  tokens_out: number
  scans: number
}

type UsageResponse = {
  days: DayUsage[]
  today_used: number
  today_budget: number
  today_remaining: number
}

type FormState = {
  api_key: string
  provider: ProviderId
  api_base_url: string
  model: string
  scan_token_budget: number
  daily_token_budget: number
  enabled: boolean
}

const DEFAULT_PROVIDER = PROVIDERS[0]

const INITIAL_FORM: FormState = {
  api_key: "",
  provider: DEFAULT_PROVIDER.id,
  api_base_url: DEFAULT_PROVIDER.apiBaseUrl,
  model: DEFAULT_PROVIDER.models[1].id,
  scan_token_budget: 100_000,
  daily_token_budget: 1_000_000,
  enabled: false,
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(n % 1_000_000 === 0 ? 0 : 1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(n % 1_000 === 0 ? 0 : 1)}K`
  return n.toLocaleString()
}

interface LlmContentProps {
  /** Admins can save / toggle; non-admins get a read-only view of the
   *  current configuration. Defaults to true so the standalone
   *  /settings/llm route still works (it sits behind its own auth gate). */
  canEdit?: boolean
  /** While `/api/v1/auth/me` is still loading we render a placeholder hint
   *  instead of pretending the user has no access. */
  sessionLoading?: boolean
}

export function LlmContent({ canEdit = true, sessionLoading = false }: LlmContentProps = {}) {
  const [cfg, setCfg] = useState<LlmConfig | null>(null)
  const [form, setForm] = useState<FormState>(INITIAL_FORM)
  const [showKey, setShowKey] = useState(false)
  const [status, setStatus] = useState<"idle" | "saving" | "saved" | "error">("idle")
  const [usage, setUsage] = useState<UsageResponse | null>(null)

  useEffect(() => {
    fetch("/api/v1/settings/llm")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return
        setCfg(data)
        const inferredProvider = inferProvider(data.api_base_url ?? "")
        setForm((f) => ({
          ...f,
          provider: inferredProvider,
          api_base_url: data.api_base_url ?? f.api_base_url,
          model: data.model ?? f.model,
          scan_token_budget: data.scan_token_budget ?? f.scan_token_budget,
          daily_token_budget: data.daily_token_budget ?? f.daily_token_budget,
          enabled: Boolean(data.enabled),
        }))
      })
      .catch(() => {
        // Treat as unconfigured — leave form on its defaults.
      })
  }, [])

  // Refresh usage independently — surfaces even while config is still
  // loading, so the meter doesn't lag behind the form.
  useEffect(() => {
    fetch("/api/v1/settings/llm/usage?days=30")
      .then((r) => (r.ok ? (r.json() as Promise<UsageResponse>) : null))
      .then((data) => {
        if (data) setUsage(data)
      })
      .catch(() => {
        /* leave usage as null — the chart renders its own skeleton */
      })
  }, [status])

  const activeProvider = useMemo(
    () => PROVIDERS.find((p) => p.id === form.provider) ?? DEFAULT_PROVIDER,
    [form.provider],
  )

  function handleProviderChange(next: ProviderId) {
    const p = PROVIDERS.find((x) => x.id === next) ?? DEFAULT_PROVIDER
    setForm((f) => ({
      ...f,
      provider: p.id,
      // Reset to the provider's default base URL whenever the picker
      // changes — prevents stale Azure URLs from leaking into a switch
      // back to Anthropic, etc.
      api_base_url: p.apiBaseUrl,
      model: p.models[0]?.id ?? f.model,
    }))
  }

  async function save() {
    setStatus("saving")
    try {
      const next = await apiClient<LlmConfig>("/api/v1/settings/llm", {
        method: "PUT",
        body: {
          api_key: form.api_key,
          api_base_url: form.api_base_url,
          model: form.model,
          scan_token_budget: form.scan_token_budget,
          daily_token_budget: form.daily_token_budget,
          enabled: form.enabled,
        },
      })
      setCfg(next)
      // Clear the key field — the saved value is masked; further edits
      // start from a blank input rather than re-saving what's already
      // stored server-side.
      setForm((f) => ({ ...f, api_key: "" }))
      setStatus("saved")
    } catch {
      setStatus("error")
    }
  }

  const configured = Boolean(cfg?.configured)
  const enabled = Boolean(cfg?.enabled)
  const isDirty = form.api_key.length > 0 || (
    cfg !== null && (
      form.api_base_url !== cfg.api_base_url ||
      form.model !== cfg.model ||
      form.scan_token_budget !== cfg.scan_token_budget ||
      form.daily_token_budget !== cfg.daily_token_budget ||
      form.enabled !== cfg.enabled
    )
  )

  // Read-only fallback when the user lacks `manage_settings`. The section
  // still renders so the in-page nav anchor stays intact and the section
  // heading explains *why* the form isn't editable.
  if (!canEdit && !sessionLoading) {
    return (
      <div className="space-y-4">
        <StatusBanner configured={configured} enabled={enabled} providerName={activeProvider.name} />
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">
            Read-only
          </p>
          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
            Configuring LLM verification needs the <span className="font-mono">manage_settings</span> permission. Ask an admin to update the provider or model.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6" aria-busy={sessionLoading || undefined}>
      {/* Status banner */}
      <StatusBanner configured={configured} enabled={enabled} providerName={activeProvider.name} />

      {/* Provider */}
      <SettingsCard heading="Provider">
        <SettingsRow
          label="LLM provider"
          description="Pick which hosted or self-hosted endpoint Aegis sends verification prompts to."
          layout="stack"
        >
          <ProviderPicker value={form.provider} onChange={handleProviderChange} />
        </SettingsRow>

        <SettingsRow label="API key" description={configured ? "A key is stored. Paste a new one to replace it." : "Used only to authenticate from the Aegis backend — never sent to the browser."} layout="stack">
          <div className="flex gap-2">
            <div className="flex-1">
              <Input
                id="llm-api-key"
                type={showKey ? "text" : "password"}
                value={form.api_key}
                placeholder={configured ? "•••••••• (stored)" : activeProvider.id === "anthropic" ? "sk-ant-..." : activeProvider.id === "openai" ? "sk-..." : "Paste API key"}
                autoComplete="off"
                onChange={(e) => setForm({ ...form, api_key: e.target.value })}
              />
            </div>
            <Button
              variant="secondary"
              size="md"
              onClick={() => setShowKey((s) => !s)}
              aria-label={showKey ? "Hide API key" : "Show API key"}
              className="shrink-0"
            >
              {showKey ? "Hide" : "Show"}
            </Button>
          </div>
        </SettingsRow>

        {activeProvider.baseUrlEditable && (
          <SettingsRow label="API base URL" description="OpenAI-compatible endpoint. Aegis appends /chat/completions automatically." layout="stack">
            <Input
              id="llm-api-base-url"
              type="url"
              value={form.api_base_url}
              onChange={(e) => setForm({ ...form, api_base_url: e.target.value })}
            />
          </SettingsRow>
        )}

        <SettingsRow
          label="Model"
          description={activeProvider.models.length === 0 ? "For Azure, use your deployment name. For custom endpoints, the model identifier the server expects." : "Higher-tier models cost more per token but verify findings more accurately."}
          layout="stack"
        >
          {activeProvider.models.length > 0 ? (
            <Select
              id="llm-model"
              value={form.model}
              onChange={(e) => setForm({ ...form, model: e.target.value })}
            >
              {activeProvider.models.map((m) => (
                <option key={m.id} value={m.id}>{m.label}</option>
              ))}
            </Select>
          ) : (
            <Input
              id="llm-model"
              type="text"
              placeholder={activeProvider.id === "azure_openai" ? "your-gpt4o-deployment" : "model-identifier"}
              value={form.model}
              onChange={(e) => setForm({ ...form, model: e.target.value })}
            />
          )}
        </SettingsRow>
      </SettingsCard>

      {/* Limits */}
      <SettingsCard heading="Limits">
        <SettingsRow
          label="Per-scan token budget"
          description="Maximum tokens Aegis spends verifying a single scan's findings before falling back to unverified results."
        >
          <div className="flex w-56 flex-col items-end gap-1">
            <Input
              id="llm-scan-token-budget"
              type="number"
              min={1000}
              step={10000}
              className="text-right tabular-nums"
              value={form.scan_token_budget}
              onChange={(e) =>
                setForm({ ...form, scan_token_budget: Number(e.target.value) || 0 })
              }
            />
            <span className="text-2xs text-[var(--color-text-tertiary)]">
              {formatTokens(form.scan_token_budget)} tokens
            </span>
          </div>
        </SettingsRow>

        <SettingsRow
          label="Daily token cap"
          description="Org-wide ceiling. When today's usage hits this number, new verifications are paused until midnight UTC."
        >
          <div className="flex w-56 flex-col items-end gap-1">
            <Input
              id="llm-daily-token-budget"
              type="number"
              min={10000}
              step={100000}
              className="text-right tabular-nums"
              value={form.daily_token_budget}
              onChange={(e) =>
                setForm({ ...form, daily_token_budget: Number(e.target.value) || 0 })
              }
            />
            <span className="text-2xs text-[var(--color-text-tertiary)]">
              {formatTokens(form.daily_token_budget)} tokens
            </span>
          </div>
        </SettingsRow>
      </SettingsCard>

      {/* Enable */}
      <SettingsCard heading="Activation">
        <SettingsRow
          label="Enable LLM verification"
          description="When on, SAST and secrets findings are checked by the configured model and tagged with a verdict (confirmed / needs verify / possible / ruled out)."
        >
          <ToggleSwitch
            checked={form.enabled}
            onChange={(next) => setForm({ ...form, enabled: next })}
            label="Enable LLM verification"
          />
        </SettingsRow>
      </SettingsCard>

      {/* Save row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          {status === "saved" && (
            <span className="inline-flex items-center text-xs font-medium text-[var(--color-status-ok)]" role="status" aria-live="polite">
              ✓ Settings saved
            </span>
          )}
          {status === "error" && (
            <span className="inline-flex items-center text-xs font-medium text-[var(--color-severity-critical)]" role="alert">
              ✕ Save failed
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {configured && <TestConnectionButton />}
          <Button
            variant="primary"
            size="md"
            onClick={save}
            disabled={status === "saving" || (!form.api_key && !configured) || !isDirty}
            isLoading={status === "saving"}
          >
            {status === "saving" ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>

      {/* Usage */}
      {usage && configured && (
        <SettingsCard heading="Usage">
          <div className="space-y-6 p-4">
            <UsageMeter used={usage.today_used} budget={usage.today_budget} />
            <CostChart days={usage.days} />
          </div>
        </SettingsCard>
      )}
    </div>
  )
}


function StatusBanner({
  configured,
  enabled,
  providerName,
}: {
  configured: boolean
  enabled: boolean
  providerName: string
}) {
  if (!configured) {
    return (
      <div className="rounded-md border border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)] px-4 py-3">
        <p className="text-sm font-medium text-[var(--color-state-pending)]">
          LLM verification is not configured
        </p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          Add an API key below to start verifying SAST and secrets findings. Typically cuts noise by 40–60%.
        </p>
      </div>
    )
  }
  if (!enabled) {
    return (
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">
          LLM verification is paused
        </p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          A key for {providerName} is stored. Toggle on under Activation to resume verifying findings.
        </p>
      </div>
    )
  }
  return (
    <div className="rounded-md border border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] px-4 py-3">
      <p className="text-sm font-medium text-[var(--color-status-ok)]">
        LLM verification is active — {providerName}
      </p>
      <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
        New SAST and secrets findings are verified automatically before they hit the inbox.
      </p>
    </div>
  )
}

function ProviderPicker({
  value,
  onChange,
}: {
  value: ProviderId
  onChange: (next: ProviderId) => void
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {PROVIDERS.map((p) => {
        const active = p.id === value
        return (
          <button
            key={p.id}
            type="button"
            onClick={() => onChange(p.id)}
            aria-pressed={active}
            className={`flex flex-col rounded-md border px-3 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
              active
                ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                : "border-[var(--color-border)] bg-[var(--color-surface)] hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-raised)]"
            }`}
          >
            <span className="flex items-center gap-2">
              <span
                aria-hidden="true"
                className={`flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
                  active
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                    : "border-[var(--color-border-strong)]"
                }`}
              >
                {active && (
                  <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-current" />
                )}
              </span>
              <span className={`text-sm font-medium ${active ? "text-[var(--color-accent)]" : "text-[var(--color-text-primary)]"}`}>
                {p.name}
              </span>
            </span>
            <span className="mt-1 pl-6 text-xs text-[var(--color-text-secondary)]">
              {p.description}
            </span>
          </button>
        )
      })}
    </div>
  )
}

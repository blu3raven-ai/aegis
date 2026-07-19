"use client"

import { useEffect, useState } from "react"
import { Eye } from "lucide-react"

import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import { Sheet } from "@/components/ui/Sheet"
import {
  disconnectArgus,
  getArgusConnection,
  testArgusConnection,
  updateArgusConnection,
  type ArgusConnection,
  type ArgusTestResult,
} from "@/lib/client/argus-settings-api"

type FormState = {
  endpoint: string
  token_endpoint: string
  client_id: string
  refresh_token: string
  enabled: boolean
}

const INITIAL_FORM: FormState = {
  endpoint: "",
  token_endpoint: "",
  client_id: "",
  refresh_token: "",
  enabled: false,
}

/** Non-secret fields tracked for dirty detection (refresh_token is write-only). */
type ArgusBaseline = Pick<FormState, "endpoint" | "token_endpoint" | "client_id" | "enabled">

const INITIAL_BASELINE: ArgusBaseline = {
  endpoint: "",
  token_endpoint: "",
  client_id: "",
  enabled: false,
}

function StatusBanner({ conn }: { conn: ArgusConnection | null }) {
  if (!conn || !conn.endpoint) {
    return (
      <div className="rounded-md border border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)] px-4 py-3">
        <p className="text-sm font-medium text-[var(--color-state-pending-text)]">Argus is not connected</p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          Add your Argus endpoint and OAuth credentials below to enrich findings with exploit and
          threat intelligence.
        </p>
      </div>
    )
  }
  if (!conn.enabled) {
    return (
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">Argus is paused</p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          A connection to {conn.endpoint} is stored. Toggle on under Activation to resume enriching
          findings.
        </p>
      </div>
    )
  }
  return (
    <div className="rounded-md border border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] px-4 py-3">
      <p className="text-sm font-medium text-[var(--color-status-ok-text)]">
        Argus is connected: {conn.endpoint}
      </p>
      <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
        New findings are enriched with exploit and threat intel automatically as they arrive.
      </p>
    </div>
  )
}

/**
 * Configure the hosted Argus threat-intel connection used to enrich findings.
 * Argus is reached over an OAuth2 refresh-token grant (short-lived bearer tokens,
 * never a static key), so this form captures the Argus endpoint, the IdP token
 * endpoint, the client id, and the refresh token. Finding verification is a
 * separate concern configured under "LLM verification".
 */
interface ArgusConnectionContentProps {
  /** Admins can edit; others get a read-only status view. Defaults to true for
   *  callers that gate edit-access themselves before rendering this form. */
  canEdit?: boolean
  /** While the session/permission is still loading, render a placeholder. */
  sessionLoading?: boolean
  /** Notify the parent when this connection's active state changes, so the
   *  shared "which provider is on" state stays in sync. */
  onActiveChange?: (active: boolean) => void
  /** Rendered inline as a row alongside the built-in advisory sources: mark the
   *  card with an "Add-on" pill so its paid-plugin status reads at a glance. */
  isAddon?: boolean
}

export function ArgusConnectionContent({
  canEdit = true,
  sessionLoading = false,
  onActiveChange,
  isAddon = false,
}: ArgusConnectionContentProps = {}) {
  const [conn, setConn] = useState<ArgusConnection | null>(null)
  const [form, setForm] = useState<FormState>(INITIAL_FORM)
  const [baseline, setBaseline] = useState<ArgusBaseline>(INITIAL_BASELINE)
  const [showToken, setShowToken] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<ArgusTestResult | null>(null)

  useEffect(() => {
    getArgusConnection()
      .then((data) => {
        setConn(data)
        setForm((f) => ({
          ...f,
          endpoint: data.endpoint,
          token_endpoint: data.token_endpoint,
          client_id: data.client_id,
          enabled: data.enabled,
        }))
        setBaseline({
          endpoint: data.endpoint,
          token_endpoint: data.token_endpoint,
          client_id: data.client_id,
          enabled: data.enabled,
        })
      })
      .catch(() => {
        /* treat as unconfigured — leave the form on its defaults */
      })
  }, [])

  const configured = Boolean(conn?.endpoint)

  // Every field is required to save (the refresh token must be re-entered).
  const canSave =
    form.endpoint.trim().length > 3 &&
    form.token_endpoint.trim().length > 3 &&
    form.client_id.trim().length > 0 &&
    form.refresh_token.length > 0

  async function handleSave(): Promise<boolean> {
    if (!canSave) {
      setError("Fill in every field, including the refresh token.")
      return false
    }
    setSaving(true)
    setError(null)
    setTestResult(null)
    try {
      const next = await updateArgusConnection({
        endpoint: form.endpoint.trim(),
        token_endpoint: form.token_endpoint.trim(),
        client_id: form.client_id.trim(),
        refresh_token: form.refresh_token,
        enabled: true,
      })
      setConn(next)
      // Clear the secret field — the stored value is masked; further edits
      // start blank rather than re-submitting what's already on file.
      setForm((f) => ({ ...f, refresh_token: "", enabled: next.enabled }))
      setBaseline({
        endpoint: next.endpoint,
        token_endpoint: next.token_endpoint,
        client_id: next.client_id,
        enabled: next.enabled,
      })
      onActiveChange?.(next.enabled)
      return true
    } catch {
      setError("Couldn't save the connection. Check the fields and try again.")
      return false
    } finally {
      setSaving(false)
    }
  }

  function handleDiscard() {
    setForm({ ...baseline, refresh_token: "" })
    setError(null)
    setTestResult(null)
  }

  async function test() {
    setTesting(true)
    setTestResult(null)
    try {
      setTestResult(await testArgusConnection())
    } catch {
      setTestResult({ ok: false, error: "request_failed" })
    } finally {
      setTesting(false)
    }
  }

  async function disconnect() {
    setSaving(true)
    setError(null)
    try {
      await disconnectArgus()
      setConn({ endpoint: "", token_endpoint: "", client_id: "", enabled: false, connected: false })
      setForm(INITIAL_FORM)
      setBaseline(INITIAL_BASELINE)
      setTestResult(null)
      onActiveChange?.(false)
    } catch {
      setError("Couldn't disconnect. Try again.")
    } finally {
      setSaving(false)
    }
  }

  // The connection form lives in a modal that opens only when the user turns
  // Argus on (or clicks Manage) — the card itself stays compact.
  const [configOpen, setConfigOpen] = useState(false)

  function openConfig() {
    setError(null)
    setTestResult(null)
    setConfigOpen(true)
  }
  function closeConfig() {
    handleDiscard()
    setConfigOpen(false)
  }
  async function saveConfig() {
    if (await handleSave()) setConfigOpen(false)
  }
  async function handleToggle(next: boolean) {
    if (next) openConfig()
    else await disconnect()
  }

  // Read-only view for users without manage_settings.
  if (!canEdit && !sessionLoading) {
    return (
      <div className="space-y-4">
        <StatusBanner conn={conn} />
        <p className="text-xs text-[var(--color-text-secondary)]">
          Configuring Argus needs the <span className="font-mono">manage_settings</span> permission.
          Ask an admin to update the connection.
        </p>
      </div>
    )
  }

  // On = a connection is stored and active. Configured-but-off reads as "paused".
  const active = configured && form.enabled

  return (
    <div className="space-y-6">
      <div className={`rounded-md border px-4 py-3.5 transition-colors ${active ? "border-[var(--color-argus-border)] bg-[var(--color-argus-subtle)]" : "border-[var(--color-border)] bg-[var(--color-surface)]"}`}>
        <div className="flex items-start gap-3.5">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--color-argus-subtle)] text-[var(--color-argus)] ring-1 ring-inset ring-[var(--color-argus-border)]">
            <Eye className="h-[18px] w-[18px]" strokeWidth={2} aria-hidden="true" />
          </span>
          <div className="min-w-0 flex-1">
            <span className="inline-flex items-center gap-2">
              <span className="text-sm font-semibold text-[var(--color-text-primary)]">Blu3Raven Argus</span>
              {isAddon && (
                <span className="inline-flex items-center rounded-full bg-[var(--color-argus-subtle)] px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.08em] text-[var(--color-argus)] ring-1 ring-inset ring-[var(--color-argus-border)]">
                  Add-on
                </span>
              )}
            </span>
            <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
              AI-powered threat intelligence: exploit availability, chain risk (how vulnerabilities combine into an attack path), and advisory enrichment on top of the built-in feeds. Works with any plan.
            </p>
          </div>
          <ToggleSwitch
            checked={active}
            onChange={handleToggle}
            label="Enable Argus"
          />
        </div>

        {configured ? (
          <div className="mt-3.5 flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-t border-[var(--color-border-divider)] pt-3">
            <span className={`inline-flex min-w-0 items-center gap-1.5 text-xs font-medium ${active ? "text-[var(--color-status-ok-text)]" : "text-[var(--color-state-pending-text)]"}`}>
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${active ? "bg-[var(--color-status-ok-text)]" : "bg-[var(--color-state-pending-text)]"}`} aria-hidden="true" />
              <span className="truncate">{active ? "Enriching findings" : "Paused"} · {conn?.endpoint}</span>
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {testResult && (
                <span className={`text-xs ${testResult.ok ? "text-[var(--color-status-ok-text)]" : "text-[var(--color-severity-critical-text)]"}`}>
                  {testResult.ok ? "Reachable" : `Test failed${testResult.error ? ` (${testResult.error})` : ""}`}
                </span>
              )}
              <Button variant="secondary" size="xs" onClick={openConfig}>Manage</Button>
              <Button variant="secondary" size="xs" onClick={test} isLoading={testing}>Test</Button>
              <Button variant="ghost" size="xs" onClick={disconnect} className="text-[var(--color-severity-critical-text)]">Disconnect</Button>
            </div>
          </div>
        ) : (
          <p className="mt-3 border-t border-[var(--color-border-divider)] pt-3 text-xs text-[var(--color-text-tertiary)]">
            Turning it on opens a short setup for your endpoint and OAuth credentials.
          </p>
        )}
      </div>

      <Sheet
        open={configOpen}
        onClose={closeConfig}
        title={configured ? "Manage Argus connection" : "Connect Argus"}
        description="Enter your hosted Argus endpoint and OAuth credentials. Aegis exchanges the refresh token for short-lived access tokens — nothing is sent to the browser."
        variant="modal"
        size="lg"
        dismissGuard={{ isDirty: canSave, message: "Discard the Argus connection details you entered?" }}
        footer={
          <div className="flex items-center justify-end gap-2">
            {error && <span className="mr-auto text-xs text-[var(--color-severity-critical-text)]">{error}</span>}
            <Button variant="secondary" size="sm" onClick={closeConfig}>Cancel</Button>
            <Button variant="primary" size="sm" onClick={saveConfig} isLoading={saving} disabled={!canSave}>
              {configured ? "Save changes" : "Connect"}
            </Button>
          </div>
        }
      >
        <div className="space-y-4 px-5 py-5">
          <SettingsRow label="Argus endpoint" description="Base URL of your hosted Argus threat-intel service." layout="stack">
            <Input
              id="argus-endpoint"
              type="url"
              value={form.endpoint}
              placeholder="https://argus.your-org.example.com"
              onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
            />
          </SettingsRow>
          <SettingsRow label="Token endpoint" description="Your identity provider's OAuth2 token endpoint. Aegis exchanges the refresh token here for a short-lived access token." layout="stack">
            <Input
              id="argus-token-endpoint"
              type="url"
              value={form.token_endpoint}
              placeholder="https://idp.your-org.example.com/oauth2/token"
              onChange={(e) => setForm({ ...form, token_endpoint: e.target.value })}
            />
          </SettingsRow>
          <SettingsRow label="Client ID" description="OAuth2 client identifier issued for Aegis." layout="stack">
            <Input
              id="argus-client-id"
              type="text"
              value={form.client_id}
              placeholder="aegis-verification"
              autoComplete="off"
              onChange={(e) => setForm({ ...form, client_id: e.target.value })}
            />
          </SettingsRow>
          <SettingsRow
            label="Refresh token"
            description={
              configured
                ? "A token is stored. Paste a new one to replace it (required to re-save)."
                : "Long-lived OAuth2 refresh token. Stored encrypted and never sent to the browser."
            }
            layout="stack"
          >
            <div className="flex gap-2">
              <div className="flex-1">
                <Input
                  id="argus-refresh-token"
                  type={showToken ? "text" : "password"}
                  value={form.refresh_token}
                  placeholder={configured ? "•••••••• (stored)" : "Paste refresh token"}
                  autoComplete="off"
                  onChange={(e) => setForm({ ...form, refresh_token: e.target.value })}
                />
              </div>
              <Button
                variant="secondary"
                size="md"
                onClick={() => setShowToken((s) => !s)}
                aria-label={showToken ? "Hide refresh token" : "Show refresh token"}
                className="shrink-0"
              >
                {showToken ? "Hide" : "Show"}
              </Button>
            </div>
          </SettingsRow>
        </div>
      </Sheet>
    </div>
  )
}

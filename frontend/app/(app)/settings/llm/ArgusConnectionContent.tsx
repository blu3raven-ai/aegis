"use client"

import { useEffect, useState } from "react"

import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
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

function StatusBanner({ conn }: { conn: ArgusConnection | null }) {
  if (!conn || !conn.endpoint) {
    return (
      <div className="rounded-lg border border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)] px-4 py-3">
        <p className="text-sm font-medium text-[var(--color-state-pending)]">Argus is not connected</p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          Add your Argus endpoint and OAuth credentials below to start verifying SAST, secrets, and
          IaC findings. Typically cuts noise by 40–60%.
        </p>
      </div>
    )
  }
  if (!conn.enabled) {
    return (
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">Argus is paused</p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          A connection to {conn.endpoint} is stored. Toggle on under Activation to resume verifying
          findings.
        </p>
      </div>
    )
  }
  return (
    <div className="rounded-lg border border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] px-4 py-3">
      <p className="text-sm font-medium text-[var(--color-status-ok)]">
        Argus is connected — {conn.endpoint}
      </p>
      <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
        New SAST, secrets, and IaC findings are verified automatically before they hit the inbox.
      </p>
    </div>
  )
}

/**
 * Connect the per-org Argus verification service. Aegis no longer runs an LLM
 * itself — verification happens in Argus, reached over an OAuth2 refresh-token
 * grant (short-lived bearer tokens, never a static key). This form configures
 * that connection: the Argus endpoint, the IdP token endpoint, the client id,
 * and the refresh token.
 */
interface ArgusConnectionContentProps {
  /** Admins can edit; others get a read-only status view. Defaults to true for
   *  callers that gate edit-access themselves before rendering this form. */
  canEdit?: boolean
  /** While the session/permission is still loading, render a placeholder. */
  sessionLoading?: boolean
}

export function ArgusConnectionContent({
  canEdit = true,
  sessionLoading = false,
}: ArgusConnectionContentProps = {}) {
  const [conn, setConn] = useState<ArgusConnection | null>(null)
  const [form, setForm] = useState<FormState>(INITIAL_FORM)
  const [showToken, setShowToken] = useState(false)
  const [status, setStatus] = useState<"idle" | "saving" | "saved" | "error">("idle")
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
      })
      .catch(() => {
        /* treat as unconfigured — leave the form on its defaults */
      })
  }, [])

  const configured = Boolean(conn?.endpoint)

  async function save() {
    setStatus("saving")
    setTestResult(null)
    try {
      const next = await updateArgusConnection({
        endpoint: form.endpoint.trim(),
        token_endpoint: form.token_endpoint.trim(),
        client_id: form.client_id.trim(),
        refresh_token: form.refresh_token,
        enabled: form.enabled,
      })
      setConn(next)
      // Clear the secret field — the stored value is masked; further edits
      // start blank rather than re-submitting what's already on file.
      setForm((f) => ({ ...f, refresh_token: "" }))
      setStatus("saved")
    } catch {
      setStatus("error")
    }
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
    setStatus("saving")
    try {
      await disconnectArgus()
      setConn({ endpoint: "", token_endpoint: "", client_id: "", enabled: false, connected: false })
      setForm(INITIAL_FORM)
      setStatus("idle")
      setTestResult(null)
    } catch {
      setStatus("error")
    }
  }

  // Every field is required to save (the refresh token must be re-entered).
  const canSave =
    form.endpoint.trim().length > 3 &&
    form.token_endpoint.trim().length > 3 &&
    form.client_id.trim().length > 0 &&
    form.refresh_token.length > 0

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

  return (
    <div className="space-y-6">
      <StatusBanner conn={conn} />

      <SettingsCard heading="Connection">
        <SettingsRow
          label="Argus endpoint"
          description="Base URL of your hosted Argus verification service."
          layout="stack"
        >
          <Input
            id="argus-endpoint"
            type="url"
            value={form.endpoint}
            placeholder="https://argus.your-org.example.com"
            onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
          />
        </SettingsRow>

        <SettingsRow
          label="Token endpoint"
          description="Your identity provider's OAuth2 token endpoint — Aegis exchanges the refresh token here for a short-lived access token."
          layout="stack"
        >
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
      </SettingsCard>

      <SettingsCard heading="Activation">
        <SettingsRow
          label="Enable Argus verification"
          description="When on, SAST, secrets, and IaC findings are verified by Argus and tagged with a verdict (confirmed / needs verify / possible / ruled out)."
        >
          <ToggleSwitch
            checked={form.enabled}
            onChange={(next) => setForm({ ...form, enabled: next })}
            label="Enable Argus verification"
          />
        </SettingsRow>
      </SettingsCard>

      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" size="md" onClick={save} isLoading={status === "saving"} disabled={!canSave}>
          Save connection
        </Button>
        <Button variant="secondary" size="md" onClick={test} isLoading={testing} disabled={!configured}>
          Test connection
        </Button>
        {configured && (
          <Button variant="ghost" size="md" onClick={disconnect} className="text-[var(--color-severity-critical)]">
            Disconnect
          </Button>
        )}
        {status === "saved" && (
          <span className="text-xs text-[var(--color-status-ok)]">Saved</span>
        )}
        {status === "error" && (
          <span className="text-xs text-[var(--color-severity-critical)]">Couldn&apos;t save — check the fields and try again.</span>
        )}
        {testResult && (
          <span
            className={`text-xs ${testResult.ok ? "text-[var(--color-status-ok)]" : "text-[var(--color-severity-critical)]"}`}
          >
            {testResult.ok
              ? "Connection OK — Argus reachable."
              : `Test failed${testResult.error ? ` (${testResult.error})` : ""}.`}
          </span>
        )}
      </div>
    </div>
  )
}

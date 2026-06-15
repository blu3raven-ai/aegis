"use client"

import { useEffect, useState } from "react"

import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Textarea } from "@/components/ui/Textarea"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"
import { ToggleSwitch } from "@/components/settings/ToggleSwitch"
import {
  generateSamlKeypair,
  refreshSamlMetadata,
  saveSsoSettings,
  useSsoSettings,
  type SsoSettings,
} from "@/lib/client/settings/use-sso-settings"
import {
  clearScimToken,
  generateScimToken,
  saveScimSettings,
  useScimSettings,
} from "@/lib/client/settings/use-scim-settings"
import {
  saveAuditStreamSettings,
  testAuditStream,
  useAuditStreamSettings,
} from "@/lib/client/settings/use-audit-stream-settings"
import { ScimTokenModal } from "@/components/settings/ScimTokenModal"

type EditableFields = Pick<
  SsoSettings,
  "enabled" | "protocol" | "defaultRoleId" | "samlMetadataUrl" | "samlMetadataXml"
  | "oidcDiscoveryUrl" | "oidcClientId" | "oidcScopes"
> & { oidcClientSecret?: string }

export function SsoContent() {
  const { data, mutate } = useSsoSettings()
  const [draft, setDraft] = useState<EditableFields | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [keypairBusy, setKeypairBusy] = useState(false)
  const [metaRefreshMsg, setMetaRefreshMsg] = useState<string | null>(null)
  const scim = useScimSettings()
  const [revealToken, setRevealToken] = useState<string | null>(null)
  const audit = useAuditStreamSettings()
  const [auditDraft, setAuditDraft] = useState<{
    enabled: boolean
    targetType: "webhook" | "splunk_hec" | "syslog" | null
    endpointUrl: string | null
    authToken: string
  } | null>(null)
  const [auditTestMsg, setAuditTestMsg] = useState<string | null>(null)

  useEffect(() => {
    if (audit.data) {
      setAuditDraft({
        enabled: audit.data.enabled,
        targetType: audit.data.targetType,
        endpointUrl: audit.data.endpointUrl,
        authToken: "",
      })
    }
  }, [audit.data])

  useEffect(() => {
    if (data) {
      setDraft({
        enabled: data.enabled,
        protocol: data.protocol,
        defaultRoleId: data.defaultRoleId,
        samlMetadataUrl: data.samlMetadataUrl,
        samlMetadataXml: data.samlMetadataXml,
        oidcDiscoveryUrl: data.oidcDiscoveryUrl,
        oidcClientId: data.oidcClientId,
        oidcScopes: data.oidcScopes,
      })
    }
  }, [data])

  const isDirty = !!data && !!draft && (
    draft.enabled !== data.enabled ||
    draft.protocol !== data.protocol ||
    draft.defaultRoleId !== data.defaultRoleId ||
    draft.samlMetadataUrl !== data.samlMetadataUrl ||
    draft.samlMetadataXml !== data.samlMetadataXml ||
    draft.oidcDiscoveryUrl !== data.oidcDiscoveryUrl ||
    draft.oidcClientId !== data.oidcClientId ||
    draft.oidcScopes !== data.oidcScopes ||
    (draft.oidcClientSecret !== undefined && draft.oidcClientSecret !== "")
  )

  const handleSave = async () => {
    if (!draft) return
    setSaving(true); setError(null)
    try {
      const next = await saveSsoSettings(draft)
      mutate(next)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save.")
    } finally {
      setSaving(false)
    }
  }

  const handleDiscard = () => {
    if (!data) return
    setDraft({
      enabled: data.enabled,
      protocol: data.protocol,
      defaultRoleId: data.defaultRoleId,
      samlMetadataUrl: data.samlMetadataUrl,
      samlMetadataXml: data.samlMetadataXml,
      oidcDiscoveryUrl: data.oidcDiscoveryUrl,
      oidcClientId: data.oidcClientId,
      oidcScopes: data.oidcScopes,
    })
    setError(null)
  }

  useSaveBarSection({
    id: "sso",
    dirty: !!isDirty,
    saving,
    count: isDirty ? 1 : 0,
    error,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  const handleGenerateKeypair = async () => {
    setKeypairBusy(true)
    setError(null)
    try {
      await generateSamlKeypair()
      mutate()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Keypair generation failed.")
    } finally {
      setKeypairBusy(false)
    }
  }

  const handleRefreshMetadata = async () => {
    setMetaRefreshMsg(null)
    const res = await refreshSamlMetadata()
    setMetaRefreshMsg(res.ok ? "Metadata refreshed." : (res.error ?? "Refresh failed."))
    mutate()
  }

  const handleCopySpMetadata = () => {
    const url = data?.samlSpMetadataUrl
    if (!url) return
    navigator.clipboard?.writeText(url).catch(() => {})
  }

  const handleGenerateScimToken = async () => {
    try {
      const res = await generateScimToken()
      setRevealToken(res.token)
      scim.mutate()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate token.")
    }
  }

  const handleClearScimToken = async () => {
    try {
      await clearScimToken()
      scim.mutate()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to clear token.")
    }
  }

  const handleToggleScim = async (enabled: boolean) => {
    try {
      const next = await saveScimSettings({ enabled })
      scim.mutate(next)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to update SCIM.")
    }
  }

  const handleSaveAudit = async () => {
    if (!auditDraft) return
    try {
      const next = await saveAuditStreamSettings({
        enabled: auditDraft.enabled,
        targetType: auditDraft.targetType,
        endpointUrl: auditDraft.endpointUrl,
        ...(auditDraft.authToken ? { authToken: auditDraft.authToken } : {}),
      })
      audit.mutate(next)
      setAuditDraft((d) => (d ? { ...d, authToken: "" } : d))
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save audit stream.")
    }
  }

  const handleTestAudit = async () => {
    setAuditTestMsg(null)
    try {
      const res = await testAuditStream()
      setAuditTestMsg(res.ok ? "Test event delivered." : (res.error ?? "Test failed."))
    } catch (e) {
      setAuditTestMsg(e instanceof Error ? e.message : "Test failed.")
    }
  }

  return (
    <div className="space-y-4">
      <SettingsCard heading="Identity provider">
        <SettingsRow label="Enable SSO" description="Show a 'Sign in with SSO' button on the login page">
          <ToggleSwitch
            label="Toggle SSO"
            checked={!!draft?.enabled}
            onChange={(v) => setDraft((d) => (d ? { ...d, enabled: v } : d))}
          />
        </SettingsRow>

        <SettingsRow label="Protocol" description="Choose SAML 2.0 or OIDC depending on your IdP">
          <Select
            size="sm"
            aria-label="Protocol"
            value={draft?.protocol ?? ""}
            onChange={(e) => setDraft((d) => (d ? { ...d, protocol: (e.target.value || null) as SsoSettings["protocol"] } : d))}
          >
            <option value="">— select —</option>
            <option value="saml">SAML 2.0</option>
            <option value="oidc">OIDC</option>
          </Select>
        </SettingsRow>

        {draft?.protocol === "saml" && (
          <>
            <SettingsRow
              label="Metadata URL"
              description="Your IdP's published metadata endpoint. We re-fetch nightly."
              layout="stack"
            >
              <Input
                aria-label="IdP metadata URL"
                type="url"
                placeholder="https://idp.example.com/metadata"
                value={draft?.samlMetadataUrl ?? ""}
                onChange={(e) => setDraft((d) => (d ? { ...d, samlMetadataUrl: e.target.value || null } : d))}
              />
              <div className="mt-1.5 flex items-center gap-2">
                <Button variant="secondary" size="sm" aria-label="Refresh IdP metadata" onClick={handleRefreshMetadata}>Refresh now</Button>
                {metaRefreshMsg && <span className="text-xs text-[var(--color-text-secondary)]">{metaRefreshMsg}</span>}
              </div>
            </SettingsRow>

            <SettingsRow
              label="Or paste metadata XML"
              description="For IdPs that don't publish a metadata URL"
              layout="stack"
            >
              <Textarea
                aria-label="IdP metadata XML"
                className="font-mono text-xs"
                rows={6}
                value={draft?.samlMetadataXml ?? ""}
                onChange={(e) => setDraft((d) => (d ? { ...d, samlMetadataXml: e.target.value || null } : d))}
              />
            </SettingsRow>

            <SettingsRow
              label="SP metadata URL"
              description="Paste this URL into your IdP's setup"
              layout="stack"
            >
              <div className="flex items-start gap-2">
                <code
                  className="block flex-1 rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface-2)] px-3 py-2 text-xs text-[var(--color-text-primary)] break-all"
                >
                  {data?.samlSpMetadataUrl ?? ""}
                </code>
                <Button variant="secondary" size="sm" aria-label="Copy SP metadata URL" onClick={handleCopySpMetadata}>Copy</Button>
              </div>
            </SettingsRow>

            <SettingsRow
              label="SP keypair"
              description={data?.samlSpPrivateKeySet ? "Currently configured" : "Not configured"}
            >
              <Button variant="secondary" size="sm" onClick={handleGenerateKeypair} disabled={keypairBusy} isLoading={keypairBusy}>
                {data?.samlSpPrivateKeySet ? "Regenerate keypair" : "Generate keypair"}
              </Button>
            </SettingsRow>
          </>
        )}

        {draft?.protocol === "oidc" && (
          <>
            <SettingsRow
              label="Discovery URL"
              description="The IdP's /.well-known/openid-configuration endpoint."
              layout="stack"
            >
              <Input
                aria-label="OIDC discovery URL"
                type="url"
                placeholder="https://accounts.example.com/.well-known/openid-configuration"
                value={draft?.oidcDiscoveryUrl ?? ""}
                onChange={(e) => setDraft((d) => (d ? { ...d, oidcDiscoveryUrl: e.target.value || null } : d))}
              />
            </SettingsRow>

            <SettingsRow label="Client ID" description="The OIDC application's client identifier" layout="stack">
              <Input
                aria-label="OIDC client ID"
                type="text"
                value={draft?.oidcClientId ?? ""}
                onChange={(e) => setDraft((d) => (d ? { ...d, oidcClientId: e.target.value || null } : d))}
              />
            </SettingsRow>

            <SettingsRow
              label="Client secret"
              description={data?.oidcClientSecretSet ? "A secret is currently set. Enter a new value to replace it." : "Provided by your IdP."}
              layout="stack"
            >
              <Input
                aria-label="OIDC client secret"
                type="password"
                placeholder={data?.oidcClientSecretSet ? "••••••••" : ""}
                value={draft?.oidcClientSecret ?? ""}
                onChange={(e) => setDraft((d) => (d ? { ...d, oidcClientSecret: e.target.value } : d))}
              />
            </SettingsRow>

            <SettingsRow label="Scopes" description="Space-separated scopes; defaults to 'openid email profile'.">
              <Input
                aria-label="OIDC scopes"
                type="text"
                placeholder="openid email profile"
                value={draft?.oidcScopes ?? ""}
                onChange={(e) => setDraft((d) => (d ? { ...d, oidcScopes: e.target.value } : d))}
              />
            </SettingsRow>

            <SettingsRow
              label="Redirect URI"
              description="Register this URI with your IdP."
              layout="stack"
            >
              <code className="block w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface-2)] px-3 py-2 text-xs text-[var(--color-text-primary)] break-all">
                {data?.oidcRedirectUri ?? ""}
              </code>
            </SettingsRow>
          </>
        )}
      </SettingsCard>

      <SettingsCard heading="Provisioning (SCIM)">
        <SettingsRow label="Enable SCIM" description="Allow your IdP to create and deactivate users via the SCIM 2.0 API">
          <ToggleSwitch
            label="Toggle SCIM"
            checked={!!scim.data?.enabled}
            onChange={handleToggleScim}
          />
        </SettingsRow>

        <SettingsRow label="SCIM endpoint URL" description="Configure your IdP to use this URL." layout="stack">
          <code className="block w-full rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface-2)] px-3 py-2 text-xs text-[var(--color-text-primary)] break-all">
            {scim.data?.scimEndpointUrl ?? ""}
          </code>
        </SettingsRow>

        <SettingsRow
          label="Bearer token"
          description={scim.data?.tokenSet ? "A token is currently set. Generating a new one will replace it." : "No token configured."}
        >
          <Button variant="secondary" size="sm" onClick={handleGenerateScimToken}>
            {scim.data?.tokenSet ? "Regenerate token" : "Generate token"}
          </Button>
          {scim.data?.tokenSet && (
            <Button variant="secondary" size="sm" onClick={handleClearScimToken}>Clear</Button>
          )}
        </SettingsRow>
      </SettingsCard>

      <SettingsCard heading="Audit log streaming">
        <SettingsRow label="Enable streaming" description="Forward audit events to your SIEM in real time">
          <ToggleSwitch
            label="Toggle audit streaming"
            checked={!!auditDraft?.enabled}
            onChange={(v) => setAuditDraft((d) => (d ? { ...d, enabled: v } : d))}
          />
        </SettingsRow>

        <SettingsRow label="Target" description="Choose how events are delivered">
          <Select
            size="sm"
            aria-label="Audit-stream target"
            value={auditDraft?.targetType ?? ""}
            onChange={(e) => setAuditDraft((d) => (d ? { ...d, targetType: (e.target.value || null) as typeof d.targetType } : d))}
          >
            <option value="">— select —</option>
            <option value="webhook">Generic webhook</option>
            <option value="splunk_hec">Splunk HEC</option>
            <option value="syslog">Syslog (TCP)</option>
          </Select>
        </SettingsRow>

        <SettingsRow
          label="Endpoint URL"
          description={auditDraft?.targetType === "syslog" ? "host:port" : "Full URL"}
          layout="stack"
        >
          <Input
            aria-label="Audit-stream endpoint URL"
            type="text"
            value={auditDraft?.endpointUrl ?? ""}
            onChange={(e) => setAuditDraft((d) => (d ? { ...d, endpointUrl: e.target.value || null } : d))}
          />
        </SettingsRow>

        <SettingsRow
          label="Auth token"
          description={audit.data?.authTokenSet ? "Token is currently set. Enter a new one to replace it." : "Bearer for webhook; HEC token for Splunk; unused for syslog."}
          layout="stack"
        >
          <Input
            aria-label="Audit-stream auth token"
            type="password"
            placeholder={audit.data?.authTokenSet ? "••••••••" : ""}
            value={auditDraft?.authToken ?? ""}
            onChange={(e) => setAuditDraft((d) => (d ? { ...d, authToken: e.target.value } : d))}
          />
        </SettingsRow>

        <SettingsRow label="Status">
          <span className="text-xs text-[var(--color-text-secondary)]">
            {audit.data?.lastError
              ? `Last error: ${audit.data.lastError}`
              : audit.data?.lastSuccessAt
                ? `Last success: ${audit.data.lastSuccessAt}`
                : "No deliveries yet."}
          </span>
        </SettingsRow>

        <SettingsRow label="Actions">
          <Button variant="secondary" size="sm" onClick={handleSaveAudit}>Save audit settings</Button>
          <Button variant="secondary" size="sm" onClick={handleTestAudit}>Send test event</Button>
          {auditTestMsg && <span className="text-xs text-[var(--color-text-secondary)]">{auditTestMsg}</span>}
        </SettingsRow>
      </SettingsCard>

      <ScimTokenModal
        open={revealToken !== null}
        token={revealToken ?? ""}
        onClose={() => setRevealToken(null)}
      />
    </div>
  )
}


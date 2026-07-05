"use client"

import Link from "next/link"
import { useLicense } from "@/lib/client/license/client"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"

export interface AdvisorySourceState {
  enabled: boolean
  apiKey: string
  initialApiKey: string
  initialApiKeyHint: string
  showKey: boolean
  editingKey: boolean
}

export interface AdvisorySourceHandlers {
  setEnabled: (enabled: boolean) => void
  setApiKey: (key: string) => void
  setShowKey: (show: boolean) => void
  setEditingKey: (editing: boolean) => void
}

export interface AdvisorySourcesGridValues {
  nvd: AdvisorySourceState
  ghsa: AdvisorySourceState
  /** Only supplied when the Argus source card is rendered (see includeArgus). */
  argus?: AdvisorySourceState
}

export interface AdvisorySourcesGridHandlers {
  nvd: AdvisorySourceHandlers
  ghsa: AdvisorySourceHandlers
  argus?: AdvisorySourceHandlers
}

export interface AdvisorySourcesGridProps {
  values: AdvisorySourcesGridValues
  onChange: AdvisorySourcesGridHandlers
  canEdit: boolean
  /** Render the Argus advisory-source card. Off where Argus is surfaced as its
   *  own hosted-connection add-on instead of a per-scanner key. Default true. */
  includeArgus?: boolean
}

function maskKey(key: string, hint?: string): string {
  if (!key) return ""
  if (key === "[redacted]") return "•".repeat(8) + (hint || "")
  if (key.length <= 4) return "•".repeat(8)
  return "•".repeat(8) + key.slice(-4)
}

function EyeIcon({ open }: { open: boolean }) {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
      {open ? (
        <>
          <path d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" />
          <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
        </>
      ) : (
        <>
          <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
          <path fillRule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
        </>
      )}
    </svg>
  )
}

function WarningIcon() {
  return (
    <svg aria-hidden="true" className="h-3 w-3 shrink-0" viewBox="0 0 16 16" fill="currentColor">
      <path fillRule="evenodd" d="M8.22 1.754a.25.25 0 00-.44 0L1.698 13.132a.25.25 0 00.22.368h12.164a.25.25 0 00.22-.368L8.22 1.754zm-1.763-.707c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575L6.457 1.047zM9 11a1 1 0 11-2 0 1 1 0 012 0zm-.25-5.25a.75.75 0 00-1.5 0v2.5a.75.75 0 001.5 0v-2.5z" clipRule="evenodd" />
    </svg>
  )
}

function InfoIcon() {
  return (
    <svg aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 16 16" fill="currentColor">
      <path fillRule="evenodd" d="M15 8A7 7 0 111 8a7 7 0 0114 0zm-6 3.5a1 1 0 11-2 0 1 1 0 012 0zM8 5.5a1 1 0 00-.993.884L7 6.5v3a1 1 0 001.993.117L9 9.5v-3A1 1 0 008 5.5z" clipRule="evenodd" />
    </svg>
  )
}

function StatusDot() {
  return <svg aria-hidden="true" className="h-2.5 w-2.5" viewBox="0 0 6 6" fill="currentColor"><circle cx="3" cy="3" r="3" /></svg>
}

interface KeyInputProps {
  id?: string
  value: string
  onChange: (value: string) => void
  placeholder: string
  show: boolean
  onToggleShow: () => void
  ariaLabel: string
  errorState?: boolean
}

function KeyInput({ id, value, onChange, placeholder, show, onToggleShow, ariaLabel, errorState }: KeyInputProps) {
  return (
    <div className="relative">
      <Input
        id={id}
        type={show ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        invalid={errorState}
        className="pr-10"
      />
      <Button
        variant="link"
        size="xs"
        onClick={onToggleShow}
        className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)]"
        aria-label={ariaLabel}
      >
        <EyeIcon open={show} />
      </Button>
    </div>
  )
}

interface MaskedKeyDisplayProps {
  id?: string
  maskedValue: string
  canEdit: boolean
  onChangeClick: () => void
}

function MaskedKeyDisplay({ id, maskedValue, canEdit, onChangeClick }: MaskedKeyDisplayProps) {
  return (
    <div className="flex items-center gap-2">
      <Input
        id={id}
        type="text"
        value={maskedValue}
        readOnly
        className="min-w-0 flex-1 font-mono"
      />
      {canEdit && (
        <Button variant="secondary" size="sm" onClick={onChangeClick} className="shrink-0">
          Change
        </Button>
      )}
    </div>
  )
}

function NvdCard({ state, handlers, canEdit }: { state: AdvisorySourceState; handlers: AdvisorySourceHandlers; canEdit: boolean }) {
  const { enabled, apiKey, initialApiKey, initialApiKeyHint, showKey, editingKey } = state

  return (
    <div className={`relative space-y-3 rounded-lg border p-4 transition-colors ${
      enabled
        ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.03]"
        : "border-[var(--color-border)] bg-[var(--color-surface)]"
    }`}>
      <div className="flex items-start justify-between">
        <label className="flex items-center gap-2.5 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => handlers.setEnabled(e.target.checked)}
            className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
          />
          <div>
            <span className="font-medium text-[var(--color-text-primary)]">NVD (NIST)</span>
            <p className="text-xs text-[var(--color-text-secondary)]">National Vulnerability Database</p>
          </div>
        </label>
        {enabled && (
          <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full bg-[var(--color-state-fixed-subtle)] px-2 py-0.5 text-2xs font-medium text-[var(--color-state-fixed-text)]">
            <StatusDot />
            Active
          </span>
        )}
      </div>
      <div className={`space-y-3 transition-opacity ${enabled ? "" : "opacity-40 pointer-events-none"}`}>
        <FormField
          label={<>API Key <span className="font-normal text-[var(--color-text-tertiary)]">(optional)</span></>}
          htmlFor="advisory-nvd-key"
        >
          {!editingKey ? (
            <MaskedKeyDisplay
              id="advisory-nvd-key"
              maskedValue={maskKey(initialApiKey, initialApiKeyHint)}
              canEdit={canEdit}
              onChangeClick={() => { handlers.setEditingKey(true); handlers.setApiKey(""); handlers.setShowKey(false) }}
            />
          ) : (
            <KeyInput
              id="advisory-nvd-key"
              value={apiKey}
              onChange={handlers.setApiKey}
              placeholder="Enter NVD API key"
              show={showKey}
              onToggleShow={() => handlers.setShowKey(!showKey)}
              ariaLabel={showKey ? "Hide key" : "Show key"}
            />
          )}
        </FormField>

        <div className="flex items-start gap-2 rounded-md border border-[var(--color-border)]/60 bg-[var(--color-bg-section)] px-3 py-2.5">
          <InfoIcon />
          <div className="text-xs text-[var(--color-text-secondary)]">
            <p className="font-medium text-[var(--color-text-primary)]">How to get a key</p>
            <ol className="mt-1 list-inside list-decimal space-y-0.5 leading-relaxed">
              <li>Visit <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener noreferrer" className="text-[var(--color-accent)] hover:underline">nvd.nist.gov &rsaquo; Request API Key</a></li>
              <li>Enter your email and organization name</li>
              <li>Check your inbox and paste the key above</li>
            </ol>
            <div className="mt-2 flex items-center gap-3 border-t border-[var(--color-border)]/40 pt-2 text-[var(--color-text-tertiary)]">
              <span className="flex items-center gap-1">
                <svg aria-hidden="true" className="h-3 w-3" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8zm9-3a1 1 0 11-2 0 1 1 0 012 0zM8 6.5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 018 6.5z" /></svg>
                Without key: 5 req/30s
              </span>
              <span className="flex items-center gap-1">
                <svg aria-hidden="true" className="h-3 w-3 text-[var(--color-state-fixed-text)]" viewBox="0 0 16 16" fill="currentColor"><path fillRule="evenodd" d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8zm11.28-1.72a.75.75 0 010 1.06l-4 4a.75.75 0 01-1.06 0l-2-2a.75.75 0 111.06-1.06L6.75 9.69l3.47-3.47a.75.75 0 011.06 0z" clipRule="evenodd" /></svg>
                With key: 50 req/30s
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function GhsaCard({ state, handlers, canEdit }: { state: AdvisorySourceState; handlers: AdvisorySourceHandlers; canEdit: boolean }) {
  const { enabled, apiKey, initialApiKey, initialApiKeyHint, showKey, editingKey } = state
  const hasKey = apiKey.trim() || (!editingKey && initialApiKey)
  const missingKey = enabled && !apiKey.trim() && editingKey

  return (
    <div className={`relative space-y-3 rounded-lg border p-4 transition-colors ${
      enabled
        ? hasKey
          ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.03]"
          : "border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)]"
        : "border-[var(--color-border)] bg-[var(--color-surface)]"
    }`}>
      <div className="flex items-start justify-between">
        <label className="flex items-center gap-2.5 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => handlers.setEnabled(e.target.checked)}
            className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
          />
          <div>
            <span className="font-medium text-[var(--color-text-primary)]">GitHub Advisory Database</span>
            <p className="text-xs text-[var(--color-text-secondary)]">GHSA-enriched Vulnerability Database</p>
          </div>
        </label>
        {enabled && (
          <span className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-2xs font-medium ${
            hasKey
              ? "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed-text)]"
              : "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]"
          }`}>
            <StatusDot />
            {hasKey ? "Active" : "Needs key"}
          </span>
        )}
      </div>
      <div className={`space-y-3 transition-opacity ${enabled ? "" : "opacity-40 pointer-events-none"}`}>
        <FormField
          label={<>GitHub PAT <span className="font-normal text-[var(--color-state-pending-text)]">(required)</span></>}
          htmlFor="advisory-ghsa-key"
        >
          {!editingKey ? (
            <MaskedKeyDisplay
              id="advisory-ghsa-key"
              maskedValue={maskKey(initialApiKey, initialApiKeyHint)}
              canEdit={canEdit}
              onChangeClick={() => { handlers.setEditingKey(true); handlers.setApiKey(""); handlers.setShowKey(false) }}
            />
          ) : (
            <>
              <KeyInput
                id="advisory-ghsa-key"
                value={apiKey}
                onChange={handlers.setApiKey}
                placeholder="ghp_..."
                show={showKey}
                onToggleShow={() => handlers.setShowKey(!showKey)}
                ariaLabel={showKey ? "Hide key" : "Show key"}
                errorState={enabled && !apiKey.trim()}
              />
              {missingKey && (
                <p className="mt-1.5 flex items-center gap-1 text-xs text-[var(--color-state-pending-text)]">
                  <WarningIcon />
                  A GitHub PAT is required to query the advisory database.
                </p>
              )}
            </>
          )}
        </FormField>

        <div className="flex items-start gap-2 rounded-md border border-[var(--color-border)]/60 bg-[var(--color-bg-section)] px-3 py-2.5">
          <InfoIcon />
          <div className="text-xs text-[var(--color-text-secondary)]">
            <p className="font-medium text-[var(--color-text-primary)]">How to create a PAT</p>
            <ol className="mt-1 list-inside list-decimal space-y-0.5 leading-relaxed">
              <li>Go to <a href="https://github.com/settings/tokens?type=beta" target="_blank" rel="noopener noreferrer" className="text-[var(--color-accent)] hover:underline">GitHub &rsaquo; Settings &rsaquo; Tokens</a> (fine-grained)</li>
              <li>Click &quot;Generate new token&quot;</li>
              <li>No extra permissions needed &mdash; advisory access is public</li>
            </ol>
            <p className="mt-1.5 text-[var(--color-text-tertiary)]">
              A classic PAT with zero scopes also works.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

function ArgusUnlicensedCard() {
  return (
    <div className="relative space-y-3 rounded-lg border border-[var(--color-argus-border)] bg-[var(--color-argus-subtle)] p-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium text-[var(--color-text-primary)]">Blu3Raven Argus</span>
            <span className="rounded-full bg-[var(--color-argus-subtle)] px-2 py-0.5 text-2xs font-semibold text-[var(--color-argus)]">Add-on</span>
          </div>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            AI-powered threat intelligence with EPSS scores, exploit availability, and advisory enrichment. Requires a Blu3Raven Argus license.
          </p>
        </div>
        <Link
          href="/settings/license"
          className="shrink-0 rounded-lg border border-[var(--color-argus-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-argus)] transition-colors hover:bg-[var(--color-argus-subtle)]"
        >
          Activate
        </Link>
      </div>
    </div>
  )
}

function ArgusCard({ state, handlers, canEdit }: { state: AdvisorySourceState; handlers: AdvisorySourceHandlers; canEdit: boolean }) {
  const { enabled, apiKey, initialApiKey, initialApiKeyHint, showKey, editingKey } = state
  const hasKey = apiKey.trim() || (!editingKey && initialApiKey)
  const missingKey = enabled && !apiKey.trim() && editingKey

  return (
    <div className={`relative space-y-3 rounded-lg border p-4 transition-colors ${
      enabled
        ? hasKey
          ? "border-[var(--color-accent)]/40 bg-[var(--color-accent)]/[0.03]"
          : "border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)]"
        : "border-[var(--color-border)] bg-[var(--color-surface)]"
    }`}>
      <div className="flex items-start justify-between">
        <label className="flex items-center gap-2.5 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => handlers.setEnabled(e.target.checked)}
            className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30"
          />
          <div>
            <span className="font-medium text-[var(--color-text-primary)]">Blu3Raven Argus</span>
            <p className="text-xs text-[var(--color-text-secondary)]">AI-Powered Threat Intelligence</p>
          </div>
        </label>
        {enabled && (
          <span className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-2xs font-medium ${
            hasKey
              ? "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed-text)]"
              : "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]"
          }`}>
            <StatusDot />
            {hasKey ? "Active" : "Needs key"}
          </span>
        )}
      </div>
      <div className={`space-y-3 transition-opacity ${enabled ? "" : "opacity-40 pointer-events-none"}`}>
        <FormField
          label={<>API Key <span className="font-normal text-[var(--color-state-pending-text)]">(required)</span></>}
          htmlFor="advisory-argus-key"
        >
          {!editingKey ? (
            <MaskedKeyDisplay
              id="advisory-argus-key"
              maskedValue={maskKey(initialApiKey, initialApiKeyHint)}
              canEdit={canEdit}
              onChangeClick={() => { handlers.setEditingKey(true); handlers.setApiKey(""); handlers.setShowKey(false) }}
            />
          ) : (
            <>
              <KeyInput
                id="advisory-argus-key"
                value={apiKey}
                onChange={handlers.setApiKey}
                placeholder="argus_..."
                show={showKey}
                onToggleShow={() => handlers.setShowKey(!showKey)}
                ariaLabel={showKey ? "Hide key" : "Show key"}
                errorState={enabled && !apiKey.trim()}
              />
              {missingKey && (
                <p className="mt-1.5 flex items-center gap-1 text-xs text-[var(--color-state-pending-text)]">
                  <WarningIcon />
                  An API key is required to use Argus enrichment.
                </p>
              )}
            </>
          )}
        </FormField>

        <div className="flex items-start gap-2 rounded-md border border-[var(--color-border)]/60 bg-[var(--color-bg-section)] px-3 py-2.5">
          <InfoIcon />
          <div className="text-xs text-[var(--color-text-secondary)]">
            <p className="font-medium text-[var(--color-text-primary)]">How to get an API key</p>
            <p className="mt-1 leading-relaxed">
              API key provisioning instructions coming soon. Contact your Blu3Raven representative for early access.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export function AdvisorySourcesGrid({ values, onChange, canEdit, includeArgus = true }: AdvisorySourcesGridProps) {
  const { addons } = useLicense()
  const hasArgusLicense = addons?.includes("argus") ?? false
  const showArgus = includeArgus && values.argus && onChange.argus

  return (
    <div className={`grid grid-cols-1 gap-6 md:grid-cols-2 ${showArgus ? "lg:grid-cols-3" : ""}`}>
      <NvdCard state={values.nvd} handlers={onChange.nvd} canEdit={canEdit} />
      <GhsaCard state={values.ghsa} handlers={onChange.ghsa} canEdit={canEdit} />
      {showArgus &&
        (hasArgusLicense ? (
          <ArgusCard state={values.argus!} handlers={onChange.argus!} canEdit={canEdit} />
        ) : (
          <ArgusUnlicensedCard />
        ))}
    </div>
  )
}

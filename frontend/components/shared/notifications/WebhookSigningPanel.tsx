"use client"

import { useCallback, useEffect, useState } from "react"
import type { SigningSecretMeta, RotateSecretResponse } from "@/lib/client/webhook-signing-api"
import { listSigningSecrets, rotateSigningSecret, revokeSigningSecret } from "@/lib/client/webhook-signing-api"
import { Button } from "@/components/ui/Button"
import { Sheet } from "@/components/ui/Sheet"
import { SegmentedControl } from "@/components/ui/SegmentedControl"

interface WebhookSigningPanelProps {
  destId: number
}

const PYTHON_SNIPPET = `import hashlib, hmac, json, time

def verify_aegis_webhook(payload_bytes: bytes, secret: str,
                          timestamp_str: str, signature_header: str,
                          tolerance: int = 300) -> bool:
    age = abs(time.time() - int(timestamp_str))
    if age > tolerance:
        return False
    payload = json.loads(payload_bytes)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signed = f"{timestamp_str}.{canonical}".encode()
    expected = "v1=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    candidates = signature_header.split(",")
    return any(hmac.compare_digest(expected, s.strip()) for s in candidates)
`

const NODE_SNIPPET = `const crypto = require("crypto");

function verifyAegisWebhook(payloadBuffer, secret, timestampStr, signatureHeader, tolerance = 300) {
  const age = Math.abs(Date.now() / 1000 - Number(timestampStr));
  if (age > tolerance) return false;
  const payload = JSON.parse(payloadBuffer.toString());
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  const signed = \`\${timestampStr}.\${canonical}\`;
  const expected = "v1=" + crypto.createHmac("sha256", secret).update(signed).digest("hex");
  return signatureHeader.split(",").some(
    (s) => crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(s.trim()))
  );
}
`

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <Button
      variant="secondary"
      size="xs"
      onClick={handleCopy}
      aria-label="Copy to clipboard"
    >
      {copied ? "Copied!" : "Copy"}
    </Button>
  )
}

function StatusBadge({ status }: { status: SigningSecretMeta["status"] }) {
  const styles: Record<SigningSecretMeta["status"], string> = {
    active: "bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]",
    rotating: "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]",
    revoked: "bg-[var(--color-border)] text-[var(--color-text-tertiary)]",
  }
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-2xs font-semibold ${styles[status]}`}>
      {status}
    </span>
  )
}

interface RotateModalProps {
  open: boolean
  destId: number
  onClose: () => void
  onRotated: (result: RotateSecretResponse) => void
}

function RotateModal({ open, destId, onClose, onRotated }: RotateModalProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<RotateSecretResponse | null>(null)
  const [rawCopied, setRawCopied] = useState(false)

  async function handleConfirm() {
    setLoading(true)
    setError(null)
    try {
      const res = await rotateSigningSecret(destId)
      setResult(res)
      onRotated(res)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to rotate secret")
    } finally {
      setLoading(false)
    }
  }

  function handleCopyRaw() {
    if (!result) return
    void navigator.clipboard.writeText(result.secret.raw).then(() => {
      setRawCopied(true)
      setTimeout(() => setRawCopied(false), 3000)
    })
  }

  // Once the new secret is shown, block dismissal until the user explicitly
  // acknowledges they've copied it — same affordance as before, just routed
  // through Sheet's dismissGuard for consistent Esc/backdrop behavior.
  const handleClose = () => {
    if (result || !loading) onClose()
  }

  return (
    <Sheet
      open={open}
      onClose={handleClose}
      title={result ? "New signing secret — save it now" : "Rotate signing secret"}
      description={
        result
          ? "This secret will not be shown again. Copy it before closing."
          : "A new secret will be generated. The current secret will remain valid during the 5-minute rotation window so receivers can upgrade gracefully."
      }
      size="md"
      footer={
        <div className="flex justify-end gap-2">
          {!result ? (
            <>
              <Button variant="secondary" size="sm" onClick={onClose} disabled={loading}>
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() => { void handleConfirm() }}
                disabled={loading}
                isLoading={loading}
              >
                {loading ? "Rotating…" : "Rotate"}
              </Button>
            </>
          ) : (
            <Button variant="primary" size="sm" onClick={onClose}>
              Done
            </Button>
          )}
        </div>
      }
    >
      {!result ? (
        error && (
          <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
        )
      ) : (
        <>
          <div
            data-testid="new-secret-value"
            className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2"
          >
            <code className="flex-1 break-all font-mono text-xs text-[var(--color-text-primary)]">
              {result.secret.raw}
            </code>
            <Button
              variant="secondary"
              size="xs"
              onClick={handleCopyRaw}
              aria-label="Copy secret"
              className="shrink-0"
            >
              {rawCopied ? "Copied!" : "Copy"}
            </Button>
          </div>
          <p className="mt-2 text-[11px] text-[var(--color-text-tertiary)]">
            Version {result.signing_secret_version} · {result.notice}
          </p>
        </>
      )}
    </Sheet>
  )
}

export function WebhookSigningPanel({ destId }: WebhookSigningPanelProps) {
  const [secrets, setSecrets] = useState<SigningSecretMeta[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showRotateModal, setShowRotateModal] = useState(false)
  const [revoking, setRevoking] = useState<number | null>(null)
  const [revokeError, setRevokeError] = useState<string | null>(null)
  const [snippetLang, setSnippetLang] = useState<"python" | "node">("python")
  const [snippetOpen, setSnippetOpen] = useState(false)

  const loadSecrets = useCallback(() => {
    setLoading(true)
    setError(null)
    listSigningSecrets(destId)
      .then((rows) => setSecrets(rows))
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false))
  }, [destId])

  useEffect(() => {
    loadSecrets()
  }, [loadSecrets])

  function handleRotated() {
    setShowRotateModal(false)
    loadSecrets()
  }

  async function handleRevoke(version: number) {
    if (!window.confirm(`Revoke version ${version}? Receivers using this key will fail immediately.`)) return
    setRevoking(version)
    setRevokeError(null)
    try {
      await revokeSigningSecret(destId, version)
      loadSecrets()
    } catch (err: unknown) {
      setRevokeError(err instanceof Error ? err.message : "Failed to revoke")
    } finally {
      setRevoking(null)
    }
  }

  const labelClass =
    "text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <p className={labelClass}>Signing secret</p>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setShowRotateModal(true)}
          data-testid="rotate-secret-button"
        >
          Rotate secret
        </Button>
      </div>

      {loading && (
        <p className="text-xs text-[var(--color-text-tertiary)]">Loading…</p>
      )}

      {error && (
        <p className="text-xs text-[var(--color-severity-critical)]">{error}</p>
      )}

      {revokeError && (
        <p className="text-xs text-[var(--color-severity-critical)]">{revokeError}</p>
      )}

      {!loading && secrets.length === 0 && (
        <p className="text-xs text-[var(--color-text-tertiary)]">
          No signing secret configured. Click <strong>Rotate secret</strong> to generate one.
        </p>
      )}

      {/* Secret versions list */}
      {secrets.length > 0 && (
        <ul className="divide-y divide-[var(--color-border)] rounded-lg border border-[var(--color-border)]">
          {secrets.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-3 px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-[var(--color-text-primary)]">
                  v{s.version}
                </span>
                <StatusBadge status={s.status} />
                <span className="text-[11px] text-[var(--color-text-tertiary)]">
                  Created {new Date(s.created_at).toLocaleDateString()}
                </span>
                {s.revoked_at && (
                  <span className="text-[11px] text-[var(--color-text-tertiary)]">
                    · Revoked {new Date(s.revoked_at).toLocaleDateString()}
                  </span>
                )}
              </div>
              {s.status !== "revoked" && (
                <Button
                  variant="link"
                  size="xs"
                  onClick={() => { void handleRevoke(s.version) }}
                  disabled={revoking === s.version}
                  aria-label={`Revoke version ${s.version}`}
                  className="text-[var(--color-severity-critical)] hover:underline hover:text-[var(--color-severity-critical)]"
                >
                  {revoking === s.version ? "Revoking…" : "Revoke"}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}

      {/* Verification snippet expandable */}
      <div className="rounded-xl border border-[var(--color-border)]">
        <button
          type="button"
          onClick={() => setSnippetOpen((p) => !p)}
          className="flex w-full items-center justify-between px-3 py-2 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] transition-colors rounded-xl"
        >
          <span>Verification snippet</span>
          <span className="font-mono">{snippetOpen ? "−" : "+"}</span>
        </button>

        {snippetOpen && (
          <div className="border-t border-[var(--color-border)] px-3 pb-3 pt-2 space-y-3">
            {/* Language toggle */}
            <SegmentedControl
              ariaLabel="Snippet language"
              value={snippetLang}
              onChange={setSnippetLang}
              options={[
                { id: "python", label: "Python" },
                { id: "node",   label: "Node.js" },
              ]}
            />

            <div className="relative">
              <pre className="overflow-x-auto rounded-lg bg-[var(--color-surface-raised)] p-3 text-[11px] font-mono text-[var(--color-text-primary)] whitespace-pre">
                {snippetLang === "python" ? PYTHON_SNIPPET : NODE_SNIPPET}
              </pre>
              <div className="absolute right-2 top-2">
                <CopyButton text={snippetLang === "python" ? PYTHON_SNIPPET : NODE_SNIPPET} />
              </div>
            </div>

            <p className="text-[11px] text-[var(--color-text-tertiary)]">
              Headers: <code className="font-mono">X-Aegis-Timestamp</code>,{" "}
              <code className="font-mono">X-Aegis-Signature</code>,{" "}
              <code className="font-mono">X-Aegis-Signature-Version</code>
            </p>
          </div>
        )}
      </div>

      {/* Rotate modal */}
      <RotateModal
        open={showRotateModal}
        destId={destId}
        onClose={() => { setShowRotateModal(false); handleRotated() }}
        onRotated={handleRotated}
      />
    </div>
  )
}

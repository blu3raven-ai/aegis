import { cn } from "@/lib/shared/utils"

type Props = {
  /** Whether the scanner confirmed the credential is live; undefined when the detector can't validate. */
  verified: boolean | undefined
  /** Detector that fired (e.g. "AWS secret"), shown as the provider context. */
  detector: string | undefined
}

/**
 * Verification panel for secret findings. Secrets are verified by the secret
 * scanner's live provider check — never by an LLM — so this is their equivalent
 * of the LLM EvidenceSection: it surfaces whether the credential authenticated
 * against the provider, which is the single most decision-relevant signal for a
 * leaked secret. Renders nothing when the detector couldn't validate (the chip
 * and this panel both stay quiet rather than imply a result).
 */
export function SecretVerificationSection({ verified, detector }: Props) {
  if (verified == null) return null

  return (
    <section>
      <h3 className="mb-2 text-base font-semibold text-[var(--color-text-primary)]">
        Verification
      </h3>
      <div
        className={cn(
          "rounded border p-3",
          verified
            ? "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)]"
            : "border-[var(--color-border)] bg-[var(--color-bg-section)]",
        )}
      >
        <div className="flex items-center gap-2">
          {verified ? (
            <svg viewBox="0 0 24 24" className="h-4 w-4 text-[var(--color-severity-critical-text)]" fill="currentColor" aria-hidden="true">
              <path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" className="h-4 w-4 text-[var(--color-text-secondary)]" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
              <circle cx="12" cy="12" r="9" />
              <path d="M12 8v4M12 16h.01" />
            </svg>
          )}
          <span
            className={cn(
              "text-sm font-semibold",
              verified
                ? "text-[var(--color-severity-critical-text)]"
                : "text-[var(--color-text-primary)]",
            )}
          >
            {verified ? "Live credential — provider-verified" : "Not verified live"}
          </span>
        </div>
        <p className="mt-1.5 text-sm leading-relaxed text-[var(--color-text-primary)]">
          {verified
            ? `The secret scanner authenticated this credential against the provider${detector ? ` (${detector})` : ""} — it is active and usable right now. Rotate it immediately.`
            : `The secret scanner could not confirm this credential is active against the provider${detector ? ` (${detector})` : ""}. It may be revoked, rotated, or a non-live format — still treat it as a leak and rotate.`}
        </p>
        <p className="mt-2 font-mono text-2xs uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Checked by the secret scanner
        </p>
      </div>
    </section>
  )
}

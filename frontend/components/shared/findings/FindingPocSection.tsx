"use client"

import { useCallback, useRef, useState } from "react"

import { Button, buttonClassName } from "@/components/ui/Button"
import { findingPocUrl, generateFindingPoc } from "@/lib/client/findings-api"

interface GeneratedPoc {
  poc_script: string
  poc_filename: string
  poc_language: string
}

interface FindingPocSectionProps {
  findingId: number
  pocScript?: string
  pocFilename?: string
  pocLanguage?: string
  /** Called after a successful generate/regenerate so the drawer can update the finding. */
  onGenerated: (poc: GeneratedPoc) => void
}

/**
 * On-demand proof-of-concept panel for a finding: generate a benign PoC, refine
 * it with free-text guidance and regenerate, cancel a run in flight, and
 * download or copy the result. The benign hard-rules are enforced server-side,
 * so guidance can steer the script but never weaponize it.
 */
export function FindingPocSection({
  findingId,
  pocScript,
  pocFilename,
  pocLanguage,
  onGenerated,
}: FindingPocSectionProps) {
  const [instruction, setInstruction] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  const run = useCallback(async () => {
    const controller = new AbortController()
    abortRef.current = controller
    setBusy(true)
    setError(null)
    try {
      const poc = await generateFindingPoc(findingId, {
        instruction: instruction.trim() || undefined,
        signal: controller.signal,
      })
      onGenerated(poc)
    } catch (err) {
      // A user-triggered cancel is not an error.
      if (!controller.signal.aborted) {
        setError(err instanceof Error ? err.message : "Failed to generate PoC")
      }
    } finally {
      setBusy(false)
      abortRef.current = null
    }
  }, [findingId, instruction, onGenerated])

  const cancel = useCallback(() => abortRef.current?.abort(), [])

  const copy = useCallback(() => {
    if (!pocScript) return
    void navigator.clipboard?.writeText(pocScript).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }, [pocScript])

  const meta = [pocFilename, pocLanguage].filter(Boolean).join(" · ")

  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Proof of Concept</h3>
        {pocScript && meta ? (
          <span className="text-2xs font-mono text-[var(--color-text-tertiary)]">{meta}</span>
        ) : null}
      </div>

      {pocScript ? (
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 font-mono text-xs leading-relaxed text-[var(--color-text-primary)]">
          {pocScript}
        </pre>
      ) : (
        <p className="text-sm text-[var(--color-text-secondary)]">
          Generate a runnable, benign proof-of-concept that demonstrates this finding is reachable.
        </p>
      )}

      {busy ? (
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" isLoading disabled>
            Generating…
          </Button>
          <Button variant="ghost" size="sm" onClick={cancel}>
            Cancel
          </Button>
        </div>
      ) : (
        <>
          {pocScript ? (
            <div className="flex flex-wrap items-center gap-2">
              <a
                href={findingPocUrl(findingId)}
                download
                className={buttonClassName({ variant: "secondary", size: "sm" })}
              >
                Download
              </a>
              <Button variant="secondary" size="sm" onClick={copy}>
                {copied ? "Copied" : "Copy"}
              </Button>
            </div>
          ) : null}
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={instruction}
              onChange={(e) => setInstruction(e.target.value)}
              maxLength={500}
              aria-label="Proof-of-concept guidance"
              placeholder={
                pocScript
                  ? "Refine (optional): what should it change?"
                  : "Guidance (optional): e.g. target the login route, prefer curl"
              }
              onKeyDown={(e) => {
                if (e.key === "Enter") run()
              }}
              className="h-8 flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]"
            />
            <Button variant="secondary" size="sm" onClick={run}>
              {pocScript ? "Regenerate" : "Generate PoC"}
            </Button>
          </div>
        </>
      )}

      {error ? (
        <span role="alert" className="block text-xs text-[var(--color-severity-critical-text)]">
          {error}
        </span>
      ) : null}
    </section>
  )
}

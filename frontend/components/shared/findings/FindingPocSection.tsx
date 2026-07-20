"use client"

import { useCallback, useRef, useState } from "react"
import { Copy, Download, Sparkles } from "lucide-react"

import { Button, buttonClassName } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { LinkButton } from "@/components/ui/LinkButton"
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
  /** Whether an LLM model key is configured. Generation needs one, so with it
   *  off the panel shows a blurred preview and the BYOK call to action. */
  verificationEnabled?: boolean
  /** Called after a successful generate/regenerate so the drawer can update the finding. */
  onGenerated: (poc: GeneratedPoc) => void
}

// Ghosted script lines blurred behind the call to action when generation is
// locked. Decorative, so aria-hidden and inert.
function GhostScript() {
  const widths = ["w-9/12", "w-11/12", "w-7/12", "w-10/12", "w-6/12", "w-8/12"]
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none select-none space-y-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 opacity-60 blur-[3px]"
    >
      {widths.map((w, i) => (
        <div key={i} className={`h-2.5 rounded bg-[var(--color-surface-raised)] ${w}`} />
      ))}
    </div>
  )
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
  verificationEnabled = true,
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
      {pocScript && meta ? (
        <p className="text-right text-2xs font-mono text-[var(--color-text-tertiary)]">{meta}</p>
      ) : null}

      {pocScript ? (
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 font-mono text-xs leading-relaxed text-[var(--color-text-primary)]">
          {pocScript}
        </pre>
      ) : verificationEnabled ? (
        <p className="text-sm text-[var(--color-text-secondary)]">
          Generate a runnable, benign proof-of-concept that demonstrates this finding is reachable.
        </p>
      ) : (
        // No model key configured: preview the shape, gate generation behind BYOK.
        <div className="relative overflow-hidden rounded-md">
          <GhostScript />
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-[color-mix(in_srgb,var(--color-surface)_55%,transparent)] px-6 text-center">
            <p className="max-w-sm text-xs leading-relaxed text-[var(--color-text-secondary)]">
              A benign proof-of-concept that demonstrates reachability is generated on demand.
            </p>
            <LinkButton
              href="/settings#llm"
              variant="primary"
              size="sm"
              trailingIcon={<span aria-hidden="true">→</span>}
            >
              Enable LLM verification
            </LinkButton>
          </div>
        </div>
      )}

      {/* Download / copy an existing script needs no model key. */}
      {pocScript && !busy ? (
        <div className="flex flex-wrap items-center gap-2">
          <a
            href={findingPocUrl(findingId)}
            download
            className={buttonClassName({ variant: "secondary", size: "sm" })}
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            Download
          </a>
          <Button
            variant="secondary"
            size="sm"
            leadingIcon={<Copy className="h-3.5 w-3.5" />}
            onClick={copy}
          >
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      ) : null}

      {/* Generation controls need a configured model key. */}
      {verificationEnabled &&
        (busy ? (
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" isLoading disabled>
              Generating…
            </Button>
            <Button variant="ghost" size="sm" onClick={cancel}>
              Cancel
            </Button>
          </div>
        ) : (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <Input
                size="sm"
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
                className="flex-1"
              />
              <Button
                variant="secondary"
                size="sm"
                leadingIcon={<Sparkles className="h-3.5 w-3.5" />}
                onClick={run}
              >
                {pocScript ? "Regenerate" : "Generate PoC"}
              </Button>
            </div>
            <p className="text-2xs text-[var(--color-text-tertiary)]">
              Runs on demand and spends tokens. The script proves reachability with a benign marker only.
            </p>
          </div>
        ))}

      {error ? (
        <span role="alert" className="block text-xs text-[var(--color-severity-critical-text)]">
          {error}
        </span>
      ) : null}
    </section>
  )
}

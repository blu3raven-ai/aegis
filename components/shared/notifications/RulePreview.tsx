"use client"

/**
 * Preview pane for notification routing rules.
 *
 * Lets the user fill in a sample finding and immediately see which rules
 * would match (calls the /preview endpoint against the full org rule set).
 */

import { useState } from "react"
import type {
  PreviewBreakdownItem,
  PreviewFinding,
} from "@/lib/client/notification-rules-api"
import { previewOrg } from "@/lib/client/notification-rules-api"

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"]
const SCANNER_OPTIONS = ["dependencies", "code_scanning", "secrets", "container_scanning"]

interface RulePreviewProps {
  orgId: string
}

export function RulePreview({ orgId }: RulePreviewProps) {
  const [finding, setFinding] = useState<PreviewFinding>({
    severity: "high",
    scanner: "dependencies",
    repo_id: "",
    repo_labels: [],
  })
  const [labelsInput, setLabelsInput] = useState("")
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [breakdown, setBreakdown] = useState<PreviewBreakdownItem[] | null>(null)
  const [matchedIds, setMatchedIds] = useState<number[] | null>(null)

  async function handleRun() {
    setRunning(true)
    setError(null)
    setBreakdown(null)
    setMatchedIds(null)

    const labels = labelsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)

    try {
      const result = await previewOrg({
        org_id: orgId,
        finding: { ...finding, repo_labels: labels },
      })
      setBreakdown(result.breakdown)
      setMatchedIds(result.matched_channel_ids)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Preview failed")
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-[var(--color-text-secondary)]">
        Configure a sample finding and run the preview to see which rules match.
      </p>

      {/* Sample finding form */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {/* Severity */}
        <div>
          <label
            htmlFor="preview-severity"
            className="block text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)] mb-1"
          >
            Severity
          </label>
          <select
            id="preview-severity"
            value={finding.severity ?? "high"}
            onChange={(e) => setFinding((f) => ({ ...f, severity: e.target.value }))}
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>

        {/* Scanner */}
        <div>
          <label
            htmlFor="preview-scanner"
            className="block text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)] mb-1"
          >
            Scanner
          </label>
          <select
            id="preview-scanner"
            value={finding.scanner ?? ""}
            onChange={(e) => setFinding((f) => ({ ...f, scanner: e.target.value }))}
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
          >
            <option value="">Any</option>
            {SCANNER_OPTIONS.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>

        {/* Repo ID */}
        <div>
          <label
            htmlFor="preview-repo-id"
            className="block text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)] mb-1"
          >
            Repository ID
          </label>
          <input
            id="preview-repo-id"
            type="text"
            value={finding.repo_id ?? ""}
            onChange={(e) => setFinding((f) => ({ ...f, repo_id: e.target.value }))}
            placeholder="e.g. repo-abc123"
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
          />
        </div>

        {/* Repo labels */}
        <div>
          <label
            htmlFor="preview-repo-labels"
            className="block text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)] mb-1"
          >
            Repo labels
          </label>
          <input
            id="preview-repo-labels"
            type="text"
            value={labelsInput}
            onChange={(e) => setLabelsInput(e.target.value)}
            placeholder="production, backend, …"
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
          />
        </div>
      </div>

      {/* Run button */}
      <button
        type="button"
        onClick={handleRun}
        disabled={running}
        className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] disabled:opacity-60"
      >
        {running ? "Running…" : "Preview"}
      </button>

      {/* Error */}
      {error && (
        <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
      )}

      {/* Results */}
      {breakdown !== null && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
          <div className="px-4 py-2.5 border-b border-[var(--color-border)]">
            <span className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-[0.12em]">
              Results
            </span>
            {matchedIds !== null && matchedIds.length > 0 ? (
              <span className="ml-2 text-xs text-[var(--color-status-ok)] font-medium">
                {matchedIds.length} channel{matchedIds.length !== 1 ? "s" : ""} matched
              </span>
            ) : (
              <span className="ml-2 text-xs text-[var(--color-text-tertiary)] font-medium">
                No rules matched — default fanout applies
              </span>
            )}
          </div>

          {breakdown.length === 0 ? (
            <p className="px-4 py-3 text-sm text-[var(--color-text-tertiary)]">
              No active rules to evaluate.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--color-border)]">
                  {["Priority", "Rule", "Match"].map((h) => (
                    <th
                      key={h}
                      className="px-4 py-2 text-left text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-divider)]">
                {breakdown.map((row) => (
                  <tr key={row.rule_id} className={row.matched ? "bg-[var(--color-status-ok)]/5" : ""}>
                    <td className="px-4 py-2 tabular-nums text-[var(--color-text-tertiary)] text-xs">
                      {row.priority}
                    </td>
                    <td className="px-4 py-2 font-medium text-[var(--color-text-primary)]">
                      {row.rule_name}
                    </td>
                    <td className="px-4 py-2">
                      {row.matched ? (
                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-[var(--color-status-ok)]">
                          <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-status-ok)]" aria-hidden="true" />
                          Match
                        </span>
                      ) : (
                        <span className="text-xs text-[var(--color-text-tertiary)]">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

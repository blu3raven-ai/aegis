"use client";

import { VerdictBadge, type Verdict } from "./VerdictBadge";

type EvidenceKind = "source" | "sink" | "gate";
type Evidence = { file: string; line: number; snippet: string; kind: EvidenceKind };
type RuledOutReason = {
  file?: string | null;
  line?: number | null;
  snippet?: string | null;
  reasoning?: string | null;
};

type VerificationMetadata = {
  model?: string;
  tokens_in?: number;
  tokens_out?: number;
  ruled_out_reason?: RuledOutReason;
  skipped?: string;
  [k: string]: unknown;
};

type Props = {
  verdict: Verdict;
  evidence: Evidence[] | null | undefined;
  exploitChain: string | null | undefined;
  metadata: VerificationMetadata | null | undefined;
};

const KIND_COLOR: Record<EvidenceKind, string> = {
  source: "text-[var(--color-severity-medium)]",
  sink: "text-[var(--color-severity-critical)]",
  gate: "text-[var(--color-status-ok)]",
};

/**
 * Drop-in evidence block for the existing FindingDrawer. Renders the LLM
 * verification verdict + exploit chain + per-citation evidence + (optional)
 * ruled-out reason. Returns null when nothing to show.
 */
export function EvidenceSection({ verdict, evidence, exploitChain, metadata }: Props) {
  const hasChain = Boolean(exploitChain);
  const hasEvidence = Boolean(evidence && evidence.length > 0);
  const ruledOut = metadata?.ruled_out_reason;
  const hasMetadata = Boolean(metadata?.model || metadata?.tokens_in);
  const llmDisabled = metadata?.skipped === "llm_disabled";

  // Render the "verification available" hint when we have nothing else
  // to show because the BYO-LLM key isn't configured. Silently render
  // null only when there's truly no verification signal AND no hint to
  // surface.
  if (!verdict && !hasChain && !hasEvidence && !ruledOut && !hasMetadata) {
    if (!llmDisabled) return null;
    return (
      <section className="mt-6">
        <div className="mb-2">
          <h3 className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Verification
          </h3>
        </div>
        <div className="rounded border border-dashed border-[var(--color-border)] bg-[var(--color-bg-section)] p-3">
          <p className="text-sm text-[var(--color-text-primary)]">
            LLM-driven exploit verification is available for this finding.
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            Configure an LLM endpoint (set <code className="font-mono">LLM_API_KEY</code>) on the
            scanner runner to enable verdict, exploit chain, and cited evidence on each finding.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="mt-6">
      <div className="mb-2 flex items-center gap-2">
        <h3 className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Verification
        </h3>
        <VerdictBadge verdict={verdict} />
      </div>

      {hasChain && (
        <p className="text-sm text-[var(--color-text-primary)] leading-relaxed">{exploitChain}</p>
      )}

      {hasEvidence && (
        <ul className="mt-3 space-y-2">
          {evidence!.map((e, i) => (
            <li
              key={i}
              className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-2"
            >
              <div className="flex items-center justify-between gap-3 text-2xs font-semibold uppercase tracking-[0.14em]">
                <span className={KIND_COLOR[e.kind] || "text-[var(--color-text-secondary)]"}>
                  {e.kind}
                </span>
                <span
                  className="text-[var(--color-text-secondary)] truncate"
                  title={`${e.file}:${e.line}`}
                >
                  {e.file}:{e.line}
                </span>
              </div>
              <pre className="mt-1 rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 text-xs font-mono leading-relaxed whitespace-pre-wrap break-all">
                {e.snippet}
              </pre>
            </li>
          ))}
        </ul>
      )}

      {ruledOut && (ruledOut.reasoning || ruledOut.snippet) && (
        <div className="mt-3 border-l-2 border-[var(--color-status-ok-border)] pl-3">
          <h4 className="mb-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-status-ok)]">
            Mitigation found
          </h4>
          {ruledOut.reasoning && (
            <p className="text-sm leading-relaxed">{ruledOut.reasoning}</p>
          )}
          {ruledOut.snippet && (
            <pre className="mt-2 rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 text-xs font-mono whitespace-pre-wrap break-all">
              {ruledOut.snippet}
            </pre>
          )}
          {ruledOut.file && (
            <div className="mt-1 text-2xs text-[var(--color-text-secondary)]">
              {ruledOut.file}
              {ruledOut.line ? `:${ruledOut.line}` : ""}
            </div>
          )}
        </div>
      )}

      {hasMetadata && (
        <p className="mt-3 text-2xs text-[var(--color-text-secondary)] tabular-nums">
          {metadata?.model && (
            <>
              Model: <span className="font-mono">{metadata.model}</span>
            </>
          )}
          {(metadata?.tokens_in || metadata?.tokens_out) && (
            <>
              {metadata?.model ? " · " : ""}
              {(metadata?.tokens_in ?? 0).toLocaleString()} in /{" "}
              {(metadata?.tokens_out ?? 0).toLocaleString()} out
            </>
          )}
        </p>
      )}
    </section>
  );
}

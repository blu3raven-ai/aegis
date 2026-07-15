// Coverage indicator showing which scanner types are active for a source.
import { cn } from "@/lib/shared/utils";

export type ScannerType = "sca" | "sast" | "secrets" | "iac" | "agent" | "audit";

const LABELS: Record<ScannerType, string> = {
  sca: "SCA",
  sast: "SAST",
  secrets: "SEC",
  iac: "IaC",
  agent: "AGT",
  audit: "AUD",
};

const ORDER: ScannerType[] = ["sca", "sast", "secrets", "iac", "agent", "audit"];

type Props = {
  scanners: ScannerType[];
};

export function ScannerCoverage({ scanners }: Props) {
  const active = new Set(scanners);
  return (
    <div className="inline-flex items-center gap-1" role="group" aria-label="Scanner coverage">
      {ORDER.map((s) => {
        const on = active.has(s);
        return (
          <span
            key={s}
            className={cn(
              "inline-flex items-center justify-center rounded border px-1.5 py-0.5",
              "text-2xs font-semibold uppercase tracking-[0.06em] tabular-nums whitespace-nowrap leading-none",
              on
                ? "border-[var(--color-accent)]/30 bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                : "border-[var(--color-border)] bg-transparent text-[var(--color-text-secondary)] opacity-50",
            )}
            title={on ? `${LABELS[s]} enabled` : `${LABELS[s]} not enabled`}
          >
            {LABELS[s]}
          </span>
        );
      })}
    </div>
  );
}

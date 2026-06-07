import type { FindingRow } from "@/lib/client/repos-api"

type ScannerKey = "dependencies" | "code_scanning" | "container_scanning" | "secrets"

interface ScannerCoverageStripProps {
  covered: string[]
  activeFindings: FindingRow[]
}

interface ScannerSpec {
  key: ScannerKey
  label: string
  matchTools: string[]
  icon: React.ReactNode
}

function DependenciesIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9" />
    </svg>
  )
}

function CodeIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M17.25 6.75 22.5 12l-5.25 5.25M6.75 17.25 1.5 12l5.25-5.25M14.25 4.5l-4.5 15" />
    </svg>
  )
}

function ContainerIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="6" width="18" height="14" rx="2" />
      <path d="M3 14l4-3 4 3 4-3 6 5" />
      <circle cx="8.5" cy="10" r="1.5" />
    </svg>
  )
}

function SecretsIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" />
    </svg>
  )
}

const SCANNERS: ScannerSpec[] = [
  { key: "dependencies", label: "Dependencies", matchTools: ["grype", "syft", "trivy", "osv"], icon: <DependenciesIcon /> },
  { key: "code_scanning", label: "Code scanning", matchTools: ["semgrep", "joern", "codeql", "bandit"], icon: <CodeIcon /> },
  { key: "secrets", label: "Secrets", matchTools: ["gitleaks", "trufflehog"], icon: <SecretsIcon /> },
  { key: "container_scanning", label: "Container", matchTools: ["trivy", "grype", "syft"], icon: <ContainerIcon /> },
]

function findingCountFor(scanner: ScannerSpec, findings: FindingRow[]): number {
  if (scanner.key === "container_scanning") {
    return findings.filter((f) => f.tool.toLowerCase().includes("container")).length
  }
  const lowercased = scanner.matchTools
  return findings.filter((f) => {
    const tool = f.tool.toLowerCase()
    return lowercased.some((t) => tool === t || tool.startsWith(`${t}-`) || tool.endsWith(`-${t}`))
  }).length
}

export function ScannerCoverageStrip({ covered, activeFindings }: ScannerCoverageStripProps) {
  const coveredSet = new Set(covered)

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {SCANNERS.map((scanner) => {
        const isCovered = coveredSet.has(scanner.key)
        const count = isCovered ? findingCountFor(scanner, activeFindings) : 0
        const meta = isCovered
          ? `${count} finding${count === 1 ? "" : "s"}`
          : "Never scanned"
        const dotClass = isCovered
          ? "bg-[var(--color-state-fixed)]"
          : "bg-[var(--color-text-secondary)] opacity-60"
        return (
          <div
            key={scanner.key}
            className={`flex items-center gap-3 rounded-xl border px-4 py-3 ${
              isCovered
                ? "border-[var(--color-border)] bg-[var(--color-surface)]"
                : "border-[var(--color-border)] bg-[var(--color-surface-raised)] opacity-80"
            }`}
          >
            <div
              className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${
                isCovered
                  ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                  : "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]"
              }`}
            >
              <span className="h-5 w-5">{scanner.icon}</span>
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold text-[var(--color-text-primary)]">{scanner.label}</div>
              <div className="text-xs text-[var(--color-text-secondary)]">{meta}</div>
            </div>
            <span className={`h-2 w-2 shrink-0 rounded-full ${dotClass}`} aria-hidden="true" />
          </div>
        )
      })}
    </div>
  )
}

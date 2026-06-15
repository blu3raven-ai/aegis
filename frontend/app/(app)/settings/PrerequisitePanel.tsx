"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import {
  computeScannerPrereqItems,
  type ScannerPrerequisiteState,
  type PrerequisiteItem,
} from "@/lib/shared/prerequisite-utils"
import { Button } from "@/components/ui/Button"

export type { PrerequisiteItem }

interface Props {
  title: string
  description: string
  items: PrerequisiteItem[]
  onRefresh: () => void
  isRefreshing: boolean
  summary?: string
  installCommand?: string
  installLabel?: string
  copyState?: "idle" | "copied" | "failed"
  onCopyInstallCommand?: () => void
}

function CopyableCodeBlock({ command }: { command: string }) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function handleCopy() {
    navigator.clipboard.writeText(command)
    setCopied(true)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="flex items-center justify-between gap-3 rounded-md bg-[var(--color-bg)] px-3 py-2">
      <code className="text-[13px] font-mono text-[var(--color-text-secondary)] select-all">{command}</code>
      <Button variant="link" size="xs" onClick={handleCopy} className="shrink-0">
        {copied ? "Copied!" : "Copy"}
      </Button>
    </div>
  )
}

export function PrerequisitePanel({
  title,
  description,
  items,
  onRefresh,
  isRefreshing,
  summary,
  installCommand,
  installLabel = "Pull the scanner image to get started:",
  copyState = "idle",
  onCopyInstallCommand,
}: Props) {
  const allPass = items.length > 0 && items.every((i) => i.status === "pass")
  const anyFail = items.some((i) => i.status === "fail")

  return (
    <div
      className={`rounded-lg border p-4 space-y-3 ${
        allPass
          ? "border-[var(--color-state-fixed-border)] bg-[var(--color-state-fixed-subtle)]"
          : anyFail
          ? "border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)]"
          : "border-[var(--color-border)] bg-[var(--color-surface-raised)]"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-2xs font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            {title}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">{description}</p>
        </div>
        <Button variant="link" size="xs" onClick={onRefresh} disabled={isRefreshing} className="shrink-0">
          {isRefreshing ? "Checking…" : "Re-check"}
        </Button>
      </div>

      <ul className="space-y-2">
        {items.map((item) => (
          <li key={item.label} className="flex items-start gap-2.5">
            <span className="mt-0.5 shrink-0">
              {item.status === "loading" && <SpinnerIcon />}
              {item.status === "pass" && <CheckIcon />}
              {item.status === "fail" && <XIcon />}
            </span>
            <div>
              <span
                className={`text-sm font-medium ${
                  item.status === "pass"
                    ? "text-[var(--color-state-fixed)]"
                    : item.status === "fail"
                    ? "text-[var(--color-state-pending)]"
                    : "text-[var(--color-text-tertiary)]"
                }`}
              >
                {item.label}
              </span>
              {item.detail && (
                <p className="text-xs text-[var(--color-text-tertiary)] mt-0.5">{item.detail}</p>
              )}
              {item.status === "fail" && item.fix && (
                <div className="mt-3 space-y-2">
                  {item.fix.split("\n").filter(Boolean).map((line, i) => {
                    const colonIdx = line.indexOf(": ")
                    const label = colonIdx > -1 ? line.slice(0, colonIdx) : null
                    const cmd = colonIdx > -1 ? line.slice(colonIdx + 2) : line

                    return (
                      <div key={i}>
                        {label && (
                          <p className="text-[11px] text-[var(--color-text-tertiary)] mb-1">{label}</p>
                        )}
                        <CopyableCodeBlock command={cmd} />
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </li>
        ))}
      </ul>

      {installCommand && onCopyInstallCommand && (
        <div>
          <p className="text-xs text-[var(--color-state-pending)]">
            {installLabel}
          </p>
          <div className="mt-2 flex items-center justify-between gap-3 rounded bg-[var(--color-bg)] px-3 py-2 font-mono text-xs text-[var(--color-text-secondary)]">
            <span className="truncate">{installCommand}</span>
            <div className="relative shrink-0">
              <Button variant="link" size="xs" onClick={onCopyInstallCommand}>
                {copyState === "copied" ? "Copied" : "Copy"}
              </Button>
              {copyState !== "idle" && (
                <span
                  role="status"
                  aria-live="polite"
                  className="absolute -top-9 right-0 whitespace-nowrap rounded bg-[var(--color-bg)] px-2 py-1 text-[11px] font-medium text-[var(--color-text-primary)] shadow-lg ring-1 ring-[var(--color-border)]"
                >
                  {copyState === "copied" ? "Copied to clipboard" : "Copy failed"}
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {summary && (
        <p
          className={`border-t pt-2 text-xs ${
            allPass
              ? "border-[var(--color-state-fixed-border)] text-[var(--color-state-fixed)]"
              : anyFail
              ? "border-[var(--color-state-pending-border)] text-[var(--color-state-pending)]"
              : "border-[var(--color-border)] text-[var(--color-text-tertiary)]"
          }`}
        >
          {summary}
        </p>
      )}
    </div>
  )
}

// ─── Icons ────────────────────────────────────────────────────────────────────

function CheckIcon() {
  return (
    <svg
      className="w-4 h-4 text-[var(--color-state-fixed)]"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2.5}
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
    </svg>
  )
}

function XIcon() {
  return (
    <svg
      className="w-4 h-4 text-[var(--color-state-pending)]"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"
      />
    </svg>
  )
}

function SpinnerIcon() {
  return (
    <svg className="w-4 h-4 text-[var(--color-text-tertiary)] animate-spin" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
      />
    </svg>
  )
}

// ─── Hooks ────────────────────────────────────────────────────────────────────

const POLL_INTERVAL_FAST_MS = 10_000  // poll every 10s while waiting for prerequisites
const POLL_INTERVAL_SLOW_MS = 30_000  // poll every 30s after prerequisites pass (detect deletions)

function useScannerPrerequisites(
  tool: "dependencies" | "codeScanning" | "container-scanning" | "secrets",
  label: string,
) {
  const loadingState: ScannerPrerequisiteState = {
    items: [{ label: `Checking ${label}…`, status: "loading" }],
    canEnable: false,
  }

  const [state, setState] = useState<ScannerPrerequisiteState>(loadingState)
  const [isRefreshing, setIsRefreshing] = useState(false)

  const check = useCallback(async () => {
    setIsRefreshing(true)
    try {
      const { checkScannerPrerequisites } = await import("@/lib/client/settings-api")
      const result = await checkScannerPrerequisites(tool)
      if (!result.ok) {
        setState({
          items: [{ label: "Scanner", status: "fail", detail: result.error }],
          canEnable: false,
        })
        return
      }
      setState(
        computeScannerPrereqItems(result),
      )
    } finally {
      setIsRefreshing(false)
    }
  }, [tool])

  // Check on mount
  useEffect(() => {
    void check()
  }, [check])

  // Auto-poll: fast while waiting, slow after ready (detects image deletion)
  useEffect(() => {
    const interval = state.canEnable ? POLL_INTERVAL_SLOW_MS : POLL_INTERVAL_FAST_MS
    const timer = setInterval(() => { void check() }, interval)
    return () => clearInterval(timer)
  }, [check, state.canEnable])

  const passingCount = state.items.filter((i) => i.status === "pass").length
  const totalCount = state.items.filter((i) => i.status !== "loading").length

  return { ...state, isRefreshing, refresh: check, passingCount, totalCount }
}

// Named exports for each scanner — backward compatible
export function useDependenciesPrerequisites() {
  return useScannerPrerequisites("dependencies", "Dependencies Scanner")
}

export function useCodeScanningPrerequisites() {
  return useScannerPrerequisites("codeScanning", "Code Scanning Scanner")
}

export function useContainerScanningPrerequisites() {
  return useScannerPrerequisites("container-scanning", "Container Scanner")
}

export function useSecretsPrerequisites() {
  return useScannerPrerequisites("secrets", "Secret Scanner")
}

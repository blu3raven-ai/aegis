"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import {
  computeScannerPrereqItems,
  type ScannerPrerequisiteState,
  type PrerequisiteItem,
} from "@/lib/shared/prerequisite-utils"

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
    <div className="flex items-center justify-between gap-3 rounded-md bg-gray-900/80 px-3 py-2">
      <code className="text-[13px] font-mono text-gray-300 select-all">{command}</code>
      <button
        type="button"
        onClick={handleCopy}
        className="shrink-0 text-[11px] text-gray-500 transition-colors hover:text-gray-300"
      >
        {copied ? "Copied!" : "Copy"}
      </button>
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
          ? "border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/20"
          : anyFail
          ? "border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20"
          : "border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/40"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">
            {title}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">{description}</p>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="shrink-0 text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 disabled:opacity-40"
        >
          {isRefreshing ? "Checking…" : "Re-check"}
        </button>
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
                    ? "text-emerald-700 dark:text-emerald-400"
                    : item.status === "fail"
                    ? "text-amber-700 dark:text-amber-400"
                    : "text-gray-500 dark:text-gray-400"
                }`}
              >
                {item.label}
              </span>
              {item.detail && (
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{item.detail}</p>
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
          <p className="text-xs text-amber-700 dark:text-amber-400">
            {installLabel}
          </p>
          <div className="mt-2 flex items-center justify-between gap-3 rounded bg-gray-900 px-3 py-2 font-mono text-xs text-gray-300">
            <span className="truncate">{installCommand}</span>
            <div className="relative shrink-0">
              <button
                type="button"
                onClick={onCopyInstallCommand}
                className="text-gray-400 transition-colors hover:text-white"
              >
                {copyState === "copied" ? "Copied" : "Copy"}
              </button>
              {copyState !== "idle" && (
                <span
                  role="status"
                  aria-live="polite"
                  className="absolute -top-9 right-0 whitespace-nowrap rounded bg-gray-950 px-2 py-1 text-[11px] font-medium text-white shadow-lg ring-1 ring-white/10"
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
              ? "border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400"
              : anyFail
              ? "border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400"
              : "border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400"
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
      className="w-4 h-4 text-emerald-600 dark:text-emerald-400"
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
      className="w-4 h-4 text-amber-600 dark:text-amber-400"
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
    <svg className="w-4 h-4 text-gray-400 animate-spin" fill="none" viewBox="0 0 24 24">
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
    imageName: null,
    registryImage: null,
    signature: null,
    digest: null,
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
          items: [{ label: "Scanner image", status: "fail", detail: result.error }],
          canEnable: false,
          imageName: null,
          registryImage: null,
          signature: null,
          digest: null,
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

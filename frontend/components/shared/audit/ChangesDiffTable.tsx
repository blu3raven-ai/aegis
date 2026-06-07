"use client"

import { useState } from "react"

function flattenObject(
  obj: Record<string, unknown>,
  prefix = "",
  out: Map<string, string> = new Map(),
): Map<string, string> {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      flattenObject(v as Record<string, unknown>, key, out)
    } else {
      out.set(key, v === null ? "null" : v === undefined ? "undefined" : JSON.stringify(v))
    }
  }
  return out
}

interface ChangesDiffTableProps {
  changes: Record<string, unknown>
}

export function ChangesDiffTable({ changes }: ChangesDiffTableProps) {
  const [collapsed, setCollapsed] = useState(false)

  const hasBefore = "before" in changes
  const hasAfter = "after" in changes

  if (!hasBefore && !hasAfter) {
    return (
      <pre className="rounded-lg bg-[var(--color-bg-section)] p-3 text-[11px] font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)] overflow-x-auto whitespace-pre-wrap break-all">
        {JSON.stringify(changes, null, 2)}
      </pre>
    )
  }

  const before = hasBefore && changes.before != null
    ? flattenObject(changes.before as Record<string, unknown>)
    : new Map<string, string>()
  const after = hasAfter && changes.after != null
    ? flattenObject(changes.after as Record<string, unknown>)
    : new Map<string, string>()

  const allKeys = new Set([...before.keys(), ...after.keys()])
  const rows = [...allKeys].map((key) => ({
    key,
    before: before.get(key) ?? null,
    after: after.get(key) ?? null,
    changed: before.get(key) !== after.get(key),
  }))
  const changedCount = rows.filter((r) => r.changed).length

  return (
    <div>
      <button
        type="button"
        className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
        onClick={() => setCollapsed((c) => !c)}
      >
        <svg className={`h-3 w-3 transition-transform ${collapsed ? "" : "rotate-90"}`} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 0 1 .02-1.06L11.168 10 7.23 6.29a.75.75 0 1 1 1.04-1.08l4.5 4.25a.75.75 0 0 1 0 1.08l-4.5 4.25a.75.75 0 0 1-1.06-.02Z" clipRule="evenodd" />
        </svg>
        Changes ({changedCount} field{changedCount !== 1 ? "s" : ""})
      </button>

      {!collapsed && (
        <div className="overflow-hidden rounded-lg border border-[var(--color-border)]">
          <div className="grid grid-cols-2 border-b border-[var(--color-border)] bg-[var(--color-bg-section)]">
            <div className="px-3 py-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)] border-r border-[var(--color-border)]">Before</div>
            <div className="px-3 py-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">After</div>
          </div>
          {rows.map((row) => (
            <div
              key={row.key}
              className={`grid grid-cols-2 border-b border-[var(--color-border-divider)] last:border-0 ${row.changed ? "bg-[var(--color-bg-section)]" : ""}`}
            >
              <div className="px-3 py-2 border-r border-[var(--color-border-divider)]">
                <div className="text-2xs text-[var(--color-text-tertiary)] mb-0.5">{row.key}</div>
                <div className={`text-xs font-[family-name:var(--font-jetbrains-mono)] break-all ${row.changed ? "text-[var(--color-severity-critical)]" : "text-[var(--color-text-secondary)]"}`}>
                  {row.before ?? <span className="italic text-[var(--color-text-tertiary)]">—</span>}
                </div>
              </div>
              <div className="px-3 py-2">
                <div className="text-2xs text-[var(--color-text-tertiary)] mb-0.5">{row.key}</div>
                <div className={`text-xs font-[family-name:var(--font-jetbrains-mono)] break-all ${row.changed ? "text-[var(--color-status-ok)]" : "text-[var(--color-text-secondary)]"}`}>
                  {row.after ?? <span className="italic text-[var(--color-text-tertiary)]">—</span>}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

"use client"

import { useState } from "react"
import type { ApiKey } from "@/lib/client/api-keys-api"
import { ScopesBadgeList } from "./ScopesBadgeList"

function relativeTime(iso: string | null): string {
  if (!iso) return "—"
  const diff = Date.now() - new Date(iso).getTime()
  const minutes = Math.floor(diff / 60000)
  if (minutes < 1) return "just now"
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

function expiryLabel(key: ApiKey): string {
  if (key.revoked_at) return "Revoked"
  if (!key.expires_at) return "Never"
  const diff = new Date(key.expires_at).getTime() - Date.now()
  if (diff < 0) return "Expired"
  const days = Math.ceil(diff / 86400000)
  return `${days}d`
}

function StatusBadge({ apiKey }: { apiKey: ApiKey }) {
  if (apiKey.revoked_at) {
    return (
      <span className="rounded-full px-2 py-0.5 text-2xs font-medium bg-[var(--color-red-subtle)] text-[var(--color-red)]">
        Revoked
      </span>
    )
  }
  if (apiKey.expires_at && new Date(apiKey.expires_at) < new Date()) {
    return (
      <span className="rounded-full px-2 py-0.5 text-2xs font-medium bg-[var(--color-yellow-subtle)] text-[var(--color-yellow)]">
        Expired
      </span>
    )
  }
  return (
    <span className="rounded-full px-2 py-0.5 text-2xs font-medium bg-[var(--color-green-subtle)] text-[var(--color-green)]">
      Active
    </span>
  )
}

function SkeletonRow() {
  return (
    <tr className="border-b border-[var(--color-border)]">
      {[1, 2, 3, 4, 5].map((i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-3 rounded bg-[var(--color-surface-raised)] animate-pulse" />
        </td>
      ))}
    </tr>
  )
}

interface ApiKeysTableProps {
  keys: ApiKey[] | null
  onRevoke: (key: ApiKey) => void
}

export function ApiKeysTable({ keys, onRevoke }: ApiKeysTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-[var(--color-border)]">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)]">
            <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              Name
            </th>
            <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              Token
            </th>
            <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              Scopes
            </th>
            <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              Expires
            </th>
            <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              Status
            </th>
            <th className="px-4 py-2.5" />
          </tr>
        </thead>
        <tbody>
          {keys === null ? (
            <>
              <SkeletonRow />
              <SkeletonRow />
              <SkeletonRow />
            </>
          ) : keys.length === 0 ? (
            <tr>
              <td colSpan={6} className="px-4 py-8 text-center text-sm text-[var(--color-text-secondary)]">
                No API keys found.
              </td>
            </tr>
          ) : (
            keys.map((key) => (
              <tr key={key.id} className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-surface-raised)] transition-colors">
                <td className="px-4 py-3 font-medium text-[var(--color-text-primary)]">
                  {key.name}
                </td>
                <td className="px-4 py-3 font-mono text-[11px] text-[var(--color-text-secondary)]">
                  {key.prefix}••••{key.last_four}
                </td>
                <td className="px-4 py-3">
                  <ScopesBadgeList scopes={key.scopes} />
                </td>
                <td className="px-4 py-3 text-xs text-[var(--color-text-secondary)]">
                  {expiryLabel(key)}
                </td>
                <td className="px-4 py-3">
                  <StatusBadge apiKey={key} />
                </td>
                <td className="px-4 py-3 text-right">
                  {!key.revoked_at && (
                    <button
                      onClick={() => onRevoke(key)}
                      className="text-xs text-[var(--color-red)] hover:underline"
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

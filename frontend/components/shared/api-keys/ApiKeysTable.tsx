"use client"

import type { ApiKey } from "@/lib/client/api-keys-api"
import { ScopesBadgeList } from "./ScopesBadgeList"
import { Button } from "@/components/ui/Button"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

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
    <Tr className="border-b border-[var(--color-border)]">
      {[1, 2, 3, 4, 5].map((i) => (
        <Td key={i}>
          <Skeleton className="h-3" />
        </Td>
      ))}
    </Tr>
  )
}

interface ApiKeysTableProps {
  keys: ApiKey[] | null
  onRevoke: (key: ApiKey) => void
}

export function ApiKeysTable({ keys, onRevoke }: ApiKeysTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-[var(--color-border)]">
      <Table>
        <Thead>
          <Tr>
            <Th className="py-2.5">Name</Th>
            <Th className="py-2.5">Token</Th>
            <Th className="py-2.5">Scopes</Th>
            <Th className="py-2.5">Expires</Th>
            <Th className="py-2.5">Status</Th>
            <Th className="py-2.5" />
          </Tr>
        </Thead>
        <Tbody divided={false}>
          {keys === null ? (
            <>
              <SkeletonRow />
              <SkeletonRow />
              <SkeletonRow />
            </>
          ) : keys.length === 0 ? (
            <Tr>
              <Td colSpan={6} className="py-8 text-center text-sm text-[var(--color-text-secondary)]">
                No API tokens found.
              </Td>
            </Tr>
          ) : (
            keys.map((key) => (
              <Tr key={key.id} interactive className="border-b border-[var(--color-border)] last:border-0">
                <Td className="font-medium text-[var(--color-text-primary)]">
                  {key.name}
                </Td>
                <Td className="font-mono text-[11px] text-[var(--color-text-secondary)]">
                  {key.prefix}••••{key.last_four}
                </Td>
                <Td>
                  <ScopesBadgeList scopes={key.scopes} />
                </Td>
                <Td className="text-xs text-[var(--color-text-secondary)]">
                  {expiryLabel(key)}
                </Td>
                <Td>
                  <StatusBadge apiKey={key} />
                </Td>
                <Td className="text-right">
                  {!key.revoked_at && (
                    <Button
                      variant="link"
                      size="xs"
                      onClick={() => onRevoke(key)}
                      className="text-[var(--color-red)] hover:underline hover:text-[var(--color-red)]"
                    >
                      Revoke
                    </Button>
                  )}
                </Td>
              </Tr>
            ))
          )}
        </Tbody>
      </Table>
    </div>
  )
}

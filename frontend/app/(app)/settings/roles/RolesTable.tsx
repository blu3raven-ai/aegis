"use client"

import { RoleRecord } from "@/lib/client/settings-api"
import { Card } from "@/components/ui/Card"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { formatDate } from "@/lib/shared/utils"

interface RolesTableProps {
  roles: RoleRecord[]
  onSelectRole: (role: RoleRecord) => void
  onDuplicateRole: (role: RoleRecord) => void
  onDeleteRole: (roleId: string) => void
}

const EDIT_ICON =
  "M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10"

const COPY_ICON =
  "M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 01-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 00-3.375-3.375h-1.5a1.125 1.125 0 01-1.125-1.125v-1.5a3.375 3.375 0 00-3.375-3.375H9.75"

const TRASH_ICON =
  "M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673A2.25 2.25 0 0 1 15.916 21.75H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0"

export function RolesTable({ roles, onSelectRole, onDuplicateRole, onDeleteRole }: RolesTableProps) {
  const formatPermissions = (permissions: string[]) => {
    if (permissions.length === 0) return "No permissions"
    const visible = permissions.slice(0, 6).map(p => p.replace(/_/g, ' '))
    const joined = visible.join(", ")
    return permissions.length > 6 ? `${joined}, ...` : joined
  }

  return (
    <Card padding="none" className="overflow-hidden">
      <div className="overflow-x-auto">
        <Table>
          <Thead>
            <Tr>
              <Th className="px-6 w-[15%]">Name</Th>
              <Th className="px-6 w-[45%]">Permissions</Th>
              <Th className="px-6 w-[15%]">Type</Th>
              <Th className="px-6 w-[15%]">Created</Th>
              <Th className="px-6 text-right w-[10%]">Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {roles.map((role) => (
              <Tr
                key={role.id}
                onClick={() => onSelectRole(role)}
                interactive
                className="cursor-pointer group"
              >
                <Td className="px-6 py-4 font-medium text-[var(--color-text-primary)] whitespace-nowrap">
                  {role.name}
                </Td>
                <Td className="px-6 py-4 text-[var(--color-text-secondary)]">
                  <div className="text-xs capitalize" title={role.permissions.join(", ")}>
                    {formatPermissions(role.permissions)}
                  </div>
                </Td>
                <Td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex gap-2">
                    {role.isSystem ? (
                      <span className="inline-flex items-center rounded-full bg-[var(--color-accent-subtle)] px-2 py-0.5 text-2xs font-semibold text-[var(--color-accent)] border border-[var(--color-accent-border)] uppercase tracking-tight">
                        System
                      </span>
                    ) : (
                      <span className="inline-flex items-center rounded-full bg-[var(--color-state-fixed-subtle)] px-2 py-0.5 text-2xs font-semibold text-[var(--color-state-fixed-text)] border border-[var(--color-state-fixed-border)] uppercase tracking-tight">
                        Custom
                      </span>
                    )}
                  </div>
                </Td>
                <Td className="px-6 py-4 text-[var(--color-text-secondary)] whitespace-nowrap text-[11px]">
                  {formatDate(role.createdAt)}
                </Td>
                <Td className="px-6 py-4 text-right whitespace-nowrap">
                  <div className="flex items-center justify-end gap-1">
                    {/* Copy button: greyed out if locked */}
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        onDuplicateRole(role)
                      }}
                      disabled={role.isLocked || role.id === "role_owner"}
                      className="p-1.5 text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] rounded-md transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                      title={role.isLocked || role.id === "role_owner" ? "This role is protected and cannot be duplicated" : "Duplicate role"}
                      aria-label="Duplicate role"
                    >
                      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={COPY_ICON} />
                      </svg>
                    </button>

                    {/* Delete button: greyed out if locked */}
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        onDeleteRole(role.id)
                      }}
                      disabled={role.isLocked || role.id === "role_owner"}
                      className="p-1.5 text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)] rounded-md transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                      title={role.isLocked || role.id === "role_owner" ? "This role is protected and cannot be deleted" : "Delete role"}
                      aria-label="Delete role"
                    >
                      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={TRASH_ICON} />
                      </svg>
                    </button>
                  </div>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </div>
    </Card>
  )
}

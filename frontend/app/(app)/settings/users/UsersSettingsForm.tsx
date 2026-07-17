"use client"

import { useEffect, useState, Fragment, useTransition, type MutableRefObject } from "react"
import { ROLE_LABELS, type UserRole } from "@/lib/shared/auth/roles.ts"
import { fetchCurrentUser } from "@/lib/client/auth"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"
import {
  addOrganisationTeamMember,
  listOrganisationTeams,
  listUserDirectory,
  removeOrganisationTeamMember,
  listDirectGrants,
  addDirectGrant,
  removeDirectGrant,
  searchOrganisationRepositories,
  searchOrganisationContainerImages,
  listRoles,
  type OrganisationTeam,
  type UserDirectoryEntry,
  type Grant,
  type RoleRecord,
} from "@/lib/client/settings-api"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Sheet } from "@/components/ui/Sheet"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { Dialog } from "@/components/layout/Dialog"
import { ResourceAutocomplete } from "../organisations/ResourceAutocomplete"

interface UserEntry extends UserDirectoryEntry {
  createdAt: string
  manualDirectGrantCount: number
  githubDirectGrantCount: number
  roleId?: string | null
}

const TRASH_ICON =
  "M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673A2.25 2.25 0 0 1 15.916 21.75H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0"


function extractErrorMessage(payload: unknown, fallback: string) {
  if (!payload || typeof payload !== "object") return fallback

  const data = payload as { error?: unknown; detail?: unknown }
  if (typeof data.error === "string" && data.error.trim()) return data.error
  if (typeof data.detail === "string" && data.detail.trim()) return data.detail
  if (Array.isArray(data.detail) && data.detail.length > 0) {
    const first = data.detail[0] as unknown
    if (typeof first === "string" && first.trim()) return first
    if (first && typeof first === "object") {
      const detail = first as { msg?: unknown; message?: unknown }
      if (typeof detail.msg === "string" && detail.msg.trim()) return detail.msg
      if (typeof detail.message === "string" && detail.message.trim()) return detail.message
    }
  }
  return fallback
}

interface UsersSettingsFormProps {
  canEdit?: boolean
  /**
   * When provided, the form skips rendering its own "Invite User" button row
   * and instead publishes the open-invite handler to this ref. The parent
   * section then mounts the button in SettingsSection's headerExtra slot so
   * the action sits next to the section title instead of in a separate row.
   */
  inviteTriggerRef?: MutableRefObject<(() => void) | null>
}

export function UsersSettingsForm({ canEdit = true, inviteTriggerRef }: UsersSettingsFormProps) {
  const [users, setUsers] = useState<UserEntry[]>([])
  const [roles, setRoles] = useState<RoleRecord[]>([])
  const [teams, setTeams] = useState<OrganisationTeam[]>([])
  const [directGrants, setDirectGrants] = useState<Grant[]>([])
  const [expandedUserId, setExpandedUserId] = useState<string | null>(null)
  const [expandedDirectAccessUserId, setExpandedDirectAccessUserId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [dialogError, setDialogError] = useState<string | null>(null)
  const [currentUserId, setCurrentUserId] = useState<string | null | undefined>(undefined)
  const [currentUserRole, setCurrentUserRole] = useState<UserRole | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  // Publish the open-invite handler upstream so the parent SettingsSection
  // can render the action next to the section title.
  useEffect(() => {
    if (!inviteTriggerRef) return
    inviteTriggerRef.current = () => setShowAdd(true)
    return () => {
      inviteTriggerRef.current = null
    }
  }, [inviteTriggerRef])
  const [showResetPassword, setShowResetPassword] = useState<UserEntry | null>(null)
  const [resetPasswordValue, setResetPasswordValue] = useState("")

  const [newUsername, setNewUsername] = useState("")
  const [newEmail, setNewEmail] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [newRole, setNewRole] = useState<UserRole>("viewer")
  const [newRoleId, setNewRoleId] = useState<string>("")
  const [submitting, setSubmitting] = useState(false)
  const [mutatingUserId, setMutatingUserId] = useState<string | null>(null)
  const [directRepoValue, setDirectRepoValue] = useState("")
  const [directRepoSuggestions, setDirectRepoSuggestions] = useState<string[]>([])
  const [directRepoError, setDirectRepoError] = useState<string | null>(null)
  const [directImageValue, setDirectImageValue] = useState("")
  const [directImageSuggestions, setDirectImageSuggestions] = useState<string[]>([])
  const [directImageError, setDirectImageError] = useState<string | null>(null)

  // Dialog state
  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean
    title: string
    description: string
    onConfirm: () => void
    variant?: "danger" | "info"
    confirmLabel?: string
  }>({
    open: false,
    title: "",
    description: "",
    onConfirm: () => {},
  })

  async function loadData() {
    setLoading(true)
    try {
      const [usersResult, rolesRes, teamsRes, grantsRes] = await Promise.all([
        apiClient<{ users?: any[] }>("/api/v1/workspace/users").then(
          (data) => ({ ok: true as const, data, status: 200 }),
          (err) => ({ ok: false as const, data: null, status: err instanceof ApiClientError ? err.status : 0, body: err instanceof ApiClientError ? err.body : null }),
        ),
        listRoles(),
        listOrganisationTeams(),
        listDirectGrants(),
      ])

      if (rolesRes.ok) {
        setRoles(rolesRes.roles)
        const viewerRole = rolesRes.roles.find(r => r.slug === "viewer")
        if (viewerRole) setNewRoleId(viewerRole.id)
      }

      if (!usersResult.ok) {
        if (usersResult.status === 403) {
          const dirResult = await listUserDirectory()
          if (dirResult.ok) {
            const enriched = dirResult.users.map(u => ({
              ...u,
              createdAt: new Date().toISOString(),
              manualDirectGrantCount: 0,
              githubDirectGrantCount: 0,
            }))
            setUsers(enriched)
          }
        } else {
          throw new Error(extractErrorMessage(usersResult.body, "Failed to load users"))
        }
      } else {
        const rawUsers = Array.isArray(usersResult.data?.users) ? usersResult.data.users : []
        const currentGrants = grantsRes.ok ? grantsRes.grants : []

        const enriched = rawUsers.map(u => ({
          ...u,
          manualDirectGrantCount: currentGrants.filter(g => g.subjectId === u.id && g.source === "manual").length,
          githubDirectGrantCount: currentGrants.filter(g => g.subjectId === u.id && g.source === "github").length,
        }))
        setUsers(enriched)
      }

      if (teamsRes.ok) setTeams(teamsRes.teams)
      if (grantsRes.ok) setDirectGrants(grantsRes.grants)

    } catch (err) {
      setError(err instanceof Error ? err.message : "Load failed")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadData()
  }, [])

  useEffect(() => {
    let active = true
    void fetchCurrentUser().then((user) => {
      if (!active) return
      setCurrentUserId(user?.id ?? null)
      setCurrentUserRole(user?.role ?? null)
    })
    return () => {
      active = false
    }
  }, [])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setDialogError(null)
    try {
      await apiClient("/api/v1/workspace/users", {
        method: "POST",
        body: {
          username: newUsername,
          email: newEmail,
          password: newPassword,
          role: newRole,
          roleId: newRoleId || undefined,
        },
      })
      setNewUsername("")
      setNewEmail("")
      setNewPassword("")
      setShowAdd(false)
      setDialogError(null)
      await loadData()
    } catch (err) {
      if (err instanceof ApiClientError) {
        setDialogError(extractErrorMessage(err.body, "Create failed"))
      } else {
        setDialogError(err instanceof Error ? err.message : "Create failed")
      }
    } finally {
      setSubmitting(false)
    }
  }

  async function handleToggleStatus(user: UserEntry) {
    if (currentUserId === undefined) return

    const performToggle = async () => {
      setConfirmDialog({ ...confirmDialog, open: false })
      setMutatingUserId(user.id)
      setError(null)
      try {
        const endpoint = user.status === "active" ? "disable" : "enable"
        try {
          await apiClient(`/api/v1/workspace/users/${user.id}/${endpoint}`, { method: "POST" })
        } catch (err) {
          const fallback = endpoint === "disable" ? "Disable failed" : "Enable failed"
          if (err instanceof ApiClientError) {
            throw new Error(extractErrorMessage(err.body, fallback))
          }
          throw err
        }
        await loadData()
      } catch (err) {
        setError(err instanceof Error ? err.message : "Update failed")
      } finally {
        setMutatingUserId(null)
      }
    }

    if (user.status === "active" || user.status === "pending") {
      if (user.id === currentUserId) return
      const isPending = user.status === "pending"
      setConfirmDialog({
        open: true,
        title: isPending ? "Activate User" : "Disable User",
        description: isPending 
          ? `Are you sure you want to activate ${user.username}? They will be able to access the dashboard.` 
          : `Are you sure you want to disable ${user.username}? They will no longer be able to log in.`,
        onConfirm: performToggle,
        variant: isPending ? "info" : "danger",
        confirmLabel: isPending ? "Activate" : "Disable User",
      })
    } else {
      await performToggle()
    }
  }

  async function handleRoleChange(user: UserEntry, roleId: string) {
    if (currentUserId === undefined) return
    if (user.id === currentUserId) return
    
    const roleRecord = roles.find(r => r.id === roleId)
    if (!roleRecord) return
    if (user.roleId === roleId) return

    const performRoleChange = async () => {
      setConfirmDialog({ ...confirmDialog, open: false })
      setMutatingUserId(user.id)
      setError(null)
      try {
        try {
          await apiClient(`/api/v1/workspace/users/${user.id}/role`, {
            method: "PATCH",
            body: { roleId },
          })
        } catch (err) {
          if (err instanceof ApiClientError) {
            throw new Error(extractErrorMessage(err.body, "Role update failed"))
          }
          throw err
        }
        await loadData()
      } catch (err) {
        setError(err instanceof Error ? err.message : "Role update failed")
      } finally {
        setMutatingUserId(null)
      }
    }

    const isOwnerTarget = user.role === "owner" || roleRecord.slug === "owner"
    if (isOwnerTarget) {
      setConfirmDialog({
        open: true,
        title: roleRecord.slug === "owner" ? "Promote to Owner" : "Remove Owner Role",
        description: roleRecord.slug === "owner"
          ? `Are you sure you want to promote ${user.username} to Owner? Owners have full administrative access to the workspace.`
          : `Are you sure you want to change ${user.username} from Owner?`,
        onConfirm: performRoleChange,
        variant: "info",
        confirmLabel: "Confirm Change",
      })
    } else {
      await performRoleChange()
    }
  }

  async function handleResetPassword(e: React.FormEvent) {
    e.preventDefault()
    if (!showResetPassword) return
    setSubmitting(true)
    setDialogError(null)
    try {
      await apiClient(`/api/v1/workspace/users/${showResetPassword.id}/reset-password`, {
        method: "POST",
        body: { password: resetPasswordValue },
      })
      setShowResetPassword(null)
      setResetPasswordValue("")
      setDialogError(null)
    } catch (err) {
      if (err instanceof ApiClientError) {
        setDialogError(extractErrorMessage(err.body, "Reset failed"))
      } else {
        setDialogError(err instanceof Error ? err.message : "Reset failed")
      }
    } finally {
      setSubmitting(false)
    }
  }

  async function handleDeleteUser(user: UserEntry) {
    if (currentUserId === undefined) return
    if (user.id === currentUserId) {
      setError("You cannot delete your own account.")
      return
    }
    if (currentUserRole !== "owner" && user.role === "owner") return

    setConfirmDialog({
      open: true,
      title: "Delete User",
      description: `Are you sure you want to permanently delete ${user.username}? This action cannot be undone and will remove all their data.`,
      onConfirm: async () => {
        setConfirmDialog({ ...confirmDialog, open: false })
        setMutatingUserId(user.id)
        setError(null)
        try {
          try {
            await apiClient(`/api/v1/workspace/users/${user.id}`, { method: "DELETE" })
          } catch (err) {
            if (err instanceof ApiClientError) {
              throw new Error(extractErrorMessage(err.body, "Delete failed"))
            }
            throw err
          }
          await loadData()
        } catch (err) {
          setError(err instanceof Error ? err.message : "Delete failed")
        } finally {
          setMutatingUserId(null)
        }
      },
      variant: "danger",
      confirmLabel: "Delete User",
    })
  }

  async function handleAddTeamMember(teamId: string, userId: string) {
    setError(null)
    const result = await addOrganisationTeamMember(teamId, { userId })
    if (result.ok) {
      setTeams(prev => prev.map(t => t.id === teamId ? result.team : t))
    } else {
      setError(result.error)
    }
  }

  async function handleRemoveTeamMember(teamId: string, userId: string) {
    setError(null)
    const result = await removeOrganisationTeamMember(teamId, userId)
    if (result.ok) {
      setTeams(prev => prev.map(t => t.id === teamId ? result.team : t))
    } else {
      setError(result.error)
    }
  }

  async function updateDirectRepoValue(next: string) {
    setDirectRepoValue(next)
    try {
      const result = await searchOrganisationRepositories(null, next)
      setDirectRepoSuggestions(result.repositories.map((repo) => repo.fullName))
      setDirectRepoError(result.error ?? null)
    } catch {
      setDirectRepoSuggestions([])
      setDirectRepoError("Could not load repository suggestions. You can still enter org/repo manually.")
    }
  }

  async function updateDirectImageValue(next: string) {
    setDirectImageValue(next)
    try {
      const result = await searchOrganisationContainerImages(null, next)
      setDirectImageSuggestions(result.images.map((image) => image.image))
      setDirectImageError(result.error ?? null)
    } catch {
      setDirectImageSuggestions([])
      setDirectImageError("Could not load image suggestions. You can still enter the image path manually.")
    }
  }

  async function _refreshDirectGrants() {
    const grantsRes = await listDirectGrants()
    if (grantsRes.ok) {
      setDirectGrants(grantsRes.grants)
      const enriched = users.map(u => ({
        ...u,
        manualDirectGrantCount: grantsRes.grants.filter(g => g.subjectId === u.id && g.source === "manual").length,
        githubDirectGrantCount: grantsRes.grants.filter(g => g.subjectId === u.id && g.source === "github").length,
      }))
      setUsers(enriched)
    }
  }

  async function handleAddDirectGrant(userId: string, type: "repository" | "containerImage", key: string) {
    setError(null)
    const trimmed = key.trim()
    if (!trimmed) return
    // Upsert the asset, then create the grant
    let assetId: string
    try {
      const assetPayload =
        type === "repository"
          ? (() => {
              const slash = trimmed.indexOf("/")
              const owner = trimmed.slice(0, slash)
              const name = trimmed.slice(slash + 1)
              return { type: "repo", source_type: "github", owner, name }
            })()
          : (() => {
              const parts = trimmed.split("/")
              const [registry, ...rest] = parts
              return { type: "image", registry, image: rest.join("/"), tag: "" }
            })()
      const created = await apiClient<{ asset_id: string }>("/api/v1/sources/manual", {
        method: "POST",
        body: assetPayload,
      })
      assetId = created.asset_id
    } catch {
      setError("Could not create asset. Please try again.")
      return
    }
    const result = await addDirectGrant(userId, assetId)
    if (result.ok) {
      if (type === "repository") {
        setDirectRepoValue("")
        setDirectRepoSuggestions([])
        setDirectRepoError(null)
      } else {
        setDirectImageValue("")
        setDirectImageSuggestions([])
        setDirectImageError(null)
      }
      await _refreshDirectGrants()
    } else {
      setError(result.error)
    }
  }

  async function handleRemoveDirectGrant(userId: string, assetId: string) {
    setError(null)
    const result = await removeDirectGrant(userId, assetId)
    if (result.ok) {
      await _refreshDirectGrants()
    } else {
      setError(result.error)
    }
  }

  if (loading && users.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-accent)] border-t-transparent" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-lg border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2.5 text-sm text-[var(--color-severity-critical-text)]">
          {error}
        </div>
      )}

      {/* Title + subtitle come from the parent <SettingsSection>. When the
          parent supplies an inviteTriggerRef the action lives in the section
          header, so we skip the in-form button row entirely. */}
      {canEdit && !inviteTriggerRef && (
        <div className="flex items-start justify-end gap-4">
          <Button
            variant="primary"
            size="md"
            onClick={() => setShowAdd(true)}
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <line x1="19" y1="8" x2="19" y2="14" />
                <line x1="22" y1="11" x2="16" y2="11" />
              </svg>
            }
          >
            Invite User
          </Button>
        </div>
      )}

      <Sheet
        open={showAdd}
        onClose={() => { setShowAdd(false); setDialogError(null) }}
        title="Invite a member"
        description="Create an account with a starter password. Members can reset it later from account settings."
        size="md"
        dismissGuard={{
          isDirty: newUsername.trim() !== "" || newEmail.trim() !== "" || newPassword !== "",
        }}
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="md" onClick={() => setShowAdd(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="invite-member-form"
              variant="primary"
              size="md"
              disabled={submitting}
              isLoading={submitting}
            >
              {submitting ? "Creating…" : "Invite member"}
            </Button>
          </div>
        }
      >
        <form id="invite-member-form" onSubmit={handleCreate} className="space-y-4">
          {dialogError && (
            <div
              role="alert"
              className="rounded-lg border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2.5 text-sm text-[var(--color-severity-critical-text)]"
            >
              {dialogError}
            </div>
          )}
          <div className="space-y-4">
            <FormField label="Username" htmlFor="invite-username" required>
              <Input
                id="invite-username"
                type="text"
                required
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="Enter username"
              />
            </FormField>
            <FormField label="Email address" htmlFor="invite-email" required>
              <Input
                id="invite-email"
                type="email"
                required
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                placeholder="name@example.com"
              />
            </FormField>
            <FormField label="Password" htmlFor="invite-password" required>
              <Input
                id="invite-password"
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Set a password"
              />
            </FormField>
            <FormField label="Assigned role" htmlFor="invite-role">
              <Select
                id="invite-role"
                value={newRoleId}
                onChange={(e) => setNewRoleId(e.target.value)}
              >
                {roles.map(role => (
                  <option key={role.id} value={role.id}>{role.name}</option>
                ))}
              </Select>
            </FormField>
          </div>
        </form>
      </Sheet>

      <Dialog
        open={showResetPassword !== null}
        onClose={() => { setShowResetPassword(null); setDialogError(null) }}
        title="Reset User Password"
      >
        <form onSubmit={handleResetPassword} className="space-y-4">
          <div className="space-y-4">
            <p className="text-sm text-[var(--color-text-secondary)]">
              Enter a new password for <strong>{showResetPassword?.username}</strong>.
            </p>
            {dialogError && (
              <div className="rounded-lg border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2.5 text-sm text-[var(--color-severity-critical-text)]">
                {dialogError}
              </div>
            )}
            <FormField label="New Password" htmlFor="reset-password" required>
              <Input
                id="reset-password"
                type="password"
                required
                value={resetPasswordValue}
                onChange={(e) => setResetPasswordValue(e.target.value)}
                placeholder="Enter new password"
              />
            </FormField>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-[var(--color-border)] mt-6">
            <Button variant="ghost" size="md" onClick={() => setShowResetPassword(null)}>Cancel</Button>
            <Button type="submit" variant="primary" size="md" disabled={submitting} isLoading={submitting}>
              {submitting ? "Resetting..." : "Reset Password"}
            </Button>
          </div>
        </form>
      </Dialog>

      <Card padding="none" className="overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th className="w-[22%] px-5">User</Th>
              <Th className="w-[12%]">Role</Th>
              <Th className="w-[10%]">Login</Th>
              <Th className="w-[10%] text-center">Teams</Th>
              <Th className="w-[14%] text-center whitespace-nowrap">Direct Access</Th>
              <Th className="px-5 text-right">Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {users.map((user) => (
              <Fragment key={user.id}>
                <Tr interactive>
                  <Td className="px-5 py-4">
                    <div className="flex flex-col">
                      <span className="font-medium text-[var(--color-text-primary)]">{user.username}</span>
                      <span className="text-xs text-[var(--color-text-secondary)]">{user.email || "No email"}</span>
                      {user.status === "disabled" && (
                        <span className="mt-1 inline-flex w-fit items-center rounded-full border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-2 py-0.5 text-2xs font-medium text-[var(--color-severity-critical-text)]">
                          Disabled
                        </span>
                      )}
                      {user.status === "pending" && (
                        <span className="mt-1 inline-flex w-fit items-center rounded-full border border-[var(--color-severity-medium)]/30 bg-[var(--color-severity-medium)]/10 px-2 py-0.5 text-2xs font-medium text-[var(--color-severity-medium-text)]">
                          Pending activation
                        </span>
                      )}
                    </div>
                  </Td>
                  <Td className="py-4">
                    {canEdit && user.id !== currentUserId && user.status === "active" ? (
                      <Select
                        size="sm"
                        value={user.roleId || ""}
                        onChange={(e) => void handleRoleChange(user, e.target.value)}
                        disabled={mutatingUserId === user.id}
                      >
                        {roles.map(role => (
                          <option key={role.id} value={role.id}>{role.name}</option>
                        ))}
                      </Select>
                    ) : (
                      <span className="text-[11px] font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
                        {roles.find(r => r.id === user.roleId)?.name || ROLE_LABELS[user.role] || user.role}
                      </span>
                    )}
                  </Td>
                  <Td className="py-4">
                    <span className="inline-flex items-center rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2 py-0.5 text-2xs font-medium text-[var(--color-text-secondary)]">
                      Password
                    </span>
                  </Td>
                  <Td className="py-4 text-center">
                    <button
                      onClick={() => setExpandedUserId(expandedUserId === user.id ? null : user.id)}
                      className="text-xs font-medium text-[var(--color-accent)] hover:underline"
                    >
                      {teams.filter(t => t.members.some(m => m.userId === user.id)).length} teams
                    </button>
                  </Td>
                  <Td className="py-4 text-center">
                    <button
                      onClick={() => {
                        setExpandedDirectAccessUserId(expandedDirectAccessUserId === user.id ? null : user.id)
                        setDirectRepoValue("")
                        setDirectRepoSuggestions([])
                        setDirectRepoError(null)
                        setDirectImageValue("")
                        setDirectImageSuggestions([])
                        setDirectImageError(null)
                      }}
                      className="text-xs font-medium text-[var(--color-accent)] hover:underline"
                    >
                      {user.manualDirectGrantCount + user.githubDirectGrantCount} resources
                    </button>
                  </Td>
                  <Td className="px-5 py-4 text-right">
                    <div className="flex items-center justify-end space-x-3">
                      {canEdit && (
                        <>
                          <button
                            onClick={() => setShowResetPassword(user)}
                            disabled={user.role === "owner" && currentUserRole !== "owner"}
                            className={`text-xs font-medium transition-colors ${
                              user.role === "owner" && currentUserRole !== "owner"
                                ? "text-[var(--color-text-secondary)] opacity-30 cursor-not-allowed"
                                : "text-[var(--color-accent)] hover:text-[var(--color-accent-hover)]"
                            }`}
                          >
                            Reset Password
                          </button>
                          <button
                            onClick={() => void handleToggleStatus(user)}
                            disabled={user.id === currentUserId || (user.role === "owner" && currentUserRole !== "owner")}
                            className={`text-xs font-medium transition-colors ${
                              user.id === currentUserId || (user.role === "owner" && currentUserRole !== "owner")
                                ? "text-[var(--color-text-secondary)] opacity-30 cursor-not-allowed"
                                : user.status === "disabled" ? "text-[var(--color-status-ok-text)] hover:opacity-80" : "text-[var(--color-severity-medium-text)] hover:opacity-80"
                            }`}
                          >
                            {user.status === "active" ? "Disable" : user.status === "pending" ? "Activate" : "Enable"}
                          </button>
                          <button
                            onClick={() => void handleDeleteUser(user)}
                            disabled={user.id === currentUserId || (currentUserRole !== "owner" && user.role === "owner")}
                            aria-label={`Delete ${user.username}`}
                            className="text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical-text)] transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path d={TRASH_ICON} strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} />
                            </svg>
                          </button>
                        </>
                      )}
                    </div>
                  </Td>
                </Tr>
                {expandedUserId === user.id && (
                  <Tr className="bg-[var(--color-surface-raised)]/30">
                    <Td colSpan={6} className="px-6 py-4">
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <h4 className="text-2xs font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">Team memberships</h4>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                          {teams.map(team => {
                            const isMember = team.members.some(m => m.userId === user.id)
                            const member = team.members.find(m => m.userId === user.id)
                            return (
                              <div key={team.id} className="flex items-center justify-between rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2">
                                <div className="flex flex-col min-w-0">
                                  <span className="truncate text-sm font-medium">{team.name}</span>
                                  {isMember && member!.source === "github" && (
                                    <span className="text-2xs text-[var(--color-text-secondary)]">Synced</span>
                                  )}
                                  {isMember && member!.source === "manual" && (
                                    <span className="text-2xs text-[var(--color-text-secondary)]">Source: Manual</span>
                                  )}
                                </div>
                                <button
                                  onClick={() => isMember ? handleRemoveTeamMember(team.id, user.id) : handleAddTeamMember(team.id, user.id)}
                                  disabled={isMember && member!.source === "github"}
                                  className={`ml-2 text-xs font-medium transition-colors ${
                                    isMember
                                      ? "text-[var(--color-severity-critical-text)] hover:opacity-80 disabled:opacity-30"
                                      : "text-[var(--color-accent)] hover:text-[var(--color-accent-hover)]"
                                  }`}
                                >
                                  {isMember ? "Remove" : "Add"}
                                </button>
                              </div>
                            )
                          })}
                        </div>
                      </div>
                    </Td>
                  </Tr>
                )}
                {expandedDirectAccessUserId === user.id && (
                  <Tr className="bg-[var(--color-surface-raised)]/30">
                    <Td colSpan={6} className="px-6 py-4">
                      <div className="space-y-6">
                        <div className="space-y-4">
                          <h4 className="text-2xs font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">Direct Access</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                              <label className="text-2xs font-bold uppercase text-[var(--color-text-secondary)]">Grant Repository Access</label>
                              <ResourceAutocomplete
                                value={directRepoValue}
                                ariaLabel="Grant Repository Access"
                                placeholder="Search repositories..."
                                suggestions={directRepoSuggestions}
                                error={directRepoError}
                                onChange={(next) => void updateDirectRepoValue(next)}
                                onPick={(next) => void handleAddDirectGrant(user.id, "repository", next)}
                              />
                            </div>
                            <div className="space-y-2">
                              <label className="text-2xs font-bold uppercase text-[var(--color-text-secondary)]">Grant Image Access</label>
                              <ResourceAutocomplete
                                value={directImageValue}
                                ariaLabel="Grant Image Access"
                                placeholder="Search images..."
                                suggestions={directImageSuggestions}
                                error={directImageError}
                                onChange={(next) => void updateDirectImageValue(next)}
                                onPick={(next) => void handleAddDirectGrant(user.id, "containerImage", next)}
                              />
                            </div>
                          </div>
                        </div>

                        <div className="space-y-3">
                          <h4 className="text-2xs font-bold uppercase text-[var(--color-text-secondary)]">Effective Direct Grants</h4>
                          <div className="flex flex-wrap gap-2">
                            {directGrants.filter(g => g.subjectId === user.id).length === 0 && (
                              <p className="text-xs text-[var(--color-text-secondary)] italic">No direct grants for this user.</p>
                            )}
                            {directGrants.filter(g => g.subjectId === user.id).map((grant, idx) => (
                              <div key={`${grant.assetId}-${idx}`} className="group flex items-center rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1">
                                <div className="flex flex-col mr-2">
                                  <span className="text-xs font-medium">{grant.assetDisplayName ?? grant.assetId}</span>
                                  <span className="text-2xs text-[var(--color-text-secondary)]">
                                    {grant.assetType === "repo" ? "Repo" : "Image"} • {grant.source === "github" ? "Synced" : "Manual"}
                                  </span>
                                </div>
                                {grant.source === "manual" && (
                                  <button
                                    onClick={() => void handleRemoveDirectGrant(user.id, grant.assetId)}
                                    aria-label={`Remove access to ${grant.assetDisplayName ?? grant.assetId}`}
                                    className="text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical-text)]"
                                  >
                                    <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                  </button>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </Td>
                  </Tr>
                )}
              </Fragment>
            ))}
          </Tbody>
        </Table>
      </Card>

      <Dialog
        open={confirmDialog.open}
        onClose={() => setConfirmDialog({ ...confirmDialog, open: false })}
        title={confirmDialog.title}
        description={confirmDialog.description}
        confirmLabel={confirmDialog.confirmLabel || "Confirm"}
        onConfirm={confirmDialog.onConfirm}
        variant={confirmDialog.variant}
      />
    </div>
  )
}

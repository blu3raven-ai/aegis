"use client"

import { useEffect, useState, Fragment, useTransition } from "react"
import { ROLE_LABELS, type UserRole } from "@/lib/shared/auth/roles.ts"
import { fetchCurrentUser } from "@/lib/client/auth"
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
  type DirectGrant,
  type RoleRecord,
} from "@/lib/client/settings-api"
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


async function readJsonPayload(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    return null
  }
}

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

export function UsersSettingsForm({ canEdit = true }: { canEdit?: boolean }) {
  const [users, setUsers] = useState<UserEntry[]>([])
  const [roles, setRoles] = useState<RoleRecord[]>([])
  const [teams, setTeams] = useState<OrganisationTeam[]>([])
  const [directGrants, setDirectGrants] = useState<DirectGrant[]>([])
  const [expandedUserId, setExpandedUserId] = useState<string | null>(null)
  const [expandedDirectAccessUserId, setExpandedDirectAccessUserId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [dialogError, setDialogError] = useState<string | null>(null)
  const [currentUserId, setCurrentUserId] = useState<string | null | undefined>(undefined)
  const [currentUserRole, setCurrentUserRole] = useState<UserRole | null>(null)
  const [showAdd, setShowAdd] = useState(false)
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
      const [usersRes, rolesRes, teamsRes, grantsRes] = await Promise.all([
        fetch("/api/settings/users"),
        listRoles(),
        listOrganisationTeams(),
        listDirectGrants(),
      ])

      if (rolesRes.ok) {
        setRoles(rolesRes.roles)
        const viewerRole = rolesRes.roles.find(r => r.slug === "viewer")
        if (viewerRole) setNewRoleId(viewerRole.id)
      }

      const usersData = await readJsonPayload(usersRes)
      if (!usersRes.ok) {
        if (usersRes.status === 403) {
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
          throw new Error(extractErrorMessage(usersData, "Failed to load users"))
        }
      } else {
        const payload = usersData as { users?: any[] }
        const rawUsers = Array.isArray(payload.users) ? payload.users : []
        const currentGrants = grantsRes.ok ? grantsRes.grants : []
        
        const enriched = rawUsers.map(u => ({
          ...u,
          manualDirectGrantCount: currentGrants.filter(g => g.userId === u.id && g.source === "manual-direct").length,
          githubDirectGrantCount: currentGrants.filter(g => g.userId === u.id && g.source === "github-direct").length,
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
      const res = await fetch("/api/settings/users", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: newUsername,
          email: newEmail,
          password: newPassword,
          role: newRole,
          roleId: newRoleId || undefined
        }),
      })
      const data = await readJsonPayload(res)
      if (!res.ok) throw new Error(extractErrorMessage(data, "Create failed"))
      setNewUsername("")
      setNewEmail("")
      setNewPassword("")
      setShowAdd(false)
      setDialogError(null)
      await loadData()
    } catch (err) {
      setDialogError(err instanceof Error ? err.message : "Create failed")
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
        const res = await fetch(`/api/settings/users/${user.id}/${endpoint}`, { method: "POST" })
        const data = await readJsonPayload(res)
        if (!res.ok) {
          const fallback = endpoint === "disable" ? "Disable failed" : "Enable failed"
          throw new Error(extractErrorMessage(data, fallback))
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
        const res = await fetch(`/api/settings/users/${user.id}/role`, {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ roleId }),
        })
        const data = await readJsonPayload(res)
        if (!res.ok) throw new Error(extractErrorMessage(data, "Role update failed"))
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
      const res = await fetch(`/api/settings/users/${showResetPassword.id}/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: resetPasswordValue }),
      })
      const data = await readJsonPayload(res)
      if (!res.ok) throw new Error(extractErrorMessage(data, "Reset failed"))
      setShowResetPassword(null)
      setResetPasswordValue("")
      setDialogError(null)
    } catch (err) {
      setDialogError(err instanceof Error ? err.message : "Reset failed")
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
          const res = await fetch(`/api/settings/users/${user.id}`, { method: "DELETE" })
          const data = await readJsonPayload(res)
          if (!res.ok) throw new Error(extractErrorMessage(data, "Delete failed"))
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

  async function handleAddDirectGrant(userId: string, type: "repository" | "containerImage", key: string) {
    setError(null)
    const result = await addDirectGrant(userId, type, key)
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
      const grantsRes = await listDirectGrants()
      if (grantsRes.ok) {
        setDirectGrants(grantsRes.grants)
        const enriched = users.map(u => ({
          ...u,
          manualDirectGrantCount: grantsRes.grants.filter(g => g.userId === u.id && g.source === "manual-direct").length,
          githubDirectGrantCount: grantsRes.grants.filter(g => g.userId === u.id && g.source === "github-direct").length,
        }))
        setUsers(enriched)
      }
    } else {
      setError(result.error)
    }
  }

  async function handleRemoveDirectGrant(userId: string, type: string, key: string) {
    setError(null)
    const result = await removeDirectGrant(userId, type, key)
    if (result.ok) {
      const grantsRes = await listDirectGrants()
      if (grantsRes.ok) {
        setDirectGrants(grantsRes.grants)
        const enriched = users.map(u => ({
          ...u,
          manualDirectGrantCount: grantsRes.grants.filter(g => g.userId === u.id && g.source === "manual-direct").length,
          githubDirectGrantCount: grantsRes.grants.filter(g => g.userId === u.id && g.source === "github-direct").length,
        }))
        setUsers(enriched)
      }
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
        <div className="rounded-lg border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2.5 text-sm text-[var(--color-severity-critical)]">
          {error}
        </div>
      )}

      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Members
          </h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Manage workspace members and their access levels.
          </p>
        </div>
        {canEdit && (
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]"
          >
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
              <circle cx="9" cy="7" r="4" />
              <line x1="19" y1="8" x2="19" y2="14" />
              <line x1="22" y1="11" x2="16" y2="11" />
            </svg>
            Invite User
          </button>
        )}
      </div>

      <Dialog
        open={showAdd}
        onClose={() => { setShowAdd(false); setDialogError(null) }}
        title="Create User"
      >
        <form onSubmit={handleCreate} className="space-y-4">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Create a member account with a password. The user can reset their password from account settings.
          </p>
          {dialogError && (
            <div className="rounded-lg border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2.5 text-sm text-[var(--color-severity-critical)]">
              {dialogError}
            </div>
          )}
          <div className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider">Username</label>
              <input
                type="text"
                required
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                placeholder="Enter username"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider">Email Address</label>
              <input
                type="email"
                required
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                placeholder="name@example.com"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider">Password</label>
              <input
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                placeholder="Set a password"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider">Assigned Role</label>
              <select
                value={newRoleId}
                onChange={(e) => setNewRoleId(e.target.value)}
                className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
              >
                {roles.map(role => (
                  <option key={role.id} value={role.id}>{role.name}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-[var(--color-border)] mt-6">
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="rounded-lg px-4 py-2 text-sm font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-lg bg-[var(--color-accent)] px-6 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)] disabled:opacity-50"
            >
              {submitting ? "Creating..." : "Create User"}
            </button>
          </div>
        </form>
      </Dialog>

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
              <div className="rounded-lg border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2.5 text-sm text-[var(--color-severity-critical)]">
                {dialogError}
              </div>
            )}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider">New Password</label>
              <input
                type="password"
                required
                value={resetPasswordValue}
                onChange={(e) => setResetPasswordValue(e.target.value)}
                className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                placeholder="Enter new password"
              />
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-[var(--color-border)] mt-6">
            <button
              type="button"
              onClick={() => setShowResetPassword(null)}
              className="rounded-lg px-4 py-2 text-sm font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-lg bg-[var(--color-accent)] px-6 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)] disabled:opacity-50"
            >
              {submitting ? "Resetting..." : "Reset Password"}
            </button>
          </div>
        </form>
      </Dialog>

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)] border-b border-[var(--color-border)]">
              <th className="w-[22%] px-5 py-3 font-medium uppercase tracking-wider text-[11px]">User</th>
              <th className="w-[12%] px-4 py-3 font-medium uppercase tracking-wider text-[11px]">Role</th>
              <th className="w-[10%] px-4 py-3 font-medium uppercase tracking-wider text-[11px]">Login</th>
              <th className="w-[10%] px-4 py-3 font-medium uppercase tracking-wider text-[11px] text-center">Teams</th>
              <th className="w-[14%] px-4 py-3 font-medium uppercase tracking-wider text-[11px] text-center whitespace-nowrap">Direct Access</th>
              <th className="px-5 py-3 font-medium uppercase tracking-wider text-right text-[11px]">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {users.map((user) => (
              <Fragment key={user.id}>
                <tr className="hover:bg-[var(--color-surface-raised)]/50 transition-colors">
                  <td className="px-5 py-4">
                    <div className="flex flex-col">
                      <span className="font-medium text-[var(--color-text-primary)]">{user.username}</span>
                      <span className="text-xs text-[var(--color-text-secondary)]">{user.email || "No email"}</span>
                      {user.status === "disabled" && (
                        <span className="mt-1 inline-flex w-fit items-center rounded-full border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-2 py-0.5 text-2xs font-medium text-[var(--color-severity-critical)]">
                          Disabled
                        </span>
                      )}
                      {user.status === "pending" && (
                        <span className="mt-1 inline-flex w-fit items-center rounded-full border border-[var(--color-severity-medium)]/30 bg-[var(--color-severity-medium)]/10 px-2 py-0.5 text-2xs font-medium text-[var(--color-severity-medium)]">
                          Pending activation
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    {canEdit && user.id !== currentUserId && user.status === "active" ? (
                      <select
                        value={user.roleId || ""}
                        onChange={(e) => void handleRoleChange(user, e.target.value)}
                        disabled={mutatingUserId === user.id}
                        className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
                      >
                        {roles.map(role => (
                          <option key={role.id} value={role.id}>{role.name}</option>
                        ))}
                      </select>
                    ) : (
                      <span className="text-[11px] font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
                        {roles.find(r => r.id === user.roleId)?.name || ROLE_LABELS[user.role] || user.role}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-4">
                    <span className="inline-flex items-center rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2 py-0.5 text-2xs font-medium text-[var(--color-text-secondary)]">
                      Password
                    </span>
                  </td>
                  <td className="px-4 py-4 text-center">
                    <button
                      onClick={() => setExpandedUserId(expandedUserId === user.id ? null : user.id)}
                      className="text-xs font-medium text-[var(--color-accent)] hover:underline"
                    >
                      {teams.filter(t => t.members.some(m => m.userId === user.id)).length} teams
                    </button>
                  </td>
                  <td className="px-4 py-4 text-center">
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
                  </td>
                  <td className="px-5 py-4 text-right">
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
                                : user.status === "disabled" ? "text-[var(--color-status-ok)] hover:opacity-80" : "text-[var(--color-severity-medium)] hover:opacity-80"
                            }`}
                          >
                            {user.status === "active" ? "Disable" : user.status === "pending" ? "Activate" : "Enable"}
                          </button>
                          <button
                            onClick={() => void handleDeleteUser(user)}
                            disabled={user.id === currentUserId || (currentUserRole !== "owner" && user.role === "owner")}
                            aria-label={`Delete ${user.username}`}
                            className="text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical)] transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path d={TRASH_ICON} strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} />
                            </svg>
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
                {expandedUserId === user.id && (
                  <tr className="bg-[var(--color-surface-raised)]/30">
                    <td colSpan={6} className="px-6 py-4">
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <h4 className="text-2xs font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">Team memberships</h4>
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
                                      ? "text-[var(--color-severity-critical)] hover:opacity-80 disabled:opacity-30"
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
                    </td>
                  </tr>
                )}
                {expandedDirectAccessUserId === user.id && (
                  <tr className="bg-[var(--color-surface-raised)]/30">
                    <td colSpan={6} className="px-6 py-4">
                      <div className="space-y-6">
                        <div className="space-y-4">
                          <h4 className="text-2xs font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">Direct Access</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                              <label className="text-2xs font-bold uppercase text-[var(--color-text-secondary)]">Grant Repository Access</label>
                              <ResourceAutocomplete
                                value={directRepoValue}
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
                            {directGrants.filter(g => g.userId === user.id).length === 0 && (
                              <p className="text-xs text-[var(--color-text-secondary)] italic">No direct grants for this user.</p>
                            )}
                            {directGrants.filter(g => g.userId === user.id).map((grant, idx) => (
                              <div key={`${grant.resourceType}-${grant.resourceKey}-${idx}`} className="group flex items-center rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1">
                                <div className="flex flex-col mr-2">
                                  <span className="text-xs font-medium">{grant.resourceKey}</span>
                                  <span className="text-2xs text-[var(--color-text-secondary)]">
                                    {grant.resourceType === "repository" ? "Repo" : "Image"} • {grant.source === "github-direct" ? "Synced" : "Manual"}
                                  </span>
                                </div>
                                {grant.source === "manual-direct" && (
                                  <button
                                    onClick={() => void handleRemoveDirectGrant(user.id, grant.resourceType, grant.resourceKey)}
                                    className="text-[var(--color-text-secondary)] hover:text-[var(--color-severity-critical)]"
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
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

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

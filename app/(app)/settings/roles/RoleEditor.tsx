"use client"

import { useState, useEffect } from "react"
import { RoleRecord, RoleInput } from "@/lib/client/settings-api"
import { PERMISSION_GROUPS } from "@/lib/shared/auth/permissions"
import { PermissionGroup } from "./PermissionGroup"

interface RoleEditorProps {
  role: RoleRecord | null
  isCreating?: boolean
  onSave: (role: RoleInput) => Promise<void>
  onDelete: (roleId: string) => void | Promise<void>
  onCancel: () => void
  isLoading?: boolean
}

export function RoleEditor({ 
  role, 
  isCreating = false, 
  onSave, 
  onDelete, 
  onCancel,
  isLoading = false
}: RoleEditorProps) {
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [permissions, setPermissions] = useState<string[]>([])
  const [currentId, setCurrentId] = useState("")
  
  useEffect(() => {
    if (role) {
      setName(role.name)
      setDescription(role.description)
      setPermissions(role.permissions)
      setCurrentId(role.id)
    } else {
      setName("")
      setDescription("")
      setPermissions([])
      setCurrentId(`role_${crypto.randomUUID()}`)
    }
  }, [role])

  const handleTogglePermission = (id: string) => {
    setPermissions(prev => 
      prev.includes(id) ? prev.filter(p => p !== id) : [...prev, id]
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    await onSave({ id: currentId, name, description, permissions })
  }

  if (!role && !isCreating) return null

  const isOwner = role?.id === "role_owner"
  const isLocked = role?.isLocked || isOwner

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <h2 className="text-lg font-semibold text-[var(--color-text-primary)]">
          {isCreating ? "Create New Role" : `Edit Role: ${role?.name}`}
        </h2>
        <div className="flex items-center space-x-3">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] transition-colors"
          >
            Cancel
          </button>
          {!isLocked && !isCreating && role && (
            <button
              type="button"
              onClick={() => onDelete(role.id)}
              className="rounded-lg bg-red-500/10 px-4 py-2 text-sm font-semibold text-red-500 border border-red-500/20 hover:bg-red-500/20 transition-colors"
            >
              Delete Role
            </button>
          )}
          <button
            onClick={handleSubmit}
            disabled={isLoading || isLocked}
            className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-white hover:bg-[var(--color-accent-hover)] transition-colors disabled:opacity-50"
          >
            {isLoading ? "Saving..." : "Save Role"}
          </button>
        </div>
      </div>

      {isLocked && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-400">
          This is a protected role. It cannot be modified or deleted.
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-8 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-1.5">
            <label htmlFor="role-name" className="text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">Role Name</label>
            <input
              id="role-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={isLocked || isLoading}
              required
              placeholder="e.g. Security Auditor"
              className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:border-[var(--color-accent)] focus:outline-none"
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="role-id" className="text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">Role ID</label>
            <input
              id="role-id"
              type="text"
              value={currentId}
              readOnly
              className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-sm font-mono text-[var(--color-text-secondary)] cursor-default focus:outline-none"
              title="Role ID is automatically generated and cannot be changed"
            />
          </div>
        </div>

        <div className="space-y-1.5">
          <label htmlFor="role-desc" className="text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">Description</label>
          <textarea
            id="role-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            disabled={isLocked || isLoading}
            rows={2}
            placeholder="Describe the purpose and access level of this role."
            className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:border-[var(--color-accent)] focus:outline-none resize-none"
          />
        </div>

        <div className="space-y-6 border-t border-[var(--color-border)] pt-8">
          <div className="space-y-1">
            <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">Permissions</h3>
            <p className="text-xs text-[var(--color-text-secondary)]">
              Define the capabilities for this role across different system areas.
            </p>
          </div>
          
          <div className="space-y-8">
            {PERMISSION_GROUPS.map((group) => (
              <PermissionGroup
                key={group.id}
                label={group.label}
                permissions={group.permissions}
                selectedPermissions={permissions}
                onTogglePermission={handleTogglePermission}
                disabled={isLocked || isLoading}
              />
            ))}
          </div>
        </div>
      </form>
    </div>
  )
}

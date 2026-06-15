"use client"

import { useState, useEffect, useMemo, type MutableRefObject } from "react"
import {
  listRoles,
  createRole,
  updateRole,
  duplicateRole,
  deleteRole,
  RoleRecord,
  RoleInput
} from "@/lib/client/settings-api"
import { Button } from "@/components/ui/Button"
import { Sheet } from "@/components/ui/Sheet"
import { RolesTable } from "./RolesTable"
import { RoleEditor } from "./RoleEditor"
import { Dialog } from "@/components/layout/Dialog"

interface RolesContentProps {
  /**
   * When provided, the section's "Create role" button lives in the parent
   * SettingsSection header instead of in its own row above the content.
   */
  createTriggerRef?: MutableRefObject<(() => void) | null>
}

export function RolesContent({ createTriggerRef }: RolesContentProps = {}) {
  const [roles, setRoles] = useState<RoleRecord[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [selectedRoleId, setSelectedRoleId] = useState<string | null>(null)
  const [isCreating, setIsCreating] = useState(false)

  const selectedRole = useMemo(() =>
    roles.find(r => r.id === selectedRoleId) || null,
    [roles, selectedRoleId]
  )

  // Dialog states
  const [errorDialog, setErrorDialog] = useState<{ open: boolean; title: string; message: string }>({
    open: false,
    title: "",
    message: "",
  })
  const [deleteConfirm, setDeleteConfirm] = useState<{ open: boolean; roleId: string | null }>({
    open: false,
    roleId: null,
  })

  const refreshRoles = async () => {
    setIsLoading(true)
    const result = await listRoles()
    if (result.ok) {
      setRoles(result.roles)
      setError(null)
    } else {
      setError(result.error)
    }
    setIsLoading(false)
  }

  useEffect(() => {
    refreshRoles()
  }, [])

  const handleCreate = () => {
    setIsCreating(true)
    setSelectedRoleId(null)
  }

  // Publish the create handler so the parent SettingsSection can mount the
  // action button next to the section title.
  useEffect(() => {
    if (!createTriggerRef) return
    createTriggerRef.current = handleCreate
    return () => {
      createTriggerRef.current = null
    }
  }, [createTriggerRef])

  const handleSelect = (role: RoleRecord) => {
    setSelectedRoleId(role.id)
    setIsCreating(false)
  }

  const handleDuplicate = async (role: RoleRecord) => {
    setIsSaving(true)
    const result = await duplicateRole(role.id)
    if (result.ok) {
      await refreshRoles()
      setSelectedRoleId(result.role.id)
      setIsCreating(false)
    } else {
      setErrorDialog({
        open: true,
        title: "Duplicate Failed",
        message: result.error,
      })
    }
    setIsSaving(false)
  }

  const handleSave = async (input: RoleInput) => {
    setIsSaving(true)
    let result
    if (isCreating) {
      result = await createRole(input)
    } else if (selectedRole) {
      result = await updateRole(selectedRole.id, input)
    }

    if (result && result.ok) {
      await refreshRoles()
      setSelectedRoleId(result.role.id)
      setIsCreating(false)
    } else if (result) {
      setErrorDialog({
        open: true,
        title: "Save Failed",
        message: result.error,
      })
    }
    setIsSaving(false)
  }

  const handleDeleteTrigger = (roleId: string) => {
    setDeleteConfirm({ open: true, roleId })
  }

  const handleDeleteConfirm = async () => {
    const roleId = deleteConfirm.roleId
    if (!roleId) return

    setDeleteConfirm({ open: false, roleId: null })
    setIsSaving(true)
    const result = await deleteRole(roleId)
    if (result.ok) {
      await refreshRoles()
      setSelectedRoleId(null)
      setIsCreating(false)
    } else {
      setErrorDialog({
        open: true,
        title: "Delete Failed",
        message: result.error,
      })
    }
    setIsSaving(false)
  }

  const handleCancel = () => {
    setSelectedRoleId(null)
    setIsCreating(false)
  }

  if (isLoading && roles.length === 0) {
    return (
      <div className="animate-pulse space-y-4">
        <div className="h-8 w-48 bg-[var(--color-surface-raised)] rounded" />
        <div className="h-4 w-96 bg-[var(--color-surface-raised)] rounded" />
        <div className="h-64 bg-[var(--color-surface-raised)] rounded-lg" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {!selectedRole && !isCreating && !createTriggerRef && (
        <div className="flex items-start justify-end gap-4">
          <Button
            variant="primary"
            size="md"
            onClick={handleCreate}
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="12" y1="5" x2="12" y2="19"></line>
                <line x1="5" y1="12" x2="19" y2="12"></line>
              </svg>
            }
          >
            Create Role
          </Button>
        </div>
      )}

      {error && (
        <div className="mb-6 rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3 text-sm text-[var(--color-severity-critical)]">
          {error}
        </div>
      )}

      <RolesTable
        roles={roles}
        onSelectRole={handleSelect}
        onDuplicateRole={handleDuplicate}
        onDeleteRole={handleDeleteTrigger}
      />

      <Sheet
        open={!!selectedRole || isCreating}
        onClose={handleCancel}
        title={isCreating ? "Create role" : `Edit role: ${selectedRole?.name ?? ""}`}
        description={
          isCreating
            ? "Name the role and pick the permissions it grants."
            : "Adjust the permissions this role grants."
        }
        size="xl"
        footer={
          <div className="flex items-center justify-end gap-2">
            {selectedRole && !selectedRole.isLocked && selectedRole.id !== "role_owner" && !isCreating && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handleDeleteTrigger(selectedRole.id)}
                className="mr-auto border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)] hover:border-[var(--color-severity-critical-border)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical)]"
              >
                Delete role
              </Button>
            )}
            <Button variant="ghost" size="md" onClick={handleCancel}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="role-editor-form"
              variant="primary"
              size="md"
              disabled={isSaving || (!!selectedRole && (selectedRole.isLocked || selectedRole.id === "role_owner"))}
              isLoading={isSaving}
            >
              {isSaving ? "Saving…" : isCreating ? "Create role" : "Save role"}
            </Button>
          </div>
        }
      >
        <RoleEditor
          role={selectedRole}
          isCreating={isCreating}
          onSave={handleSave}
          isLoading={isSaving}
        />
      </Sheet>

      {/* Popups */}
      <Dialog
        open={deleteConfirm.open}
        onClose={() => setDeleteConfirm({ open: false, roleId: null })}
        onConfirm={handleDeleteConfirm}
        title="Delete Role"
        description="Are you sure you want to delete this role? This action cannot be undone and will affect all assigned users."
        confirmLabel="Delete"
        variant="danger"
      />

      <Dialog
        open={errorDialog.open}
        onClose={() => setErrorDialog({ ...errorDialog, open: false })}
        title={errorDialog.title}
        description={errorDialog.message}
        confirmLabel="Close"
      />
    </div>
  )
}

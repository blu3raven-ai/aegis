"use client"

import { useState, useEffect, useMemo, Suspense } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { 
  listRoles, 
  getRole, 
  createRole, 
  updateRole, 
  duplicateRole, 
  deleteRole,
  RoleRecord,
  RoleInput
} from "@/lib/client/settings-api"
import { RolesTable } from "./RolesTable"
import { RoleEditor } from "./RoleEditor"
import { Dialog } from "@/components/layout/Dialog"

function RolesSettingsContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [roles, setRoles] = useState<RoleRecord[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Derive selection state from URL search params
  const selectedRoleId = searchParams.get("id")
  const isCreating = searchParams.get("action") === "create"

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
    router.push("/settings/roles?action=create")
  }

  const handleSelect = (role: RoleRecord) => {
    router.push(`/settings/roles?id=${role.id}`)
  }

  const handleDuplicate = async (role: RoleRecord) => {
    setIsSaving(true)
    const result = await duplicateRole(role.id)
    if (result.ok) {
      await refreshRoles()
      router.push(`/settings/roles?id=${result.role.id}`)
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
      router.push(`/settings/roles?id=${result.role.id}`)
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
      router.push("/settings/roles")
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
    router.push("/settings/roles")
  }

  if (isLoading && roles.length === 0) {
    return (
      <div className="mx-auto max-w-6xl p-6 lg:p-10">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-48 bg-[var(--color-bg-tertiary)] rounded" />
          <div className="h-4 w-96 bg-[var(--color-bg-tertiary)] rounded" />
          <div className="h-64 bg-[var(--color-bg-tertiary)] rounded-lg" />
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-6xl p-6 lg:p-10 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Roles
          </h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Define custom roles and manage system permissions.
          </p>
        </div>
        {!selectedRole && !isCreating && (
          <button
            onClick={handleCreate}
            className="flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-[var(--color-accent-hover)]"
          >
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="12" y1="5" x2="12" y2="19"></line>
              <line x1="5" y1="12" x2="19" y2="12"></line>
            </svg>
            Create Role
          </button>
        )}
      </div>

      {error && (
        <div className="mb-6 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {(selectedRole || isCreating) ? (
        <RoleEditor
          role={selectedRole}
          isCreating={isCreating}
          onSave={handleSave}
          onDelete={handleDeleteTrigger}
          onCancel={handleCancel}
          isLoading={isSaving}
        />
      ) : (
        <RolesTable
          roles={roles}
          onSelectRole={handleSelect}
          onDuplicateRole={handleDuplicate}
          onDeleteRole={handleDeleteTrigger}
        />
      )}

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

export default function RolesSettingsPage() {
  return (
    <Suspense fallback={
      <div className="mx-auto max-w-6xl p-6 lg:p-10">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-48 bg-[var(--color-bg-tertiary)] rounded" />
          <div className="h-4 w-96 bg-[var(--color-bg-tertiary)] rounded" />
          <div className="h-64 bg-[var(--color-bg-tertiary)] rounded-lg" />
        </div>
      </div>
    }>
      <RolesSettingsContent />
    </Suspense>
  )
}

"use client"

import { useState, useEffect } from "react"
import { RoleRecord, RoleInput } from "@/lib/client/settings-api"
import { PERMISSION_GROUPS } from "@/lib/shared/auth/permissions"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Textarea } from "@/components/ui/Textarea"
import { PermissionGroup } from "./PermissionGroup"

interface RoleEditorProps {
  role: RoleRecord | null
  isCreating?: boolean
  onSave: (role: RoleInput) => Promise<void>
  isLoading?: boolean
  /** Form id used by external Save buttons that submit via the form attribute. */
  formId?: string
}

// Renders only the editor body. Title + Cancel/Delete/Save live on the
// hosting Sheet's header and footer; this component owns the inputs and the
// form submit handler, exposed by id so a footer button can drive it.
export function RoleEditor({
  role,
  isCreating = false,
  onSave,
  isLoading = false,
  formId = "role-editor-form",
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
    setPermissions((prev) =>
      prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id],
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    await onSave({ id: currentId, name, description, permissions })
  }

  if (!role && !isCreating) return null

  const isLocked = !!role?.isLocked

  return (
    <div className="space-y-6">
      {isLocked && (
        <div className="rounded-md border border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)] px-4 py-3 text-sm text-[var(--color-state-pending-text)]">
          This is a protected role. It cannot be modified or deleted.
        </div>
      )}

      <form id={formId} onSubmit={handleSubmit} className="space-y-8">
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          <FormField label="Role name" htmlFor="role-name" required>
            <Input
              id="role-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={isLocked || isLoading}
              required
              placeholder="e.g. Security Auditor"
            />
          </FormField>
          <FormField label="Role ID" htmlFor="role-id">
            <Input
              id="role-id"
              type="text"
              value={currentId}
              readOnly
              className="cursor-default font-mono"
              title="Role ID is automatically generated and cannot be changed"
            />
          </FormField>
        </div>

        <FormField label="Description" htmlFor="role-desc">
          <Textarea
            id="role-desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            disabled={isLocked || isLoading}
            rows={2}
            placeholder="Describe the purpose and access level of this role."
            className="resize-none"
          />
        </FormField>

        <div className="space-y-6 border-t border-[var(--color-border)] pt-6">
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

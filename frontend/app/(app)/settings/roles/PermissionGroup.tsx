"use client"

import { Permission } from "@/lib/shared/auth/permissions"
import { Button } from "@/components/ui/Button"

interface PermissionGroupProps {
  label: string
  permissions: Array<{
    id: string
    label: string
    description: string
  }>
  selectedPermissions: string[]
  onTogglePermission: (id: string) => void
  disabled?: boolean
}

export function PermissionGroup({ 
  label, 
  permissions, 
  selectedPermissions, 
  onTogglePermission,
  disabled 
}: PermissionGroupProps) {
  const allSelected = permissions.every(p => selectedPermissions.includes(p.id))
  
  const handleToggleGroup = () => {
    if (disabled) return
    const ids = permissions.map(p => p.id)
    if (allSelected) {
      // Unselect all in this group
      ids.forEach(id => {
        if (selectedPermissions.includes(id)) {
          onTogglePermission(id)
        }
      })
    } else {
      // Select all in this group
      ids.forEach(id => {
        if (!selectedPermissions.includes(id)) {
          onTogglePermission(id)
        }
      })
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between px-1">
        <h4 className="text-2xs font-mono font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          {label}
        </h4>
        <Button
          variant="link"
          size="xs"
          onClick={handleToggleGroup}
          disabled={disabled}
          className="font-mono font-bold uppercase tracking-[0.14em] text-[var(--color-accent)] hover:text-[var(--color-accent-hover)]"
        >
          {allSelected ? "Unselect All" : "Select All"}
        </Button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {permissions.map((p) => (
          <label 
            key={p.id} 
            className={`flex items-start space-x-3 rounded-md border border-[var(--color-border)] p-3 transition-colors ${
              disabled ? 'opacity-60 grayscale bg-[var(--color-surface-raised)]/50' : 'hover:bg-[var(--color-surface-raised)] cursor-pointer bg-[var(--color-surface)]'
            }`}
          >
            <div className="flex h-5 items-center">
              <input
                type="checkbox"
                checked={selectedPermissions.includes(p.id)}
                onChange={() => onTogglePermission(p.id)}
                disabled={disabled}
                className="h-4 w-4 rounded border-[var(--color-border)] bg-[var(--color-bg)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30 disabled:cursor-not-allowed"
              />
            </div>
            <div className="space-y-0.5">
              <span className="block text-xs font-semibold text-[var(--color-text-primary)]">
                {p.label}
              </span>
              <span className="block text-[11px] leading-tight text-[var(--color-text-secondary)]">
                {p.description}
              </span>
            </div>
          </label>
        ))}
      </div>
    </div>
  )
}

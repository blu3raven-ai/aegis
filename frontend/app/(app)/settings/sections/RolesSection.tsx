"use client"

import { useRef } from "react"

import { SettingsHeaderButton } from "@/components/settings/SettingsHeaderButton"
import { SettingsSection } from "@/components/settings/SettingsSection"
import { RolesContent } from "../roles/RolesContent"

export function RolesSection() {
  const createTriggerRef = useRef<(() => void) | null>(null)

  return (
    <SettingsSection
      id="roles"
      title="Roles"
      subtitle="Role permissions and assignments"
      headerExtra={
        <SettingsHeaderButton
          onClick={() => createTriggerRef.current?.()}
          icon={
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2.5}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
          }
        >
          Create Role
        </SettingsHeaderButton>
      }
    >
      <RolesContent createTriggerRef={createTriggerRef} />
    </SettingsSection>
  )
}

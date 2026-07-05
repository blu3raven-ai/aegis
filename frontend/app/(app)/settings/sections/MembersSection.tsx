"use client"

import { useRef } from "react"

import { SettingsHeaderButton } from "@/components/settings/SettingsHeaderButton"
import { SettingsSection } from "@/components/settings/SettingsSection"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { UsersSettingsForm } from "../users/UsersSettingsForm"

export function MembersSection() {
  const { user } = useSession()
  const canEdit = user ? can(user.role as any, "manage_users") : false
  const inviteTriggerRef = useRef<(() => void) | null>(null)

  return (
    <SettingsSection
      id="members"
      title="Members"
      subtitle="Active members and roles for the organization"
      headerExtra={
        canEdit ? (
          <SettingsHeaderButton
            onClick={() => inviteTriggerRef.current?.()}
            icon={
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <line x1="19" y1="8" x2="19" y2="14" />
                <line x1="22" y1="11" x2="16" y2="11" />
              </svg>
            }
          >
            Invite Member
          </SettingsHeaderButton>
        ) : undefined
      }
    >
      <UsersSettingsForm canEdit={canEdit} inviteTriggerRef={inviteTriggerRef} />
    </SettingsSection>
  )
}

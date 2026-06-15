"use client"

import { useRef } from "react"
import { Button } from "@/components/ui/Button"
import { PageHeader } from "@/components/layout/PageHeader"
import { MembersIcon } from "@/lib/shared/ui/page-icons"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { UsersSettingsForm } from "@/app/(app)/settings/users/UsersSettingsForm"

export function MembersPageContent() {
  const { user } = useSession()
  // canEdit controls only the inner form's edit affordances. The header
  // button stays visible (matching /sources); the API enforces permissions
  // when the user actually submits, avoiding a button that flicker-appears
  // after the session resolves.
  const canEdit = user ? can(user.role as any, "manage_users") : false
  const inviteTriggerRef = useRef<(() => void) | null>(null)

  return (
    <>
      <PageHeader
        icon={<MembersIcon />}
        title="Members"
        description="Active members and roles for the organization"
        controls={
          <Button
            variant="primary"
            size="sm"
            onClick={() => inviteTriggerRef.current?.()}
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <line x1="19" y1="8" x2="19" y2="14" />
                <line x1="22" y1="11" x2="16" y2="11" />
              </svg>
            }
          >
            Invite Member
          </Button>
        }
      />
      <div className="px-6 py-6">
        <UsersSettingsForm canEdit={canEdit} inviteTriggerRef={inviteTriggerRef} />
      </div>
    </>
  )
}

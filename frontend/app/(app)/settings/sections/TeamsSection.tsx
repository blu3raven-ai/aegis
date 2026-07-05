"use client"

import { useRef } from "react"

import { SettingsHeaderButton } from "@/components/settings/SettingsHeaderButton"
import { SettingsSection } from "@/components/settings/SettingsSection"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { OrganisationsContent } from "../organisations/OrganisationsContent"

export function TeamsSection() {
  const { user } = useSession()
  const canEdit = user ? can(user.role as any, "manage_organisations") : false
  const createTriggerRef = useRef<(() => void) | null>(null)

  return (
    <SettingsSection
      id="teams"
      title="Teams"
      subtitle="Team membership and resource sharing"
      headerExtra={
        canEdit ? (
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
            New Team
          </SettingsHeaderButton>
        ) : undefined
      }
    >
      <OrganisationsContent canEdit={canEdit} createTriggerRef={createTriggerRef} />
    </SettingsSection>
  )
}

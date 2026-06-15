"use client"

import { useRef } from "react"
import { Button } from "@/components/ui/Button"
import { PageHeader } from "@/components/layout/PageHeader"
import { TeamsIcon } from "@/lib/shared/ui/page-icons"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { OrganisationsContent } from "@/app/(app)/settings/organisations/OrganisationsContent"

export function TeamsPageContent() {
  const { user } = useSession()
  // canEdit controls only the inner form's edit affordances. The header
  // button stays visible (matching /sources); the API enforces permissions
  // when the user actually submits, avoiding a button that flicker-appears
  // after the session resolves.
  const canEdit = user ? can(user.role as any, "manage_organisations") : false
  const createTriggerRef = useRef<(() => void) | null>(null)

  return (
    <>
      <PageHeader
        icon={<TeamsIcon />}
        title="Teams"
        description="Team membership and resource sharing"
        controls={
          <Button
            variant="primary"
            size="sm"
            onClick={() => createTriggerRef.current?.()}
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
            }
          >
            New Team
          </Button>
        }
      />
      <div className="px-6 py-6">
        <OrganisationsContent canEdit={canEdit} createTriggerRef={createTriggerRef} />
      </div>
    </>
  )
}

"use client"

import { useRef } from "react"
import { Button } from "@/components/ui/Button"
import { PageHeader } from "@/components/layout/PageHeader"
import { RolesIcon } from "@/lib/shared/ui/page-icons"
import { RolesContent } from "@/app/(app)/settings/roles/RolesContent"

export function RolesPageContent() {
  const createTriggerRef = useRef<(() => void) | null>(null)

  return (
    <>
      <PageHeader
        icon={<RolesIcon />}
        title="Roles"
        description="Role permissions and assignments"
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
            Create Role
          </Button>
        }
      />
      <div className="px-6 py-6">
        <RolesContent createTriggerRef={createTriggerRef} />
      </div>
    </>
  )
}

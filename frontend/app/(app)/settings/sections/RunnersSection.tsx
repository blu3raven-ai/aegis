"use client"

import { SettingsSection } from "@/components/settings/SettingsSection"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { RunnersContent } from "../runners/RunnersContent"

export function RunnersSection() {
  const { user } = useSession()
  const canEdit = user ? can(user.role as any, "manage_settings") : false
  return (
    <SettingsSection id="runners" title="Runners" subtitle="Self-hosted scan runners">
      <RunnersContent canEdit={canEdit} />
    </SettingsSection>
  )
}

"use client"

import { SettingsSection } from "@/components/settings/SettingsSection"
import { useHasPermission } from "@/lib/client/use-permission"
import { RunnersContent } from "../runners/RunnersContent"

export function RunnersSection() {
  const { allowed: canEdit } = useHasPermission("manage_runners")
  return (
    <SettingsSection id="runners" title="Runners" subtitle="Self-hosted scan runners">
      <RunnersContent canEdit={canEdit} />
    </SettingsSection>
  )
}

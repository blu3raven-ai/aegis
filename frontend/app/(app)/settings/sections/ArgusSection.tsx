"use client"

import { SettingsSection } from "@/components/settings/SettingsSection"
import { useHasPermission } from "@/lib/client/use-permission"
import { ArgusConnectionContent } from "../llm/ArgusConnectionContent"

export function ArgusSection() {
  const { allowed: canEdit, loading } = useHasPermission("manage_settings")
  return (
    <SettingsSection
      id="argus"
      title="Argus verification"
      subtitle="Connect your hosted Argus service over OAuth — no model key needed in Aegis"
    >
      <ArgusConnectionContent canEdit={canEdit} sessionLoading={loading} />
    </SettingsSection>
  )
}

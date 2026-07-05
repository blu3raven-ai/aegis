"use client"

import { SettingsSection } from "@/components/settings/SettingsSection"
import { useHasPermission } from "@/lib/client/use-permission"
import { LlmContent } from "../llm/LlmContent"

export function LlmSection() {
  const { allowed: canEdit, loading } = useHasPermission("manage_settings")
  return (
    <SettingsSection
      id="llm"
      title="LLM verification"
      subtitle="Bring your own LLM key for the agentic verification layer"
    >
      <LlmContent canEdit={canEdit} sessionLoading={loading} />
    </SettingsSection>
  )
}

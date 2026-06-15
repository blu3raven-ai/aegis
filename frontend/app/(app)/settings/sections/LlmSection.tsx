"use client"

import { SettingsSection } from "@/components/settings/SettingsSection"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { LlmContent } from "../llm/LlmContent"

export function LlmSection() {
  const { user } = useSession()
  const canEdit = user ? can(user.role as any, "manage_settings") : false
  if (!canEdit) return null
  return (
    <SettingsSection
      id="llm"
      title="LLM verification"
      subtitle="Bring your own LLM key for the agentic verification layer"
    >
      <LlmContent />
    </SettingsSection>
  )
}

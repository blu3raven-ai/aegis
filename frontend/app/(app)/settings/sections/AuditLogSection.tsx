"use client"

import { SettingsSection } from "@/components/settings/SettingsSection"
import { AuditContent } from "../audit/AuditContent"

export function AuditLogSection() {
  return (
    <SettingsSection id="audit" title="Audit Log" subtitle="Organization-wide audit events">
      <AuditContent />
    </SettingsSection>
  )
}

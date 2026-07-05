"use client"

import { SettingsSection } from "@/components/settings/SettingsSection"
import { SsoContent } from "../sso/SsoContent"

export function SsoSection() {
  return (
    <SettingsSection id="sso" title="SSO / SAML" subtitle="Single sign-on configuration">
      <SsoContent />
    </SettingsSection>
  )
}

import { SettingsSection } from "@/components/settings/SettingsSection"
import { LicenseContent } from "../license/LicenseContent"

export function LicenseSection() {
  return (
    <SettingsSection id="license" title="License" subtitle="Plan, seats, and entitlements">
      <LicenseContent />
    </SettingsSection>
  )
}

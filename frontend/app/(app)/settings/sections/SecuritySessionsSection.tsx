import { SettingsSection } from "@/components/settings/SettingsSection"
import { ActiveSessionsCard } from "@/components/settings/ActiveSessionsCard"
import { AccountContent } from "../account/AccountContent"

export function SecuritySessionsSection() {
  return (
    <SettingsSection
      id="security"
      title="Security & Sessions"
      subtitle="Identity, authentication, and active sessions"
    >
      <AccountContent />
      <ActiveSessionsCard />
    </SettingsSection>
  )
}

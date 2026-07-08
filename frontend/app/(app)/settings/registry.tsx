import type { ComponentType } from "react"

import { NotificationsDetail } from "./sections/NotificationsPanel"
import { SecurityDetail } from "./sections/SecurityPanel"
import { ApiKeysDetail } from "./sections/ApiKeysPanel"
import { GeneralDetail } from "./sections/GeneralPanel"
import { SsoDetail } from "./sections/SsoPanel"
import { AuditDetail } from "./sections/AuditPanel"
import { RunnersDetail } from "./sections/RunnersPanel"
import { AdvisoryDataDetail } from "./sections/AdvisoryDataPanel"
import { LlmDetail } from "./sections/LlmPanel"
import { LicenseDetail } from "./sections/LicensePanel"

/** Props a section detail body receives. Every section renders its detail inline
 *  on the page. */
export interface DetailComponentProps {
  /** Optional: a detail body calls this after it mutates server state so a
   *  neighbouring reader can refresh. Most inline sections re-fetch themselves. */
  onChanged?: () => void
}

export interface SettingsSectionDef {
  /** Hash id — must be unique and URL-safe. Deep links (/settings#<id>, e.g. the
   *  Findings "Enable verification" CTA) scroll to the section by this id. */
  id: string
  title: string
  subtitle?: string
  /** Nav cluster: "personal" (signed-in user), "organization" (org-admin), or
   *  "add-ons" (licensed capability add-ons: LLM verification, Argus, License). */
  group: "personal" | "organization" | "add-ons"
  detailComponent: ComponentType<DetailComponentProps>
}

export const SETTINGS_SECTIONS: readonly SettingsSectionDef[] = [
  { id: "account", title: "Account", subtitle: "Preferences, identity, 2FA, and active sessions", group: "personal", detailComponent: SecurityDetail },
  { id: "notifications", title: "Notifications", subtitle: "In-app notification preferences", group: "personal", detailComponent: NotificationsDetail },
  { id: "api-keys", title: "API tokens", subtitle: "Personal access tokens for the Aegis API", group: "personal", detailComponent: ApiKeysDetail },
  { id: "general", title: "General", subtitle: "Name, branding, and authentication policy", group: "organization", detailComponent: GeneralDetail },
  { id: "sso", title: "SSO / SAML", subtitle: "Single sign-on, SCIM, and audit streaming", group: "organization", detailComponent: SsoDetail },
  { id: "audit", title: "Audit Log", subtitle: "Org-wide activity and admin actions", group: "organization", detailComponent: AuditDetail },
  { id: "runners", title: "Runners", subtitle: "Self-hosted scan runners and concurrency", group: "organization", detailComponent: RunnersDetail },
  { id: "llm", title: "LLM verification", subtitle: "Verify findings and cut false positives with your own model", group: "add-ons", detailComponent: LlmDetail },
  { id: "advisory-data", title: "Advisory Data", subtitle: "Vulnerability feeds, advisory sources, and threat-intel add-ons", group: "add-ons", detailComponent: AdvisoryDataDetail },
  { id: "license", title: "License", subtitle: "Plan, seats, and entitlements", group: "add-ons", detailComponent: LicenseDetail },
] as const

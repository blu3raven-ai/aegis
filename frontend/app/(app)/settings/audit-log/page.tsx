import { redirect } from "next/navigation"

// Redirect legacy /settings/audit-log path to the new viewer page
export default function AuditLogRedirect() {
  redirect("/settings/audit")
}

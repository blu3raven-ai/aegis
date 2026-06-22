import { redirect } from "next/navigation"

// /inbox has no content of its own — Triage is the default tab and lives at
// /inbox/triage (sibling to /inbox/history). Redirect so the URL is explicit.
export default function InboxPage() {
  redirect("/inbox/triage")
}

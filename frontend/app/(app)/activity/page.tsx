import { redirect } from "next/navigation"

// Activity merged into the Inbox History tab. Preserve the old route for any
// existing bookmarks / deep links by redirecting to /inbox/history.
export default function ActivityPage() {
  redirect("/inbox/history")
}

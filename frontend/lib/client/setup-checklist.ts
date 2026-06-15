/**
 * Setup-checklist task status — derives task completion from real data so
 * the user never has to manually tick anything off. Stripe / Linear pattern.
 *
 * Each task fires a small read against the matching endpoint in parallel.
 * Failures are treated as `done: false` so a dead backend doesn't mark
 * setup falsely complete.
 */

import { listSourceConnections } from "./sources-api"
import { listDestinations } from "./destinations-api"
import { listFindingsSummary } from "./findings-api"
import { listRules } from "./rules-api"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

export interface SetupTask {
  /** Stable id used as the localStorage key and for analytics. */
  id: "connect_source" | "run_first_scan" | "triage_finding" | "set_sla_policy" | "add_notification"
  /** Short imperative title shown in the widget. */
  title: string
  /** One-line description shown when the task is incomplete. */
  description: string
  /** Where clicking the row sends the user. */
  href: string
  /** Derived from backend state — true when the underlying condition is met. */
  done: boolean
}

export async function getSetupChecklist(): Promise<SetupTask[]> {
  const [sources, summary, rules, destinations] = await Promise.allSettled([
    listSourceConnections(),
    listFindingsSummary(ORG_ID),
    listRules(ORG_ID),
    listDestinations(ORG_ID),
  ])

  const sourcesOk = sources.status === "fulfilled" && sources.value.ok
  const sourcesCount = sourcesOk
    ? sources.value.ok ? sources.value.data.connections.length : 0
    : 0

  const summaryOk = summary.status === "fulfilled"
  const openCount = summaryOk ? summary.value.open : 0
  // `fixed_recent` + `dismissed` together prove that *some* triage has happened.
  const triagedCount = summaryOk ? summary.value.fixed_recent + summary.value.dismissed : 0

  const rulesOk = rules.status === "fulfilled"
  const slaSet = rulesOk && rules.value.some((r) => r.category === "sla")

  const destinationsOk = destinations.status === "fulfilled"
  const destinationsCount = destinationsOk ? destinations.value.length : 0

  return [
    {
      id: "connect_source",
      title: "Connect a source",
      description: "Link a Git host or container registry so Aegis can start scanning.",
      href: "/sources",
      done: sourcesCount > 0,
    },
    {
      id: "run_first_scan",
      title: "Run your first scan",
      description: "Trigger an initial scan from any connected source.",
      href: "/sources",
      // Proxy: any finding row at all (open or triaged) means scans have run.
      done: sourcesCount > 0 && openCount + triagedCount > 0,
    },
    {
      id: "triage_finding",
      title: "Triage a finding",
      description: "Open a finding from the inbox and mark it confirmed, dismissed, or fixed.",
      href: "/inbox",
      // Any fixed/dismissed finding proves triage happened. Lightweight — no
      // dedicated decisions roundtrip for the widget.
      done: triagedCount > 0,
    },
    {
      id: "set_sla_policy",
      title: "Set an SLA policy",
      description: "Pick the time-to-fix targets that match your team's expectations.",
      href: "/policies",
      done: slaSet,
    },
    {
      id: "add_notification",
      title: "Add a notification channel",
      description: "Route critical findings to Slack, a webhook, or email.",
      href: "/notifications",
      done: destinationsCount > 0,
    },
  ]
}

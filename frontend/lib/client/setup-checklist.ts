/** Derives onboarding-checklist task status from real reads against the relevant endpoints. */

import { listSourceConnections } from "./source-connections-api"
import { listDestinations } from "./destinations-api"
import { listFindingsSummary } from "./findings-api"
import { listRules } from "./rules-api"
import { getLlmConfig } from "./llm-settings-api"

export interface SetupTask {
  /** Stable id used as the localStorage key and for analytics. */
  id: "connect_source" | "run_first_scan" | "configure_llm" | "triage_finding" | "set_sla_policy" | "add_notification"
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
  const [sources, summary, rules, destinations, llm] = await Promise.allSettled([
    listSourceConnections(),
    listFindingsSummary(),
    listRules(),
    listDestinations(),
    getLlmConfig(),
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

  // getLlmConfig resolves to null when unconfigured (404) and rejects on 403;
  // either way an unconfigured/forbidden read leaves this step incomplete.
  const llmConfigured = llm.status === "fulfilled" && Boolean(llm.value?.configured)

  return [
    {
      id: "connect_source",
      title: "Connect a source",
      description: "Link a Git host or container registry so Aegis can start scanning.",
      href: "/sources",
      done: sourcesCount > 0,
    },
    {
      id: "configure_llm",
      title: "Set up LLM verification",
      description: "Add your model's API key and base URL so Aegis verifies findings and cuts false positives.",
      href: "/settings#llm",
      done: llmConfigured,
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

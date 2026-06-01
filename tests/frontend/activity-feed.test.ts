import test from "node:test"
import assert from "node:assert/strict"

// ---------------------------------------------------------------------------
// Tests for activity feed data-flow behaviour that doesn't require a DOM.
// Validates day grouping logic, API client composition, and load-more state
// that the ActivityFeed and ActivityPage components depend on.
// ---------------------------------------------------------------------------

// Minimal ActivityEvent shape
interface ActivityEvent {
  id: string
  type: string
  occurred_at: string
  actor: string | null
  repo_id: string | null
  summary: string
  payload: Record<string, unknown>
}

function makeEvent(
  id: string,
  type = "finding.created",
  isoDate = "2026-01-15T12:00:00+00:00",
): ActivityEvent {
  return { id, type, occurred_at: isoDate, actor: "alice@example.com", repo_id: null, summary: `Event ${id}`, payload: {} }
}

// ---------------------------------------------------------------------------
// Day grouping pure function (extracted logic, not the React component)
// ---------------------------------------------------------------------------

function dayLabel(isoString: string, nowMs: number): string {
  const date = new Date(isoString)
  const now = new Date(nowMs)
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const eventDay = new Date(date.getFullYear(), date.getMonth(), date.getDate())
  const diffMs = today.getTime() - eventDay.getTime()
  const diffDays = Math.round(diffMs / 86_400_000)
  if (diffDays === 0) return "Today"
  if (diffDays === 1) return "Yesterday"
  if (diffDays < 7) return `${diffDays} days ago`
  return date.toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric" })
}

function groupByDay(
  events: ActivityEvent[],
  nowMs: number,
): Array<{ label: string; events: ActivityEvent[] }> {
  const groups: Map<string, ActivityEvent[]> = new Map()
  for (const evt of events) {
    const label = dayLabel(evt.occurred_at, nowMs)
    const existing = groups.get(label)
    if (existing) {
      existing.push(evt)
    } else {
      groups.set(label, [evt])
    }
  }
  return Array.from(groups.entries()).map(([label, evts]) => ({ label, events: evts }))
}

// ---------------------------------------------------------------------------
// Day grouping tests — use local-time-aware date construction to avoid
// timezone-boundary mismatches when comparing day labels.
// ---------------------------------------------------------------------------

function localNoon(daysAgo: number): string {
  const d = new Date()
  d.setDate(d.getDate() - daysAgo)
  d.setHours(12, 0, 0, 0)
  return d.toISOString()
}

test("groupByDay: today events are labelled Today", () => {
  const now = Date.now()
  const events = [makeEvent("1", "finding.created", localNoon(0))]
  const groups = groupByDay(events, now)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].label, "Today")
  assert.equal(groups[0].events.length, 1)
})

test("groupByDay: yesterday events are labelled Yesterday", () => {
  const now = Date.now()
  const events = [makeEvent("1", "scan.completed", localNoon(1))]
  const groups = groupByDay(events, now)
  assert.equal(groups[0].label, "Yesterday")
})

test("groupByDay: 3-days-ago events labelled as N days ago", () => {
  const now = Date.now()
  const events = [makeEvent("1", "finding.fixed", localNoon(3))]
  const groups = groupByDay(events, now)
  assert.equal(groups[0].label, "3 days ago")
})

test("groupByDay: events on the same day are merged into one group", () => {
  const now = Date.now()
  const today = localNoon(0)
  const events = [
    makeEvent("1", "finding.created", today),
    makeEvent("2", "scan.completed", today),
    makeEvent("3", "finding.fixed", today),
  ]
  const groups = groupByDay(events, now)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].events.length, 3)
})

test("groupByDay: events on different days produce separate groups", () => {
  const now = Date.now()
  const events = [
    makeEvent("1", "finding.created", localNoon(0)),
    makeEvent("2", "scan.completed", localNoon(1)),
  ]
  const groups = groupByDay(events, now)
  assert.equal(groups.length, 2)
  assert.equal(groups[0].label, "Today")
  assert.equal(groups[1].label, "Yesterday")
})

test("groupByDay: empty events returns empty groups", () => {
  const now = Date.now()
  assert.deepEqual(groupByDay([], now), [])
})

// ---------------------------------------------------------------------------
// Filter toggle logic (extracted from page state)
// ---------------------------------------------------------------------------

function toggleType(activeTypes: string[], type: string): string[] {
  return activeTypes.includes(type)
    ? activeTypes.filter((t) => t !== type)
    : [...activeTypes, type]
}

test("filter toggle: adds a type when not present", () => {
  const result = toggleType([], "finding.created")
  assert.deepEqual(result, ["finding.created"])
})

test("filter toggle: removes a type when already present", () => {
  const result = toggleType(["finding.created", "scan.completed"], "finding.created")
  assert.deepEqual(result, ["scan.completed"])
})

test("filter toggle: preserves other types when removing one", () => {
  const result = toggleType(["finding.created", "scan.completed", "sla.breached"], "scan.completed")
  assert.deepEqual(result, ["finding.created", "sla.breached"])
})

// ---------------------------------------------------------------------------
// Pagination (load-more) composition
// ---------------------------------------------------------------------------

interface FetchCall { url: string }

function makeFetchMock(responses: unknown[]) {
  const calls: FetchCall[] = []
  let index = 0
  const mock = async (input: RequestInfo | URL): Promise<Response> => {
    const body = responses[Math.min(index, responses.length - 1)]
    calls.push({ url: input.toString() })
    index++
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  }
  return { mock, calls }
}

async function loadApi() {
  return import("../../lib/client/activity-api.ts")
}

test("load-more: second call includes cursor from first response", async () => {
  const page1 = {
    events: [makeEvent("1"), makeEvent("2")],
    next_cursor: "cursor-page2",
  }
  const page2 = { events: [makeEvent("3")], next_cursor: null }

  const { mock, calls } = makeFetchMock([page1, page2])
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadApi()

  const r1 = await listActivity({ limit: 2 })
  assert.equal(r1.next_cursor, "cursor-page2")

  const r2 = await listActivity({ limit: 2, cursor: r1.next_cursor! })
  assert.equal(r2.next_cursor, null)
  assert.equal(r2.events.length, 1)

  const url2 = new URL(calls[1].url, "http://localhost")
  assert.equal(url2.searchParams.get("cursor"), "cursor-page2")
})

test("load-more: no next_cursor means no more pages", async () => {
  const resp = { events: [makeEvent("1")], next_cursor: null }
  const { mock } = makeFetchMock([resp])
  globalThis.fetch = mock as unknown as typeof fetch

  const { listActivity } = await loadApi()
  const result = await listActivity({})
  assert.equal(result.next_cursor, null)
})

// ---------------------------------------------------------------------------
// Filter chip label helper
// ---------------------------------------------------------------------------

async function loadEventLabels() {
  return import("../../components/shared/activity/event-labels.ts")
}

test("eventTypeLabel returns human label for known types", async () => {
  const { eventTypeLabel } = await loadEventLabels()
  assert.equal(eventTypeLabel("finding.created"), "New findings")
  assert.equal(eventTypeLabel("scan.completed"), "Scans")
  assert.equal(eventTypeLabel("kev.added"), "KEV updates")
})

test("eventTypeLabel returns the raw type for unknown types", async () => {
  const { eventTypeLabel } = await loadEventLabels()
  assert.equal(eventTypeLabel("unknown.event"), "unknown.event")
})

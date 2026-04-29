"use client"

import type { HeartbeatEntry } from "./types"

interface HeartbeatGridProps {
  heartbeats: HeartbeatEntry[]
  intervalSeconds?: number
  windowMinutes?: number
}

export function HeartbeatGrid({
  heartbeats,
  intervalSeconds = 30,
  windowMinutes = 60,
}: HeartbeatGridProps) {
  const totalExpected = Math.floor((windowMinutes * 60) / intervalSeconds)
  const now = Date.now()
  const windowStart = now - windowMinutes * 60 * 1000

  // "unknown" = before first heartbeat, "received" = got heartbeat, "missed" = should have but didn't
  type SlotState = "unknown" | "received" | "missed"
  const slots: SlotState[] = Array(totalExpected).fill("unknown")

  // Find the first heartbeat to determine when the runner started
  let firstHbTime = Infinity
  for (const hb of heartbeats) {
    const ts = new Date(hb.receivedAt).getTime()
    if (ts < firstHbTime) firstHbTime = ts
    if (ts < windowStart) continue
    const slotIndex = Math.floor((ts - windowStart) / (intervalSeconds * 1000))
    if (slotIndex >= 0 && slotIndex < totalExpected) {
      slots[slotIndex] = "received"
    }
  }

  // Mark slots after first heartbeat as "missed" if not received
  if (firstHbTime < Infinity) {
    const firstSlot = Math.max(0, Math.floor((firstHbTime - windowStart) / (intervalSeconds * 1000)))
    for (let i = firstSlot; i < totalExpected; i++) {
      if (slots[i] === "unknown") slots[i] = "missed"
    }
  }

  const received = slots.filter((s) => s === "received").length
  const missed = slots.filter((s) => s === "missed").length

  let firstMissedTime = ""
  if (missed > 0) {
    const firstMissedIdx = slots.findIndex((s) => s === "missed")
    if (firstMissedIdx >= 0) {
      const missedTs = windowStart + firstMissedIdx * intervalSeconds * 1000
      firstMissedTime = new Date(missedTs).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-0.5">
        {slots.map((state, i) => (
          <div
            key={i}
            className={`h-2 w-2 rounded-sm ${
              state === "received" ? "bg-emerald-500" : state === "missed" ? "bg-red-400" : "bg-gray-700"
            }`}
            title={state === "received" ? "Received" : state === "missed" ? "Missed" : "Not running"}
          />
        ))}
      </div>
      <div className="flex items-center gap-3 text-xs text-[var(--color-text-secondary)]">
        <span>
          {received}/{totalExpected} received
          {missed > 0 && ` · ${missed} missed${firstMissedTime ? ` at ${firstMissedTime}` : ""}`}
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-sm bg-emerald-500" /> received
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-sm bg-red-400" /> missed
        </span>
      </div>
    </div>
  )
}

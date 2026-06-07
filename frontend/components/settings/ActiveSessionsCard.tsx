"use client"

import { useEffect, useState } from "react"

import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"

interface ParsedAgent {
  platform: string
  browser: string
}

function parseAgent(ua: string): ParsedAgent {
  const platform = /Macintosh/.test(ua)
    ? "macOS"
    : /Windows/.test(ua)
      ? "Windows"
      : /Linux/.test(ua)
        ? "Linux"
        : /iPhone|iPad/.test(ua)
          ? "iOS"
          : /Android/.test(ua)
            ? "Android"
            : "Unknown"
  const browserMatch =
    ua.match(/Edg\/(\d+)/) ||
    ua.match(/Chrome\/(\d+)/) ||
    ua.match(/Firefox\/(\d+)/) ||
    ua.match(/Version\/(\d+)/)
  let browser = "Browser"
  if (browserMatch) {
    if (/Edg\//.test(ua)) browser = `Edge ${browserMatch[1]}`
    else if (/Chrome\//.test(ua)) browser = `Chrome ${browserMatch[1]}`
    else if (/Firefox\//.test(ua)) browser = `Firefox ${browserMatch[1]}`
    else if (/Safari/.test(ua) && /Version\//.test(ua))
      browser = `Safari ${browserMatch[1]}`
  }
  return { platform, browser }
}

export function ActiveSessionsCard() {
  const [agent, setAgent] = useState<ParsedAgent | null>(null)

  useEffect(() => {
    if (typeof navigator !== "undefined") setAgent(parseAgent(navigator.userAgent))
  }, [])

  return (
    <SettingsCard heading="Sessions">
      <SettingsRow
        label={agent ? `${agent.platform} · ${agent.browser}` : "This device"}
        description="Active right now · this device"
      >
        <span className="rounded-sm bg-[var(--color-success-bg)] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.08em] text-[var(--color-success)]">
          Current
        </span>
      </SettingsRow>
      <SettingsRow
        label="Sign out all other devices"
        description="Useful if you lost a device or suspect a compromise. Other devices will appear here once multi-session tracking is enabled for your org."
      >
        <button
          type="button"
          className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-critical)] bg-[var(--color-critical)] px-3 py-1 text-xs font-semibold text-white hover:opacity-90"
        >
          Sign out everywhere
        </button>
      </SettingsRow>
    </SettingsCard>
  )
}

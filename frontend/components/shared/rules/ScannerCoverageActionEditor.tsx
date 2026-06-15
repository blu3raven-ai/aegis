"use client"

/**
 * Editor for the scanner-coverage action portion of a rule. Lets the
 * user pick one of two action shapes — require specific scanners or
 * alert when scans go stale — and edit the per-shape fields inline.
 *
 * Like SlaActionEditor, this editor is permissive: it surfaces inline
 * hints for invalid values but the parent modal owns the final
 * go/no-go validation before submit.
 */

import Link from "next/link"
import type {
  RequireScannersAction,
  ScannerCoverageAction,
  ScannerType,
  StaleAlertAction,
} from "@/lib/client/rules-api"
import type { NotificationDestination } from "@/lib/client/destinations-api"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"

const SCANNER_OPTIONS: { value: ScannerType; label: string }[] = [
  { value: "dependencies", label: "SCA / Dependencies" },
  { value: "code_scanning", label: "SAST / Code scanning" },
  { value: "container_scanning", label: "Container scanning" },
  { value: "secrets", label: "Secret detection" },
]

export const REQUIRE_DEFAULT: RequireScannersAction = {
  type: "require_scanners",
  required_scanners: ["dependencies"],
}

const STALE_DEFAULT: StaleAlertAction = {
  type: "stale_alert",
  stale_after_days: 7,
  alert_channel_id: 0,
  auto_retrigger: false,
}

interface ScannerCoverageActionEditorProps {
  value: ScannerCoverageAction
  destinations: NotificationDestination[]
  onChange: (next: ScannerCoverageAction) => void
}

export function ScannerCoverageActionEditor({
  value,
  destinations,
  onChange,
}: ScannerCoverageActionEditorProps) {
  function switchType(next: "require_scanners" | "stale_alert") {
    if (next === value.type) return
    onChange(next === "require_scanners" ? { ...REQUIRE_DEFAULT } : { ...STALE_DEFAULT })
  }

  return (
    <div className="space-y-5">
      <div
        role="radiogroup"
        aria-label="Scanner coverage action type"
        className="grid grid-cols-1 gap-2 sm:grid-cols-2"
      >
        <label className="cursor-pointer rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 has-[input:checked]:border-[var(--color-accent)] has-[input:checked]:bg-[var(--color-accent)]/5">
          <input
            type="radio"
            name="action-type"
            checked={value.type === "require_scanners"}
            onChange={() => switchType("require_scanners")}
            className="sr-only"
          />
          <div className="text-sm font-semibold text-[var(--color-text-primary)]">
            Require specific scanners
          </div>
          <div className="text-xs text-[var(--color-text-secondary)]">
            Open a gap when required scanners are missing.
          </div>
        </label>
        <label className="cursor-pointer rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 has-[input:checked]:border-[var(--color-accent)] has-[input:checked]:bg-[var(--color-accent)]/5">
          <input
            type="radio"
            name="action-type"
            checked={value.type === "stale_alert"}
            onChange={() => switchType("stale_alert")}
            className="sr-only"
          />
          <div className="text-sm font-semibold text-[var(--color-text-primary)]">
            Alert when scans go stale
          </div>
          <div className="text-xs text-[var(--color-text-secondary)]">
            Send a notification when scan age exceeds a threshold.
          </div>
        </label>
      </div>

      {value.type === "require_scanners" ? (
        <RequireScannersFields value={value} onChange={onChange} />
      ) : (
        <StaleAlertFields value={value} destinations={destinations} onChange={onChange} />
      )}
    </div>
  )
}

function RequireScannersFields({
  value,
  onChange,
}: {
  value: RequireScannersAction
  onChange: (next: RequireScannersAction) => void
}) {
  const selected = new Set(value.required_scanners)
  const showError = value.required_scanners.length === 0

  function toggle(scanner: ScannerType) {
    const next = new Set(selected)
    if (next.has(scanner)) next.delete(scanner)
    else next.add(scanner)
    onChange({ ...value, required_scanners: Array.from(next) as ScannerType[] })
  }

  return (
    <div>
      <label className="mb-2 block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Required scanners
      </label>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {SCANNER_OPTIONS.map((opt) => (
          <label
            key={opt.value}
            className="flex cursor-pointer items-center gap-2 rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)]"
          >
            <input
              type="checkbox"
              checked={selected.has(opt.value)}
              onChange={() => toggle(opt.value)}
              className="h-4 w-4 rounded border-[var(--color-border)] accent-[var(--color-accent)]"
            />
            <span>{opt.label}</span>
          </label>
        ))}
      </div>
      {showError && (
        <p className="mt-2 text-xs text-[var(--color-severity-critical)]">
          Select at least one scanner.
        </p>
      )}
    </div>
  )
}

function StaleAlertFields({
  value,
  destinations,
  onChange,
}: {
  value: StaleAlertAction
  destinations: NotificationDestination[]
  onChange: (next: StaleAlertAction) => void
}) {
  const enabledDestinations = destinations.filter((d) => d.enabled)
  const daysInvalid = !(
    Number.isInteger(value.stale_after_days) &&
    value.stale_after_days >= 1 &&
    value.stale_after_days <= 365
  )
  const channelInvalid = !enabledDestinations.some((d) => d.id === value.alert_channel_id)

  return (
    <div className="space-y-4">
      <div>
        <label
          htmlFor="stale-after-days"
          className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
        >
          Stale after
        </label>
        <div className="flex items-center gap-2">
          <Input
            id="stale-after-days"
            type="number"
            min={1}
            max={365}
            step={1}
            value={value.stale_after_days}
            onChange={(e) =>
              onChange({
                ...value,
                stale_after_days: Number.parseInt(e.target.value, 10) || 0,
              })
            }
            invalid={daysInvalid}
            className="w-24"
          />
          <span className="text-sm text-[var(--color-text-secondary)]">
            days without a completed scan
          </span>
        </div>
        {daysInvalid && (
          <p className="mt-1 text-xs text-[var(--color-severity-critical)]">
            Must be a whole number between 1 and 365.
          </p>
        )}
      </div>

      <div>
        <label
          htmlFor="stale-channel"
          className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
        >
          Notify channel
        </label>
        {enabledDestinations.length === 0 && (
          <p className="mb-2 text-xs text-[var(--color-text-tertiary)]">
            Set up a notification destination first →{" "}
            <Link
              href="/settings/notifications"
              className="text-[var(--color-accent)] underline-offset-2 hover:underline"
            >
              Notification destinations
            </Link>
          </p>
        )}
        <Select
          id="stale-channel"
          value={value.alert_channel_id || ""}
          onChange={(e) =>
            onChange({
              ...value,
              alert_channel_id: Number.parseInt(e.target.value, 10) || 0,
            })
          }
          invalid={channelInvalid}
        >
          <option value="">Select a destination…</option>
          {enabledDestinations.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name}
            </option>
          ))}
        </Select>
        {channelInvalid && (
          <p className="mt-1 text-xs text-[var(--color-severity-critical)]">
            Select a notification destination.
          </p>
        )}
      </div>

      <label className="flex cursor-pointer select-none items-center gap-2">
        <input
          type="checkbox"
          checked={value.auto_retrigger}
          onChange={(e) => onChange({ ...value, auto_retrigger: e.target.checked })}
          className="h-4 w-4 rounded border-[var(--color-border)] accent-[var(--color-accent)]"
        />
        <span className="text-sm text-[var(--color-text-primary)]">
          Also re-trigger a scan automatically
        </span>
      </label>
    </div>
  )
}

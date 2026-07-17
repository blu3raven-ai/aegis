"use client"

import { useState } from "react"
import type { NotificationDestination, CreateDestinationPayload, UpdateDestinationPayload } from "@/lib/client/destinations-api"
import { EventFilterBuilder, type EventFilter } from "./EventFilterBuilder"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Textarea } from "@/components/ui/Textarea"

export type DestinationFormValues = {
  name: string
  destination_type: "slack" | "webhook" | "email"
  enabled: boolean
  config: Record<string, unknown>
  event_filter: EventFilter
}

interface FormErrors {
  name?: string
  url?: string
  webhookUrl?: string
  toAddresses?: string
}

function validateUrl(url: string): boolean {
  try {
    const u = new URL(url)
    return u.protocol === "https:" || u.protocol === "http:"
  } catch {
    return false
  }
}

function validateEmail(addr: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr.trim())
}

interface DestinationFormProps {
  initial?: NotificationDestination | null
  onSubmit: (payload: CreateDestinationPayload | (UpdateDestinationPayload & { id: number })) => Promise<void>
  onCancel: () => void
  submitting?: boolean
}

export function DestinationForm({
  initial,
  onSubmit,
  onCancel,
  submitting = false,
}: DestinationFormProps) {
  const isEditing = !!initial

  const [name, setName] = useState(initial?.name ?? "")
  // Safe: DestinationDrawer gates entry to this form to EDITABLE_TYPES only,
  // so destination_type is always one of the three known values at runtime.
  const [type, setType] = useState<"slack" | "webhook" | "email">(
    (initial?.destination_type ?? "slack") as "slack" | "webhook" | "email",
  )
  const [enabled, setEnabled] = useState(initial?.enabled ?? true)
  const [slackUrl, setSlackUrl] = useState(
    (initial?.config?.webhook_url as string | undefined) ?? "",
  )
  const [webhookUrl, setWebhookUrl] = useState(
    (initial?.config?.url as string | undefined) ?? "",
  )
  const [webhookSecret, setWebhookSecret] = useState(
    (initial?.config?.secret as string | undefined) ?? "",
  )
  const [toAddresses, setToAddresses] = useState(
    ((initial?.config?.to_addresses as string[] | undefined) ?? []).join(", "),
  )
  const [eventFilter, setEventFilter] = useState<EventFilter>(
    initial?.event_filter ?? {},
  )
  const [errors, setErrors] = useState<FormErrors>({})

  function validate(): boolean {
    const next: FormErrors = {}
    if (!name.trim()) next.name = "Name is required"
    if (type === "slack") {
      if (!slackUrl.trim()) {
        next.webhookUrl = "Slack webhook URL is required"
      } else if (!validateUrl(slackUrl)) {
        next.webhookUrl = "Must be a valid URL"
      }
    }
    if (type === "webhook") {
      if (!webhookUrl.trim()) {
        next.url = "Webhook URL is required"
      } else if (!validateUrl(webhookUrl)) {
        next.url = "Must be a valid URL"
      }
    }
    if (type === "email") {
      const addrs = toAddresses
        .split(/[\n,]+/)
        .map((a) => a.trim())
        .filter(Boolean)
      if (addrs.length === 0) {
        next.toAddresses = "At least one email address is required"
      } else {
        const bad = addrs.find((a) => !validateEmail(a))
        if (bad) next.toAddresses = `Invalid email: ${bad}`
      }
    }
    setErrors(next)
    return Object.keys(next).length === 0
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!validate()) return

    let config: Record<string, unknown> = {}
    if (type === "slack") config = { webhook_url: slackUrl.trim() }
    if (type === "webhook") {
      config = { url: webhookUrl.trim() }
      if (webhookSecret.trim()) config.secret = webhookSecret.trim()
    }
    if (type === "email") {
      config = {
        to_addresses: toAddresses
          .split(/[\n,]+/)
          .map((a) => a.trim())
          .filter(Boolean),
      }
    }

    if (isEditing && initial) {
      await onSubmit({
        id: initial.id,
        name: name.trim(),
        config,
        enabled,
        event_filter: eventFilter,
      })
    } else {
      await onSubmit({
        destination_type: type,
        name: name.trim(),
        config,
        enabled,
        event_filter: eventFilter,
      })
    }
  }

  const eyebrowClass =
    "block text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-1.5"

  return (
    <form onSubmit={(e) => { void handleSubmit(e) }} className="space-y-5">
      {/* Name */}
      <FormField label="Name" htmlFor="dest-name" error={errors.name}>
        <Input
          id="dest-name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Security alerts"
          autoComplete="off"
          invalid={!!errors.name}
        />
      </FormField>

      {/* Type — locked in edit mode */}
      {!isEditing && (
        <div>
          <label className={eyebrowClass}>Destination type</label>
          <div className="flex gap-2">
            {(["slack", "webhook", "email"] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setType(t)}
                className={`flex-1 rounded-md border px-3 py-2 text-sm font-medium capitalize transition-colors ${
                  type === t
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-accent)]/40 hover:text-[var(--color-text-primary)]"
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Per-type config */}
      {type === "slack" && (
        <FormField
          label="Slack webhook URL"
          htmlFor="dest-slack-url"
          error={errors.webhookUrl}
        >
          <Input
            id="dest-slack-url"
            type="url"
            value={slackUrl}
            onChange={(e) => setSlackUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            invalid={!!errors.webhookUrl}
          />
        </FormField>
      )}

      {type === "webhook" && (
        <>
          <FormField label="Webhook URL" htmlFor="dest-webhook-url" error={errors.url}>
            <Input
              id="dest-webhook-url"
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://example.com/hooks/aegis"
              invalid={!!errors.url}
            />
          </FormField>
          <FormField
            label={<>Signing secret <span className="font-normal text-[var(--color-text-tertiary)]">(optional)</span></>}
            htmlFor="dest-webhook-secret"
            hint="When set, Aegis signs payloads using HMAC-SHA256."
          >
            <Input
              id="dest-webhook-secret"
              type="password"
              value={webhookSecret}
              onChange={(e) => setWebhookSecret(e.target.value)}
              placeholder="Optional HMAC-SHA256 secret"
              autoComplete="new-password"
            />
          </FormField>
        </>
      )}

      {type === "email" && (
        <FormField
          label="Recipients"
          htmlFor="dest-email-addrs"
          hint={errors.toAddresses ? undefined : "Comma- or newline-separated email addresses."}
          error={errors.toAddresses}
        >
          <Textarea
            id="dest-email-addrs"
            value={toAddresses}
            onChange={(e) => setToAddresses(e.target.value)}
            placeholder={"security@example.com, oncall@example.com"}
            rows={3}
            className="resize-none"
            invalid={!!errors.toAddresses}
          />
        </FormField>
      )}

      {/* Event filter */}
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
        <p className="mb-3 text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          Event filter
        </p>
        <EventFilterBuilder value={eventFilter} onChange={setEventFilter} />
      </div>

      {/* Enabled toggle */}
      <label className="flex cursor-pointer items-center gap-3">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
          className="h-4 w-4 accent-[var(--color-accent)]"
        />
        <span className="text-sm text-[var(--color-text-primary)]">Enabled</span>
      </label>

      {/* Actions */}
      <div className="flex items-center justify-end gap-2 border-t border-[var(--color-border)] pt-4">
        <Button
          variant="secondary"
          size="md"
          onClick={onCancel}
          disabled={submitting}
        >
          Cancel
        </Button>
        <Button
          type="submit"
          variant="primary"
          size="md"
          disabled={submitting}
          isLoading={submitting}
        >
          {submitting ? "Saving…" : isEditing ? "Save changes" : "Add destination"}
        </Button>
      </div>
    </form>
  )
}

"use client";
import Link from "next/link";
import { cn } from "@/lib/shared/utils";
import type { Integration } from "@/lib/client/integrations-catalog-api";
import { IntegrationLogoMark } from "./IntegrationLogo";

const STATUS_BADGE: Record<Integration["status"], string> = {
  stable:
    "bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok-text)]",
  beta:
    "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]",
  preview:
    "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]",
  deprecated:
    "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
};

const CATEGORY_LABEL: Record<string, string> = {
  cicd: "CI/CD",
  notifications: "Notifications",
  ticketing: "Ticketing",
  automation: "Automation",
  runner: "Runner",
};

interface IntegrationCardProps {
  i: Integration;
  /** Fired when an inline-setup integration is clicked. Items with `href` navigate via the underlying Link instead. */
  onSelect?: (i: Integration) => void;
}

export function IntegrationCard({ i, onSelect }: IntegrationCardProps) {
  const ctaLabel = i.href ? "Open" : "Setup";
  return (
    <Link
      href={i.href ?? `/integrations/${i.slug}`}
      onClick={event => {
        if (i.href || !onSelect) return;
        event.preventDefault();
        onSelect(i);
      }}
      className={cn(
        "group relative flex h-full flex-col rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-5 text-left transition-all",
        "hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-raised)] hover:shadow-[var(--shadow-card)]",
        "focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]",
      )}
    >
      <div className="mb-3 flex items-start justify-between gap-3">
        <div
          aria-hidden="true"
          className="flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
        >
          <IntegrationLogoMark iconSlug={i.iconSlug} name={i.name} className="h-[18px] w-[18px]" />
        </div>
        <span
          aria-label={`Status: ${i.status}`}
          className={cn(
            "rounded px-1.5 py-0.5 text-2xs font-mono font-semibold uppercase tracking-[0.14em]",
            STATUS_BADGE[i.status],
          )}
        >
          {i.status}
        </span>
      </div>

      <h3 className="mb-1 text-base font-semibold text-[var(--color-text-primary)]">{i.name}</h3>
      <p className="mb-4 flex-1 text-sm leading-relaxed text-[var(--color-text-secondary)]">
        {i.description}
      </p>

      <div className="flex items-center justify-between gap-3 border-t border-[var(--color-border)] pt-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-2xs font-mono font-semibold uppercase tracking-[0.06em] tabular-nums text-[var(--color-text-tertiary)]">
            {i.version}
          </span>
          <span className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-2xs font-mono font-semibold uppercase tracking-[0.06em] text-[var(--color-text-tertiary)]">
            {CATEGORY_LABEL[i.category] ?? i.category}
          </span>
        </div>
        <span className="shrink-0 text-xs font-semibold text-[var(--color-accent)] transition-transform group-hover:translate-x-0.5">
          {ctaLabel} →
        </span>
      </div>
    </Link>
  );
}

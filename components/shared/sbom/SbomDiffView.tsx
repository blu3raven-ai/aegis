"use client"

import { useState } from "react"
import type { SbomDiffResponse, SbomComponent, SbomVersionChange } from "@/lib/client/sbom-diff-api"

function ChevronIcon({ expanded }: { expanded: boolean }) {
  return (
    <svg
      className={`h-4 w-4 shrink-0 transition-transform ${expanded ? "rotate-90" : ""}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M9 18l6-6-6-6" />
    </svg>
  )
}

function SectionHeader({
  label,
  count,
  color,
  expanded,
  onToggle,
}: {
  label: string
  count: number
  color: string
  expanded: boolean
  onToggle: () => void
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
    >
      <ChevronIcon expanded={expanded} />
      <span className="text-[12px] font-semibold text-[var(--color-text-primary)]">{label}</span>
      <span
        className={`ml-1 rounded-full px-2 py-px font-mono text-2xs font-semibold ${color}`}
      >
        {count}
      </span>
    </button>
  )
}

function ComponentRow({ component }: { component: SbomComponent }) {
  return (
    <li className="flex items-baseline gap-2 py-1 pl-8 text-[12px]">
      <span className="h-1.5 w-1.5 shrink-0 translate-y-[2px] rounded-full bg-[var(--color-text-tertiary)]" />
      <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">
        {component.name}
      </span>
      {component.version && (
        <span className="text-[var(--color-text-tertiary)]">@{component.version}</span>
      )}
    </li>
  )
}

function VersionChangeRow({ change }: { change: SbomVersionChange }) {
  return (
    <li className="flex items-baseline gap-2 py-1 pl-8 text-[12px]">
      <span className="h-1.5 w-1.5 shrink-0 translate-y-[2px] rounded-full bg-[var(--color-text-tertiary)]" />
      <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">
        {change.name}
      </span>
      <span className="text-[var(--color-text-tertiary)]">
        {change.from_version ?? "?"}
        {" → "}
        {change.to_version ?? "?"}
      </span>
    </li>
  )
}

function EmptyCategory({ message }: { message: string }) {
  return (
    <p className="py-2 pl-8 text-[12px] text-[var(--color-text-tertiary)]">{message}</p>
  )
}

interface SectionState {
  packages: boolean
}

export function SbomDiffView({ diff }: { diff: SbomDiffResponse }) {
  const [packagesOpen, setPackagesOpen] = useState(true)
  const [addedOpen, setAddedOpen] = useState(true)
  const [removedOpen, setRemovedOpen] = useState(true)
  const [bumpsOpen, setBumpsOpen] = useState(true)

  const totalChanges =
    diff.added.length + diff.removed.length + diff.version_changed.length

  return (
    <div className="flex flex-col gap-0 divide-y divide-[var(--color-border)] rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
      {/* Summary bar */}
      <div className="flex flex-wrap gap-4 px-4 py-3">
        <span className="text-[12px] text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-text-primary)]">
            {totalChanges}
          </span>{" "}
          package change{totalChanges !== 1 ? "s" : ""}
        </span>
        <span className="text-[12px] text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-status-ok)]">
            +{diff.added.length}
          </span>{" "}
          added
        </span>
        <span className="text-[12px] text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-status-critical)]">
            -{diff.removed.length}
          </span>{" "}
          removed
        </span>
        <span className="text-[12px] text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-accent)]">
            {diff.version_changed.length}
          </span>{" "}
          version bumps
        </span>
        <span className="text-[12px] text-[var(--color-text-secondary)]">
          <span className="font-semibold tabular-nums text-[var(--color-text-tertiary)]">
            {diff.unchanged_count}
          </span>{" "}
          unchanged
        </span>
      </div>

      {/* Packages section */}
      <div className="px-2 py-2">
        <SectionHeader
          label="Packages"
          count={totalChanges}
          color="bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
          expanded={packagesOpen}
          onToggle={() => setPackagesOpen((v) => !v)}
        />

        {packagesOpen && (
          <div className="mt-1 flex flex-col">
            {/* Added */}
            <SectionHeader
              label="Added"
              count={diff.added.length}
              color="bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok)]"
              expanded={addedOpen}
              onToggle={() => setAddedOpen((v) => !v)}
            />
            {addedOpen && (
              <ul>
                {diff.added.length === 0 ? (
                  <EmptyCategory message="No packages added" />
                ) : (
                  diff.added.map((c) => (
                    <ComponentRow key={`${c.name}@${c.version}`} component={c} />
                  ))
                )}
              </ul>
            )}

            {/* Removed */}
            <SectionHeader
              label="Removed"
              count={diff.removed.length}
              color="bg-[var(--color-status-critical)]/10 text-[var(--color-status-critical)]"
              expanded={removedOpen}
              onToggle={() => setRemovedOpen((v) => !v)}
            />
            {removedOpen && (
              <ul>
                {diff.removed.length === 0 ? (
                  <EmptyCategory message="No packages removed" />
                ) : (
                  diff.removed.map((c) => (
                    <ComponentRow key={`${c.name}@${c.version}`} component={c} />
                  ))
                )}
              </ul>
            )}

            {/* Version bumps */}
            <SectionHeader
              label="Version bumps"
              count={diff.version_changed.length}
              color="bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
              expanded={bumpsOpen}
              onToggle={() => setBumpsOpen((v) => !v)}
            />
            {bumpsOpen && (
              <ul>
                {diff.version_changed.length === 0 ? (
                  <EmptyCategory message="No version bumps" />
                ) : (
                  diff.version_changed.map((c) => (
                    <VersionChangeRow key={`${c.name}-${c.from_version}-${c.to_version}`} change={c} />
                  ))
                )}
              </ul>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

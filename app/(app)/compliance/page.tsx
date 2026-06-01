"use client"

import { useState, useEffect } from "react"
import { FrameworkSelector } from "@/components/shared/compliance/FrameworkSelector"
import { ControlsSummaryTable } from "@/components/shared/compliance/ControlsSummaryTable"
import { PageHeader } from "@/components/layout/PageHeader"
import { ComplianceIcon } from "@/lib/shared/ui/page-icons"
import {
  listFrameworks,
  getFrameworkSummary,
  type ComplianceFramework,
  type ControlSummaryItem,
} from "@/lib/client/compliance-api"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

type LoadState = "loading" | "ok" | "error"

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([])
  const [selectedFramework, setSelectedFramework] = useState<string>("")
  const [controls, setControls] = useState<ControlSummaryItem[]>([])
  const [loadState, setLoadState] = useState<LoadState>("loading")

  useEffect(() => {
    listFrameworks()
      .then((fws) => {
        setFrameworks(fws)
        if (fws.length > 0) setSelectedFramework(fws[0].id)
      })
      .catch(() => setLoadState("error"))
  }, [])

  useEffect(() => {
    if (!selectedFramework) return
    setLoadState("loading")
    getFrameworkSummary(selectedFramework, ORG_ID)
      .then((items) => {
        setControls(items)
        setLoadState("ok")
      })
      .catch(() => setLoadState("error"))
  }, [selectedFramework])

  const atRiskCount = controls.filter((c) => c.finding_count > 0 || c.chain_count > 0).length

  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]">
      <PageHeader
        icon={<ComplianceIcon />}
        title="Compliance"
        description="Findings and attack chains mapped to compliance controls."
        controls={
          <FrameworkSelector
            frameworks={frameworks}
            selected={selectedFramework}
            onChange={setSelectedFramework}
          />
        }
      />

      <div className="flex flex-col gap-6 p-6">

      {/* Summary chips */}
      {loadState === "ok" && (
        <div className="flex flex-wrap gap-3">
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2">
            <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-secondary)]">
              Total Controls
            </div>
            <div className="mt-0.5 text-[22px] font-bold text-[var(--color-text-primary)]">
              {controls.length}
            </div>
          </div>
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2">
            <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-secondary)]">
              At Risk
            </div>
            <div
              className={`mt-0.5 text-[22px] font-bold ${atRiskCount > 0 ? "text-[var(--color-severity-critical)]" : "text-[var(--color-text-primary)]"}`}
            >
              {atRiskCount}
            </div>
          </div>
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2">
            <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-secondary)]">
              Compliant
            </div>
            <div className="mt-0.5 text-[22px] font-bold text-[var(--color-status-ok)]">
              {controls.length - atRiskCount}
            </div>
          </div>
        </div>
      )}

      {/* Controls table */}
      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[var(--shadow-card)]">
        {loadState === "loading" && (
          <div className="flex items-center justify-center py-12 text-[13px] text-[var(--color-text-secondary)]">
            Loading controls…
          </div>
        )}
        {loadState === "error" && (
          <div className="flex items-center justify-center py-12 text-[13px] text-[var(--color-severity-critical)]">
            Failed to load compliance data.
          </div>
        )}
        {loadState === "ok" && (
          <ControlsSummaryTable controls={controls} framework={selectedFramework} />
        )}
      </div>
      </div>
    </div>
  )
}

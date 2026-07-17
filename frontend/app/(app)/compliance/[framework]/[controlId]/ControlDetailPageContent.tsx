"use client"

import { useState, useEffect, useCallback } from "react"
import { useParams } from "next/navigation"

import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { AddMappingSheet } from "@/components/shared/compliance/AddMappingSheet"
import { ControlDetailHero } from "@/components/shared/compliance/ControlDetailHero"
import { MappingsList } from "@/components/shared/compliance/MappingsList"
import {
  listFrameworkControls,
  getControlFindings,
  getFrameworkSummary,
  setMappingSuppressed,
  type FrameworkControl,
  type ComplianceFindingBrief,
  type ControlSummaryItem,
} from "@/lib/client/compliance-api"
import { useHasPermission } from "@/lib/client/use-permission"
import { AttestationPanel } from "./AttestationPanel"

type LoadState = "loading" | "ok" | "error"

// Plain-language explanation of how the control's effective status was reached —
// a manual attestation wins, otherwise it's derived from open mapped findings.
function statusReason(
  item: ControlSummaryItem | null,
  openCount: number,
  highestSeverity: string | null,
): string {
  if (item?.manual_status) {
    return `Manually attested ${item.manual_status.replace(/_/g, " ")} — this overrides the finding-derived status.`
  }
  if (openCount === 0) return "No open findings map to this control — derived as compliant."
  if (highestSeverity === "critical" || highestSeverity === "high") {
    return `${openCount} open finding${openCount === 1 ? "" : "s"} mapped (highest: ${highestSeverity}) — derived as at risk.`
  }
  return `${openCount} open finding${openCount === 1 ? "" : "s"} mapped (highest: ${highestSeverity ?? "low"}) — derived as partial.`
}

export function ControlDetailPageContent() {
  const params = useParams<{ framework: string; controlId: string }>()
  const framework = params.framework
  const controlId = params.controlId

  const [control, setControl] = useState<FrameworkControl | null>(null)
  const [findings, setFindings] = useState<ComplianceFindingBrief[]>([])
  const [summaryItem, setSummaryItem] = useState<ControlSummaryItem | null>(null)
  const [loadState, setLoadState] = useState<LoadState>("loading")
  const [showAdd, setShowAdd] = useState(false)

  const load = useCallback(
    (opts?: { silent?: boolean }) => {
      if (!framework || !controlId) return
      if (!opts?.silent) setLoadState("loading")
      Promise.all([
        listFrameworkControls(framework),
        getControlFindings(framework, controlId),
        getFrameworkSummary(framework),
      ])
        .then(([controls, findingsResp, summary]) => {
          const found = controls.find((c) => c.control_id === controlId) ?? null
          setControl(found)
          setFindings(findingsResp.findings)
          setSummaryItem(summary.find((c) => c.control_id === controlId) ?? null)
          setLoadState("ok")
        })
        .catch(() => {
          if (!opts?.silent) setLoadState("error")
        })
    },
    [framework, controlId],
  )

  useEffect(() => {
    load()
  }, [load])

  const { allowed: canManage } = useHasPermission("manage_settings")

  async function handleToggleSuppress(
    mappingId: number,
    suppressed: boolean,
    reason?: string | null,
  ) {
    await setMappingSuppressed(mappingId, { suppressed, reason })
    load({ silent: true })
  }

  // The full mapped set (incl. suppressed) is shown in the list; the hero +
  // status reflect only active mappings, matching how the control is scored.
  const mappedFindings = findings.filter((f) => f.state === "open")
  const activeFindings = mappedFindings.filter((f) => !f.suppressed)
  const highestSeverity = (() => {
    const order = ["critical", "high", "medium", "low"]
    for (const sev of order) {
      if (activeFindings.some((f) => f.severity === sev)) return sev
    }
    return null
  })()

  const notFound = loadState === "ok" && !control

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Breadcrumb lives in the AppHeader (single source of truth) — no in-page
          duplicate here. */}
      {loadState === "loading" && (
        <div className="flex items-center justify-center py-16 text-sm text-[var(--color-text-secondary)]">
          Loading control…
        </div>
      )}

      {loadState === "error" && (
        <Card padding="none" className="rounded-md px-6 py-8 text-center">
          <p className="text-sm font-semibold text-[var(--color-text-primary)]">
            Couldn&apos;t load control data
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            The compliance service may be temporarily unavailable.
          </p>
          <div className="mt-4">
            <Button variant="secondary" size="sm" onClick={() => load()}>
              Retry
            </Button>
          </div>
        </Card>
      )}

      {notFound && (
        <Card padding="none" className="rounded-md px-6 py-8 text-center">
          <p className="text-sm font-semibold text-[var(--color-text-primary)]">
            Control not found
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            No control matching &quot;{controlId}&quot; exists in this framework.
          </p>
        </Card>
      )}

      {loadState === "ok" && control && (
        <>
          <ControlDetailHero
            framework={framework}
            controlId={controlId}
            title={control?.title ?? controlId}
            description={control?.description}
            category={control?.category}
            findingCount={activeFindings.length}
            highestSeverity={highestSeverity}
          />

          <AttestationPanel
            framework={framework}
            controlId={controlId}
            assessment={summaryItem}
            onSaved={() => load({ silent: true })}
          />

          {/* Findings section */}
          <Card padding="none" elevation="sm" className="rounded-md">
            <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] px-5 py-3">
              <div className="min-w-0">
                <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
                  Mapped Findings
                  {activeFindings.length > 0 && (
                    <span className="ml-2 rounded-full bg-[var(--color-severity-critical-subtle)] px-2 py-0.5 text-2xs font-semibold text-[var(--color-severity-critical-text)]">
                      {activeFindings.length}
                    </span>
                  )}
                </h2>
                {/* Make the pass/fail logic explicit — auditors shouldn't have to
                    reverse-engineer why a control is in its current state. */}
                <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
                  {statusReason(summaryItem, activeFindings.length, highestSeverity)}
                </p>
              </div>
              {canManage && (
                <Button
                  variant="secondary"
                  size="xs"
                  className="shrink-0"
                  onClick={() => setShowAdd(true)}
                >
                  Map finding
                </Button>
              )}
            </div>
            <div className="px-5 py-4">
              <MappingsList
                findings={mappedFindings}
                canManage={canManage}
                onToggleSuppress={handleToggleSuppress}
              />
            </div>
          </Card>

          {canManage && (
            <AddMappingSheet
              open={showAdd}
              framework={framework}
              controlId={controlId}
              onClose={() => setShowAdd(false)}
              onAdded={() => load({ silent: true })}
            />
          )}
        </>
      )}
    </div>
  )
}

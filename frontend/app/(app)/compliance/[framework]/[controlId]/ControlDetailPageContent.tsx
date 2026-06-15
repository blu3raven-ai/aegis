"use client"

import { useState, useEffect, useCallback } from "react"
import { useParams } from "next/navigation"

import Link from "next/link"
import { ControlDetailHero } from "@/components/shared/compliance/ControlDetailHero"
import { MappingsList } from "@/components/shared/compliance/MappingsList"
import {
  listFrameworkControls,
  getControlFindings,
  type FrameworkControl,
  type ComplianceFindingBrief,
} from "@/lib/client/compliance-api"

type LoadState = "loading" | "ok" | "error"

export function ControlDetailPageContent() {
  const params = useParams<{ framework: string; controlId: string }>()
  const framework = params.framework
  const controlId = decodeURIComponent(params.controlId)

  const [control, setControl] = useState<FrameworkControl | null>(null)
  const [findings, setFindings] = useState<ComplianceFindingBrief[]>([])
  const [loadState, setLoadState] = useState<LoadState>("loading")

  const load = useCallback(() => {
    if (!framework || !controlId) return
    setLoadState("loading")
    Promise.all([
      listFrameworkControls(framework),
      getControlFindings(framework, controlId),
    ])
      .then(([controls, findingsResp]) => {
        const found = controls.find((c) => c.control_id === controlId) ?? null
        setControl(found)
        setFindings(findingsResp.findings)
        setLoadState("ok")
      })
      .catch(() => setLoadState("error"))
  }, [framework, controlId])

  useEffect(() => {
    load()
  }, [load])

  const openFindings = findings.filter((f) => f.state === "open")
  const highestSeverity = (() => {
    const order = ["critical", "high", "medium", "low"]
    for (const sev of order) {
      if (openFindings.some((f) => f.severity === sev)) return sev
    }
    return null
  })()

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-1.5 text-xs text-[var(--color-text-secondary)]">
        <Link href="/compliance" className="hover:text-[var(--color-text-primary)] hover:underline">
          Compliance
        </Link>
        <span>/</span>
        <span className="capitalize">{framework}</span>
        <span>/</span>
        <span className="font-medium text-[var(--color-text-primary)]">{controlId}</span>
      </nav>

      {loadState === "loading" && (
        <div className="flex items-center justify-center py-16 text-sm text-[var(--color-text-secondary)]">
          Loading control…
        </div>
      )}

      {loadState === "error" && (
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-8 text-center">
          <p className="text-sm font-semibold text-[var(--color-text-primary)]">
            Couldn&apos;t load control data
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            The compliance service may be temporarily unavailable.
          </p>
          <button
            type="button"
            onClick={load}
            className="mt-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)]"
          >
            Retry
          </button>
        </div>
      )}

      {loadState === "ok" && (
        <>
          <ControlDetailHero
            framework={framework}
            controlId={controlId}
            title={control?.title ?? controlId}
            description={control?.description}
            category={control?.category}
            findingCount={openFindings.length}
            chainCount={0}
            highestSeverity={highestSeverity}
          />

          {/* Findings section */}
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)]">
            <div className="border-b border-[var(--color-border)] px-5 py-3">
              <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
                Mapped Findings
                {openFindings.length > 0 && (
                  <span className="ml-2 rounded-full bg-[var(--color-severity-critical-subtle)] px-2 py-0.5 text-[11px] font-semibold text-[var(--color-severity-critical)]">
                    {openFindings.length}
                  </span>
                )}
              </h2>
            </div>
            <div className="px-5 py-4">
              <MappingsList findings={openFindings} />
            </div>
          </div>
        </>
      )}
    </div>
  )
}

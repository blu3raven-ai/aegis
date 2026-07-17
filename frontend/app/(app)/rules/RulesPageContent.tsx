"use client"

import { useEffect, useRef, useState } from "react"
import { PageHeader } from "@/components/layout/PageHeader"
import { RulesIcon } from "@/lib/shared/ui/page-icons"
import { RulesSummaryStrip } from "@/components/shared/rules/RulesSummaryStrip"
import { RuleCategorySection } from "@/components/shared/rules/RuleCategorySection"
import { RuleEditorModal } from "@/components/shared/rules/RuleEditorModal"
import {
  createRule,
  deleteRule,
  disengageKillSwitch,
  engageKillSwitch,
  getRulesSummary,
  listKillSwitches,
  listRules,
  toggleRule,
  updateRule,
} from "@/lib/client/rules-api"
import type {
  CreateRulePayload,
  EditableRuleCategory,
  KillSwitch,
  RuleCategory,
  RuleSummary,
  RuleSummaryStats,
  UpdateRulePayload,
} from "@/lib/client/rules-api"
import { listDestinations } from "@/lib/client/destinations-api"
import type { NotificationDestination } from "@/lib/client/destinations-api"
import { useSession } from "@/lib/client/use-session"
import { can } from "@/lib/shared/auth/roles"
import { timeAgo } from "@/lib/shared/time-ago"
import { KillSwitchDialog } from "@/components/shared/rules/KillSwitchDialog"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

function SlaIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      style={{ width: 16, height: 16 }}
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6v6l4 2" />
    </svg>
  )
}

function ScannerIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      style={{ width: 16, height: 16 }}
    >
      <circle cx="11" cy="11" r="7" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  )
}

function DismissIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      style={{ width: 16, height: 16 }}
    >
      <path d="M6 18L18 6M6 6l12 12" />
    </svg>
  )
}

function AlertOctagonIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      style={{ width: 18, height: 18 }}
      aria-hidden
    >
      <path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86L7.86 2Z" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  )
}

function RetentionIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      style={{ width: 16, height: 16 }}
    >
      <path d="M3 7h18v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7Z" />
      <path d="M3 7l2-3h6l2 3" />
    </svg>
  )
}

export function RulesPageContent() {
  const { user } = useSession()
  const canManageSla = user ? can(user.role as any, "manage_sla_rules") : false
  const canManageScannerCoverage = user
    ? can(user.role as any, "manage_scanner_coverage_rules")
    : false
  const canManageAutoDismiss = user
    ? can(user.role as any, "manage_auto_dismiss_rules")
    : false
  const canManageDataRetention = user
    ? can(user.role as any, "manage_data_retention_rules")
    : false

  const [slaRules, setSlaRules] = useState<RuleSummary[] | null>(null)
  const [scannerCoverageRules, setScannerCoverageRules] = useState<RuleSummary[] | null>(null)
  const [autoDismissRules, setAutoDismissRules] = useState<RuleSummary[] | null>(null)
  const [dataRetentionRules, setDataRetentionRules] = useState<RuleSummary[] | null>(null)
  const [killSwitches, setKillSwitches] = useState<KillSwitch[]>([])
  const [stats, setStats] = useState<RuleSummaryStats | null>(null)
  const [loading, setLoading] = useState(true)

  const [destinations, setDestinations] = useState<NotificationDestination[]>([])

  const [editorOpen, setEditorOpen] = useState(false)
  const [editorMode, setEditorMode] = useState<"create" | "edit">("create")
  const [editorCategory, setEditorCategory] = useState<EditableRuleCategory>("sla")
  const [editorRule, setEditorRule] = useState<RuleSummary | null>(null)
  const [editorSaving, setEditorSaving] = useState(false)
  const [editorError, setEditorError] = useState<string | null>(null)

  const [killSwitchDialogOpen, setKillSwitchDialogOpen] = useState(false)
  const [killSwitchSaving, setKillSwitchSaving] = useState(false)
  const [killSwitchError, setKillSwitchError] = useState<string | null>(null)

  // cancelledRef lets mutation-triggered reloads bail out if the component
  // unmounts between the mutation completing and the reload settling.
  const cancelledRef = useRef(false)

  useEffect(() => {
    let cancelled = false
    listDestinations()
      .then((ds) => {
        if (!cancelled) setDestinations(ds)
      })
      .catch((err) => {
        console.error("Failed to load destinations", err)
      })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    cancelledRef.current = false
    let cancelled = false
    const run = async () => {
      setLoading(true)
      try {
        const [s, slaList, coverageList, autoList, retentionList, ks] = await Promise.all([
          getRulesSummary(),
          listRules({ category: "sla" }),
          listRules({ category: "scanner_coverage" }),
          listRules({ category: "auto_dismiss" }),
          listRules({ category: "data_retention" }),
          listKillSwitches(),
        ])
        if (cancelled) return
        setStats(s)
        setSlaRules(slaList)
        setScannerCoverageRules(coverageList)
        setAutoDismissRules(autoList)
        setDataRetentionRules(retentionList)
        setKillSwitches(ks)
      } catch (err) {
        if (cancelled) return
        console.error("Failed to load rules", err)
        // Preserve existing lists on transient reload failures; only fall back
        // to [] on the very first load where prev is still null.
        setSlaRules((prev) => prev ?? [])
        setScannerCoverageRules((prev) => prev ?? [])
        setAutoDismissRules((prev) => prev ?? [])
        setDataRetentionRules((prev) => prev ?? [])
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    void run()
    return () => {
      cancelled = true
      cancelledRef.current = true
    }
  }, [])

  const reload = async () => {
    setLoading(true)
    try {
      const [s, slaList, coverageList, autoList, retentionList, ks] = await Promise.all([
        getRulesSummary(),
        listRules({ category: "sla" }),
        listRules({ category: "scanner_coverage" }),
        listRules({ category: "auto_dismiss" }),
        listRules({ category: "data_retention" }),
        listKillSwitches(),
      ])
      if (cancelledRef.current) return
      setStats(s)
      setSlaRules(slaList)
      setScannerCoverageRules(coverageList)
      setAutoDismissRules(autoList)
      setDataRetentionRules(retentionList)
      setKillSwitches(ks)
    } catch (err) {
      if (cancelledRef.current) return
      console.error("Failed to load rules", err)
      setSlaRules((prev) => prev ?? [])
      setScannerCoverageRules((prev) => prev ?? [])
      setAutoDismissRules((prev) => prev ?? [])
      setDataRetentionRules((prev) => prev ?? [])
    } finally {
      if (!cancelledRef.current) setLoading(false)
    }
  }

  async function handleToggle(rule: RuleSummary) {
    try {
      await toggleRule(rule.id)
      await reload()
    } catch (err) {
      console.error("Failed to toggle rule", err)
    }
  }

  async function handleDelete(rule: RuleSummary) {
    try {
      await deleteRule(rule.id)
      await reload()
    } catch (err) {
      console.error("Failed to delete rule", err)
    }
  }

  function handleEdit(rule: RuleSummary) {
    if (
      rule.category !== "sla" &&
      rule.category !== "scanner_coverage" &&
      rule.category !== "auto_dismiss" &&
      rule.category !== "data_retention"
    )
      return
    setEditorCategory(rule.category)
    setEditorMode("edit")
    setEditorRule(rule)
    setEditorError(null)
    setEditorOpen(true)
  }

  function handleCreate(category: RuleCategory) {
    if (
      category !== "sla" &&
      category !== "scanner_coverage" &&
      category !== "auto_dismiss" &&
      category !== "data_retention"
    )
      return
    setEditorCategory(category)
    setEditorMode("create")
    setEditorRule(null)
    setEditorError(null)
    setEditorOpen(true)
  }

  async function handleEngageKillSwitch(reason: string) {
    setKillSwitchSaving(true)
    setKillSwitchError(null)
    try {
      await engageKillSwitch("auto_dismiss", reason || undefined)
      setKillSwitchDialogOpen(false)
      await reload()
    } catch (err) {
      console.error("Failed to engage kill switch", err)
      setKillSwitchError(
        err instanceof Error ? err.message : "Failed to engage kill switch",
      )
    } finally {
      setKillSwitchSaving(false)
    }
  }

  async function handleDisengageKillSwitch() {
    setKillSwitchError(null)
    try {
      await disengageKillSwitch("auto_dismiss")
      await reload()
    } catch (err) {
      console.error("Failed to disengage kill switch", err)
      setKillSwitchError(
        err instanceof Error ? err.message : "Failed to disengage kill switch",
      )
    }
  }

  async function handleSave(payload: { create?: CreateRulePayload; update?: UpdateRulePayload }) {
    setEditorSaving(true)
    setEditorError(null)
    try {
      if (payload.create) {
        await createRule(payload.create)
      } else if (payload.update && editorRule) {
        await updateRule(editorRule.id, payload.update)
      }
      setEditorOpen(false)
      await reload()
    } catch (err) {
      console.error("Failed to save rule", err)
      setEditorError(err instanceof Error ? err.message : "Failed to save rule")
    } finally {
      setEditorSaving(false)
    }
  }

  const slaList = slaRules ?? []
  const slaViolationsOpen = slaList.reduce((sum, r) => sum + r.violation_count_open, 0)
  const slaSubtitle =
    slaRules == null
      ? "Time-to-fix targets by severity"
      : `Time-to-fix targets by severity · ${slaViolationsOpen} ${slaViolationsOpen === 1 ? "violation" : "violations"} open`

  const coverageList = scannerCoverageRules ?? []
  const coverageGaps = stats?.coverage_gaps ?? 0
  const coverageSubtitle =
    scannerCoverageRules == null
      ? "Required scanners by repo tier"
      : `Required scanners by repo tier · ${coverageGaps} ${coverageGaps === 1 ? "gap" : "gaps"}`

  const autoDismissList = autoDismissRules ?? []
  const autoDismissKillSwitch =
    killSwitches.find((k) => k.category === "auto_dismiss") ?? null

  const retentionList = dataRetentionRules ?? []
  const retentionRulesActive = retentionList.filter((r) => r.enabled).length
  const retentionSubtitle =
    dataRetentionRules == null
      ? "How long Aegis keeps scan results"
      : `How long Aegis keeps scan results · ${retentionRulesActive} active`

  return (
    <div className="flex h-full flex-col bg-[var(--color-bg)]">
      <PageHeader
        icon={<RulesIcon />}
        title="Rules"
        description="Org-managed automation for SLAs, scanner coverage, dismissals, and retention."
      />

      <RulesSummaryStrip stats={stats} loading={loading} />

      <main className="flex-1 overflow-y-auto px-6 py-6">
        <div className="space-y-6">
          <RuleCategorySection
            category="sla"
            title="SLA policies"
            subtitle={slaSubtitle}
            icon={<SlaIcon />}
            rules={slaList}
            loading={loading}
            onEdit={handleEdit}
            onToggle={handleToggle}
            onDelete={handleDelete}
            onCreate={handleCreate}
            canManage={canManageSla}
            scrollAnchorId="rules-section-sla"
          />

          <RuleCategorySection
            category="scanner_coverage"
            title="Scanner coverage"
            subtitle={coverageSubtitle}
            icon={<ScannerIcon />}
            rules={coverageList}
            loading={loading}
            onEdit={handleEdit}
            onToggle={handleToggle}
            onDelete={handleDelete}
            onCreate={handleCreate}
            canManage={canManageScannerCoverage}
            scrollAnchorId="rules-section-scanner-coverage"
          />

          <div className="space-y-3">
            {autoDismissKillSwitch && (
              <div className="flex items-center gap-3 rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] p-3">
                <span className="text-[var(--color-severity-critical)]">
                  <AlertOctagonIcon />
                </span>
                <div className="flex-1">
                  <div className="text-sm font-semibold text-[var(--color-text-primary)]">
                    Auto-dismiss is killed for this org
                  </div>
                  <div className="text-xs text-[var(--color-text-secondary)]">
                    Killed {timeAgo(autoDismissKillSwitch.killed_at)} by{" "}
                    {autoDismissKillSwitch.killed_by}. Reason:{" "}
                    {autoDismissKillSwitch.reason ?? "—"}
                  </div>
                </div>
                {canManageAutoDismiss && (
                  <button
                    type="button"
                    onClick={handleDisengageKillSwitch}
                    className="rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-severity-critical)] hover:bg-[var(--color-surface-raised)]"
                  >
                    Re-enable
                  </button>
                )}
              </div>
            )}

            {canManageAutoDismiss && !autoDismissKillSwitch && (
              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={() => {
                    setKillSwitchError(null)
                    setKillSwitchDialogOpen(true)
                  }}
                  className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-subtle)]"
                >
                  <AlertOctagonIcon />
                  Kill auto-dismiss
                </button>
              </div>
            )}

            <RuleCategorySection
              category="auto_dismiss"
              title="Auto-dismiss patterns"
              subtitle="Reduce noise by auto-dismissing low-confidence findings."
              icon={<DismissIcon />}
              rules={autoDismissList}
              loading={loading}
              onEdit={handleEdit}
              onToggle={handleToggle}
              onDelete={handleDelete}
              onCreate={handleCreate}
              canManage={canManageAutoDismiss}
              scrollAnchorId="rules-section-auto-dismiss"
            />
          </div>

          <RuleCategorySection
            category="data_retention"
            title="Data retention"
            subtitle={retentionSubtitle}
            icon={<RetentionIcon />}
            rules={retentionList}
            loading={loading}
            onEdit={handleEdit}
            onToggle={handleToggle}
            onDelete={handleDelete}
            onCreate={handleCreate}
            canManage={canManageDataRetention}
            scrollAnchorId="rules-section-data-retention"
          />
        </div>
      </main>

      <RuleEditorModal
        open={editorOpen}
        mode={editorMode}
        category={editorCategory}
        initialRule={editorRule}
        destinations={destinations}
        onClose={() => setEditorOpen(false)}
        onSave={handleSave}
        saving={editorSaving}
        saveError={editorError}
      />

      <KillSwitchDialog
        open={killSwitchDialogOpen}
        category="auto_dismiss"
        loading={killSwitchSaving}
        error={killSwitchError}
        onConfirm={handleEngageKillSwitch}
        onCancel={() => {
          if (!killSwitchSaving) setKillSwitchDialogOpen(false)
        }}
      />
    </div>
  )
}

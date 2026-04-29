"use client"

import { useLicense } from "@/lib/client/license/client"
import { EnterpriseGate } from "@/components/shared/EnterpriseGate"

export default function AuditLogPage() {
  const { tier } = useLicense()
  const isEnterprise = tier === "enterprise"

  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10 space-y-4">
      <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Audit Log</h2>

      {isEnterprise ? (
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8">
          <div className="max-w-lg">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
              In development
            </p>
            <h3 className="mt-3 text-sm font-semibold text-[var(--color-text-primary)]">
              Audit log viewer is not available yet
            </h3>
            <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
              A searchable log of all administrative actions is being built. Events are already being recorded.
            </p>
          </div>
        </div>
      ) : (
        <EnterpriseGate
          feature="Audit Log"
          description="Track all administrative actions across your workspace, including user changes, role assignments, and scan configurations."
        />
      )}
    </div>
  )
}

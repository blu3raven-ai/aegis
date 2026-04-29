"use client"

import { useLicense } from "@/lib/client/license/client"
import { EnterpriseGate } from "@/components/shared/EnterpriseGate"

export default function SSOPage() {
  const { tier } = useLicense()
  const isEnterprise = tier === "enterprise"

  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10 space-y-4">
      <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Single Sign-On</h2>

      {isEnterprise ? (
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8">
          <div className="max-w-lg">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
              In development
            </p>
            <h3 className="mt-3 text-sm font-semibold text-[var(--color-text-primary)]">
              SSO configuration is not available yet
            </h3>
            <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
              SAML and OIDC single sign-on will let your team authenticate through your identity provider. This feature is being built.
            </p>
          </div>
        </div>
      ) : (
        <EnterpriseGate
          feature="Single Sign-On"
          description="SAML and OIDC single sign-on lets your team authenticate through your identity provider."
        />
      )}
    </div>
  )
}

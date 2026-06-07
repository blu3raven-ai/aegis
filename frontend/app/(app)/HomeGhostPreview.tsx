/**
 * Dimmed ghost preview rendered on Home when the user has no sources connected
 * and no findings yet. Mirrors the real dashboard layout so visitors can see
 * what each section will surface once scans complete. Pointer events are
 * disabled and the entire tree is aria-hidden by the wrapping component.
 */

const SEV_BADGE_CRIT = "bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical)]"
const SEV_BADGE_HIGH = "bg-[var(--color-severity-high)]/10 text-[var(--color-severity-high)]"
const SEV_BADGE_MED = "bg-[var(--color-severity-medium)]/10 text-[var(--color-severity-medium)]"

function FeaturedCard() {
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-start gap-3">
        <span className={`inline-flex shrink-0 items-center gap-1.5 rounded px-2 py-0.5 text-2xs font-semibold uppercase tracking-wide ${SEV_BADGE_CRIT}`}>
          <span aria-hidden="true" className="inline-block h-1.5 w-1.5 rounded-full bg-current" />
          critical
        </span>
        <h3 className="flex-1 min-w-0 text-base font-semibold text-[var(--color-text-primary)] tracking-[-0.005em]">
          Newly introduced vulnerability — preview
        </h3>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-[var(--color-text-secondary)]">
        <span>example-repo</span>
        <span aria-hidden="true" className="text-[var(--color-text-tertiary)]">·</span>
        <code className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 font-[family-name:var(--font-jetbrains-mono)] text-[11.5px]">
          package.json:42
        </code>
        <span aria-hidden="true" className="text-[var(--color-text-tertiary)]">·</span>
        <span className="text-[var(--color-text-tertiary)]">Dependencies</span>
      </div>
    </div>
  )
}

function CompactRow() {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3">
      <span className={`inline-flex shrink-0 items-center gap-1.5 rounded px-2 py-0.5 text-2xs font-semibold uppercase tracking-wide ${SEV_BADGE_HIGH}`}>
        <span aria-hidden="true" className="inline-block h-1.5 w-1.5 rounded-full bg-current" />
        high
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-[var(--color-text-primary)]">
          Recently surfaced finding — preview
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-[var(--color-text-tertiary)]">
          <span>example-repo</span>
          <span>Containers</span>
        </div>
      </div>
    </div>
  )
}

function CveCard({ severity }: { severity: "critical" | "high" }) {
  const sevClass = severity === "critical" ? SEV_BADGE_CRIT : SEV_BADGE_HIGH
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className={`rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wide ${sevClass}`}>
          {severity}
        </span>
        <span className={`rounded px-1.5 py-0.5 text-2xs font-semibold ${SEV_BADGE_HIGH}`}>EPSS 95%</span>
        <span className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-2xs text-[var(--color-text-secondary)]">
          example-repo
        </span>
      </div>
      <h3 className="mt-3 truncate text-base font-semibold text-[var(--color-text-primary)]">
        com.example:library
        <span className="ml-2 font-[family-name:var(--font-jetbrains-mono)] text-sm font-normal text-[var(--color-text-tertiary)]">
          — CVE-0000-0000
        </span>
      </h3>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent-on)]">
          Investigate →
        </span>
        <span className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)]">
          Open fix PR
        </span>
      </div>
    </div>
  )
}

function WeekChart() {
  const days = [
    { label: "Mon", intro: 2, fix: 1 },
    { label: "Tue", intro: 3, fix: 2 },
    { label: "Wed", intro: 1, fix: 4 },
    { label: "Thu", intro: 4, fix: 2 },
    { label: "Fri", intro: 2, fix: 5 },
    { label: "Sat", intro: 1, fix: 1 },
    { label: "Sun", intro: 0, fix: 3 },
  ]
  const max = 5
  const w = 800
  const h = 80
  const padBottom = 16
  const usable = h - padBottom
  const slotW = w / days.length
  const barW = 10
  const gap = 3
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="mt-4 h-20 w-full" preserveAspectRatio="none">
      <g stroke="var(--color-border)" strokeWidth="1">
        <line x1="0" y1={usable * 0.33} x2={w} y2={usable * 0.33} strokeDasharray="2 4" />
        <line x1="0" y1={usable * 0.66} x2={w} y2={usable * 0.66} strokeDasharray="2 4" />
      </g>
      {days.map((d, i) => {
        const cx = slotW * i + slotW / 2
        const introH = (d.intro / max) * usable
        const fixedH = (d.fix / max) * usable
        return (
          <g key={d.label}>
            <rect x={cx - barW - gap / 2} y={usable - introH} width={barW} height={introH} rx={2} fill="var(--color-severity-high)" opacity="0.85" />
            <rect x={cx + gap / 2} y={usable - fixedH} width={barW} height={fixedH} rx={2} fill="var(--color-status-ok)" opacity="0.85" />
            <text x={cx} y={h - 2} textAnchor="middle" fontSize="9" fill="var(--color-text-tertiary)">{d.label}</text>
          </g>
        )
      })}
    </svg>
  )
}

function RepoRow({ name, detail, blocked }: { name: string; detail: string; blocked?: boolean }) {
  const borderClass = blocked
    ? "border-l-[var(--color-severity-critical)]"
    : "border-l-[var(--color-status-ok)]"
  const detailClass = blocked
    ? "text-[var(--color-severity-critical)]"
    : "text-[var(--color-status-ok)]"
  return (
    <div className={`flex items-center gap-3 rounded-lg border border-[var(--color-border)] border-l-4 ${borderClass} bg-[var(--color-surface)] px-4 py-3`}>
      <span className="flex-1 truncate text-sm font-medium text-[var(--color-text-primary)]">{name}</span>
      <span className={`shrink-0 text-xs tabular-nums ${detailClass}`}>{detail}</span>
      <svg className="h-4 w-4 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M9 18l6-6-6-6" />
      </svg>
    </div>
  )
}

export function HomeGhostPreview({ displayName, salutation }: { displayName: string; salutation: string }) {
  return (
    <div className="space-y-8">
      {/* Greeting — same shape as real render */}
      <div>
        <h1 className="text-[26px] font-bold leading-tight tracking-[-0.025em] text-[var(--color-text-primary)]">
          {salutation}, {displayName}
        </h1>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Your security summary will appear here once your first scan completes.
        </p>
      </div>

      {/* Just introduced */}
      <section>
        <div className="mb-3 flex items-baseline justify-between gap-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Just introduced · needs your attention
          </h2>
          <span className="text-xs text-[var(--color-text-tertiary)]">preview</span>
        </div>
        <div className="space-y-2">
          <FeaturedCard />
          <CompactRow />
        </div>
      </section>

      {/* Open in your repos */}
      <section>
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Open in your repos
          </h2>
          <span className="text-xs text-[var(--color-text-tertiary)]">preview</span>
        </div>
        <div className="grid gap-3">
          <CveCard severity="critical" />
          <CveCard severity="high" />
        </div>
      </section>

      {/* Your week */}
      <section>
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Your week
          </h2>
          <span className="text-xs text-[var(--color-text-tertiary)]">preview</span>
        </div>
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <div className="grid grid-cols-3 gap-4">
            <div>
              <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">Introduced</p>
              <p className="mt-2 text-3xl font-semibold tabular-nums leading-none text-[var(--color-severity-high)]">13</p>
              <p className="mt-2 text-xs text-[var(--color-text-tertiary)]">vs last week</p>
            </div>
            <div>
              <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">Fixed</p>
              <p className="mt-2 text-3xl font-semibold tabular-nums leading-none text-[var(--color-status-ok)]">18</p>
              <p className="mt-2 text-xs text-[var(--color-text-tertiary)]">vs last week</p>
            </div>
            <div>
              <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">Net change</p>
              <p className="mt-2 text-3xl font-semibold tabular-nums leading-none text-[var(--color-status-ok)]">−5</p>
              <p className="mt-2 text-xs text-[var(--color-text-tertiary)]">in your repos</p>
            </div>
          </div>
          <div className="mt-5 border-t border-[var(--color-border)]/60 pt-2">
            <WeekChart />
          </div>
        </div>
      </section>

      {/* Your repos */}
      <section>
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Your repos
          </h2>
          <span className="text-xs text-[var(--color-text-tertiary)]">preview</span>
        </div>
        <div className="space-y-1.5">
          <RepoRow name="example-org/frontend" detail="12 issues · 2 critical" blocked />
          <RepoRow name="example-org/api" detail="4 issues" blocked />
          <RepoRow name="example-org/infra" detail="All clear" />
        </div>
      </section>
    </div>
  )
}

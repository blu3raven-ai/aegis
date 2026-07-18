"use client"

/**
 * Attack Chains — beta preview.
 *
 * Chain correlation requires reachability analysis (Argus engine) and is not
 * yet generally available. This page renders a design preview of the upcoming
 * feature with representative mock chains so users can see the planned UX.
 */

import { Fragment } from "react"
import { PageHeader } from "@/components/layout/PageHeader"
import { ChainsIcon } from "@/lib/shared/ui/page-icons"
import { Button } from "@/components/ui/Button"

type Severity = "critical" | "high"
type Reachability = "public" | "internal"

type NodeVariant = "entry" | "exploit" | "escalation" | "impact"
type TagKind = "kev" | "epss" | "cwe" | "crown"

interface MockNode {
  role: string
  variant: NodeVariant
  weakest?: boolean
  title: string
  sub: string
  icon: React.ReactNode
  tags?: { kind: TagKind; label: string }[]
}

interface ActionButton {
  label: string
  primary?: boolean
}

interface MockChain {
  id: string
  severity: Severity
  reachability: Reachability
  reachabilityLabel: string
  nodeCount: number
  repo: string
  title: string
  subtitle: React.ReactNode
  detected: string
  status: string
  nodes: MockNode[]
  tactics: string[]
  recommendation: {
    title: string
    body: React.ReactNode
    meta: string
    actions: ActionButton[]
  }
  collapsedSummary?: string[]
}

const MOCK_CHAINS: MockChain[] = [
  {
    id: "ch_log4shell_s3",
    severity: "critical",
    reachability: "public",
    reachabilityLabel: "Reachable from public internet",
    nodeCount: 4,
    repo: "acme/api",
    title: "Log4Shell RCE → AWS S3 prod data exfiltration",
    subtitle: (
      <>
        Untrusted user input flows from <strong>/api/orders/search</strong> into vulnerable log4j-core,
        enabling RCE that exposes IAM credentials with prod-S3 write access.
      </>
    ),
    detected: "12 days ago",
    status: "Open · Active",
    nodes: [
      {
        role: "Initial access",
        variant: "entry",
        title: "Public API endpoint",
        sub: "POST /api/orders/search",
        icon: <GlobeIcon />,
        tags: [{ kind: "cwe", label: "Public" }],
      },
      {
        role: "Execution",
        variant: "exploit",
        title: "Untrusted input reaches log sink",
        sub: "checkout/views.py:42",
        icon: <BoltIcon />,
        tags: [{ kind: "cwe", label: "CWE-117" }],
      },
      {
        role: "Privilege escalation",
        variant: "escalation",
        weakest: true,
        title: "log4j-core 2.14.0 RCE",
        sub: "pom.xml · CVE-2024-1234",
        icon: <ShieldIcon />,
        tags: [
          { kind: "kev", label: "KEV" },
          { kind: "epss", label: "97%" },
        ],
      },
      {
        role: "Impact / Exfiltration",
        variant: "impact",
        title: "IAM access to prod S3",
        sub: "arn:aws:iam::…:role/api-prod",
        icon: <DatabaseIcon />,
        tags: [{ kind: "crown", label: "Crown-jewel" }],
      },
    ],
    tactics: [
      "T1190 · Exploit public app",
      "T1059 · Cmd interpreter",
      "T1068 · Privilege escalation",
      "T1530 · Cloud storage access",
    ],
    recommendation: {
      title: "Cheapest fix to break this chain",
      body: (
        <>
          <strong>Upgrade log4j-core <code className="rounded bg-[var(--color-bg)] px-1.5 py-0.5 font-[family-name:var(--font-jetbrains-mono)] text-[11.5px]">2.14.0 → 2.17.1</code></strong>
          {" "}— patch release, no breaking changes, ~5 min to merge.
        </>
      ),
      meta: "Breaking node 3 (Log4j RCE) eliminates the bridge between exploit and impact — no need to fix the other 3 nodes.",
      actions: [
        { label: "Open fix PR", primary: true },
        { label: "Create Jira ticket" },
        { label: "Notify Slack" },
        { label: "Investigate" },
      ],
    },
  },
  {
    id: "ch_aws_key_s3",
    severity: "critical",
    reachability: "public",
    reachabilityLabel: "Reachable from public internet",
    nodeCount: 3,
    repo: "acme/web",
    title: "Exposed AWS key → arbitrary S3 access",
    subtitle: (
      <>
        Hardcoded AWS access key in <strong>config/prod.env</strong> committed to public-mirror branch.
        The key grants <strong>full-S3</strong> access across all buckets.
      </>
    ),
    detected: "8 days ago",
    status: "Open · Active",
    nodes: [
      {
        role: "Initial access",
        variant: "entry",
        title: "Public git history",
        sub: "github.com/acme/web · branch public-mirror",
        icon: <GlobeIcon />,
      },
      {
        role: "Credential access",
        variant: "escalation",
        weakest: true,
        title: "Hardcoded AWS access key",
        sub: "config/prod.env:42",
        icon: <KeyIcon />,
        tags: [{ kind: "cwe", label: "CWE-798" }],
      },
      {
        role: "Impact / Exfiltration",
        variant: "impact",
        title: "Full S3 access (all buckets)",
        sub: "AKIAIOSFODNN7EXAMPLE",
        icon: <DatabaseIcon />,
        tags: [{ kind: "crown", label: "Crown-jewel" }],
      },
    ],
    tactics: [
      "T1078 · Valid accounts",
      "T1552 · Unsecured creds",
      "T1530 · Cloud storage access",
    ],
    recommendation: {
      title: "Rotate and revoke",
      body: (
        <>
          Rotate the AWS key in <strong>config/prod.env</strong> and revoke the leaked one.
          Aegis can open the rotation PR and trigger IAM revocation if you allow it.
        </>
      ),
      meta: "Rotation removes the credential and breaks the chain. Original key remains in git history but is no longer valid.",
      actions: [
        { label: "Rotate key", primary: true },
        { label: "Investigate" },
      ],
    },
  },
  {
    id: "ch_ssrf_postgres",
    severity: "high",
    reachability: "internal",
    reachabilityLabel: "Internal only",
    nodeCount: 5,
    repo: "acme/worker",
    title: "Internal SSRF → Postgres data access",
    subtitle: (
      <>
        Worker accepts internal webhook URLs without validation, enabling SSRF to the database.
        Internal-only chain (requires existing network access), but high blast radius if breached.
      </>
    ),
    detected: "5 days ago",
    status: "Open · Active",
    nodes: [],
    tactics: [],
    recommendation: {
      title: "",
      body: "",
      meta: "",
      actions: [],
    },
    collapsedSummary: [
      "SSRF in webhook handler",
      "Internal Postgres reachable",
      "Read all order history",
    ],
  },
]

export default function ChainsPreviewPage() {
  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      <PageHeader
        icon={<ChainsIcon />}
        title="Attack Chains"
        description="Multi-step exploit paths Aegis identifies by correlating findings across repos."
        controls={
          <span className="font-mono rounded border border-[var(--color-state-dismissed-border)] bg-[var(--color-state-dismissed-subtle)] px-2 py-0.5 text-2xs font-bold uppercase tracking-[0.08em] text-[var(--color-state-dismissed)]">
            Preview
          </span>
        }
      />

      <div className="flex-1 overflow-auto">
        <PreviewBanner />
        <StatStrip />

        <div className="space-y-4 px-6 py-6">
          {MOCK_CHAINS.map(chain => (
            <ChainCard key={chain.id} chain={chain} />
          ))}
        </div>
      </div>
    </div>
  )
}


function PreviewBanner() {
  return (
    <div className="flex items-center gap-4 border-b border-[var(--color-state-dismissed-border)] bg-gradient-to-r from-[var(--color-state-dismissed-subtle)] to-transparent px-6 py-3.5">
      <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[var(--color-state-dismissed)] text-white">
        <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636-.707.707M21 12h-1M4 12H3m3.343-5.657-.707-.707m2.828 9.9a5 5 0 1 1 7.072 0l-.548.547A3.374 3.374 0 0 0 14 18.469V19a2 2 0 1 1-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
        </svg>
      </div>
      <div className="flex-1">
        <div className="flex items-center gap-2 text-xs font-semibold text-[var(--color-state-dismissed)]">
          <span className="font-mono rounded bg-[var(--color-state-dismissed)] px-1.5 py-0.5 text-2xs font-bold uppercase tracking-[0.08em] text-white">
            In development
          </span>
          Attack Chains is a preview of upcoming functionality
        </div>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
          Chain correlation requires reachability analysis (Argus engine). The data below is a
          design preview — not yet generally available. Targeted for a future release.
        </p>
      </div>
      <a
        href="#"
        onClick={(e) => e.preventDefault()}
        className="shrink-0 text-xs font-medium text-[var(--color-state-dismissed)] hover:underline"
      >
        Join beta waitlist →
      </a>
    </div>
  )
}


function StatStrip() {
  return (
    <div className="flex flex-wrap items-stretch border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-4">
      <StatItem
        label="Active chains"
        value="3"
        valueClass="text-[var(--color-severity-critical-text)]"
        delta="▼ 2 vs last week"
      />
      <StatItem
        label="Reachable from public"
        value="2"
        valueClass="text-[var(--color-severity-critical-text)]"
        delta="verified by Argus"
      />
      <StatItem
        label="Cheapest break"
        value="3 fixes"
        delta="resolves all chains"
      />
      <StatItem
        label="Broken this month"
        value="7"
        delta="by fix-merge"
      />
    </div>
  )
}

function StatItem({
  label,
  value,
  valueClass,
  delta,
}: {
  label: string
  value: string
  valueClass?: string
  delta: string
}) {
  return (
    <div className="mr-6 border-r border-[var(--color-border)] pr-6 py-2 last:border-r-0 last:mr-0 last:pr-0">
      <div className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
        {label}
      </div>
      <div className="mt-1 flex items-baseline gap-2">
        <span className={`text-2xl font-semibold leading-none tabular-nums tracking-tight ${valueClass ?? "text-[var(--color-text-primary)]"}`}>
          {value}
        </span>
        <span className="text-xs text-[var(--color-text-secondary)]">{delta}</span>
      </div>
    </div>
  )
}


function ChainCard({ chain }: { chain: MockChain }) {
  const isCritical = chain.severity === "critical"
  const hasDetails = chain.nodes.length > 0

  return (
    <article
      className={`overflow-hidden rounded-md border bg-[var(--color-surface)] ${
        isCritical ? "border-[var(--color-severity-critical-border)]" : "border-[var(--color-border)]"
      }`}
    >
      {isCritical && (
        <div className="h-0.5 bg-gradient-to-r from-[var(--color-severity-critical)] to-transparent" />
      )}

      <div className="grid w-full grid-cols-[1fr_auto] items-center gap-4 px-5 py-4 text-left">
        <div className="min-w-0">
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <SeverityPill severity={chain.severity} />
            <ReachabilityTag reachability={chain.reachability} label={chain.reachabilityLabel} />
            <MetaTag>{chain.nodeCount} nodes</MetaTag>
            <MetaTag>{chain.repo}</MetaTag>
          </div>
          <h2 className="text-base font-semibold tracking-tight text-[var(--color-text-primary)]">
            {chain.title}
          </h2>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{chain.subtitle}</p>
          {!hasDetails && chain.collapsedSummary && (
            <div className="mt-2 flex flex-wrap items-center gap-2 font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]">
              {chain.collapsedSummary.map((segment, i) => (
                <span key={i} className="flex items-center gap-2">
                  <span>{segment}</span>
                  {i < chain.collapsedSummary!.length - 1 && (
                    <svg className="h-3 w-3 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="m9 18 6-6-6-6" />
                    </svg>
                  )}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="text-right text-[11px] tabular-nums text-[var(--color-text-tertiary)]">
          <div>
            First detected <strong className="font-semibold text-[var(--color-text-primary)]">{chain.detected}</strong>
          </div>
          <div>
            Status <strong className="font-semibold text-[var(--color-text-primary)]">{chain.status}</strong>
          </div>
        </div>
      </div>

      {hasDetails && (
        <div className="border-t border-[var(--color-border)] bg-[var(--color-bg)]">
          <ChainGraph nodes={chain.nodes} />
          {chain.tactics.length > 0 && <TacticsStrip tactics={chain.tactics} />}
          <ChainRecommendation recommendation={chain.recommendation} />
        </div>
      )}
    </article>
  )
}


function ChainGraph({ nodes }: { nodes: MockNode[] }) {
  return (
    <div className="overflow-x-auto px-6 py-7">
      <div className="flex min-w-full items-center">
        {nodes.map((node, i) => (
          <Fragment key={i}>
            <ChainNode node={node} />
            {i < nodes.length - 1 && <ChainArrow />}
          </Fragment>
        ))}
      </div>
    </div>
  )
}

function ChainNode({ node }: { node: MockNode }) {
  const variantConfig: Record<NodeVariant, { border: string; roleColor: string; iconBg: string; iconColor: string; bg?: string }> = {
    entry: {
      border: "border-[var(--color-state-dismissed-border)]",
      roleColor: "text-[var(--color-state-dismissed)]",
      iconBg: "bg-[var(--color-state-dismissed-subtle)]",
      iconColor: "text-[var(--color-state-dismissed)]",
    },
    exploit: {
      border: "border-[var(--color-severity-medium-border)]",
      roleColor: "text-[var(--color-severity-medium-text)]",
      iconBg: "bg-[var(--color-severity-medium-subtle)]",
      iconColor: "text-[var(--color-severity-medium-text)]",
    },
    escalation: {
      border: "border-[var(--color-severity-critical)]",
      roleColor: "text-[var(--color-severity-critical-text)]",
      iconBg: "bg-[var(--color-severity-critical-subtle)]",
      iconColor: "text-[var(--color-severity-critical-text)]",
    },
    impact: {
      border: "border-[var(--color-severity-critical)]",
      roleColor: "text-[var(--color-severity-critical-text)]",
      iconBg: "bg-[var(--color-severity-critical)]",
      iconColor: "text-white",
      bg: "bg-[var(--color-severity-critical-subtle)]",
    },
  }

  const cfg = variantConfig[node.variant]

  return (
    <div
      className={`relative w-[200px] shrink-0 rounded-md border p-3.5 ${cfg.border} ${cfg.bg ?? "bg-[var(--color-surface)]"} ${
        node.weakest
          ? "shadow-[0_0_0_2px_var(--color-accent),0_0_0_4px_var(--color-accent-subtle)]"
          : ""
      }`}
    >
      {node.weakest && (
        <span className="font-mono absolute -top-2.5 right-2.5 rounded-full bg-[var(--color-accent)] px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.06em] text-[var(--color-accent-on)] shadow-md">
          Weakest link · Fix here
        </span>
      )}
      <div className={`mb-2 font-mono text-2xs font-semibold uppercase tracking-[0.14em] ${cfg.roleColor}`}>
        {node.role}
      </div>
      <div className={`mb-2.5 grid h-7 w-7 place-items-center rounded-md ${cfg.iconBg} ${cfg.iconColor}`}>
        {node.icon}
      </div>
      <div className="mb-1 text-sm font-semibold leading-snug text-[var(--color-text-primary)]">
        {node.title}
      </div>
      <div className="mb-2 break-all font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]">
        {node.sub}
      </div>
      {node.tags && node.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {node.tags.map((tag, i) => (
            <NodeTag key={i} kind={tag.kind} label={tag.label} />
          ))}
        </div>
      )}
    </div>
  )
}

function ChainArrow() {
  return (
    <div className="flex min-w-[32px] flex-1 items-center px-1">
      <div className="relative h-0.5 w-full bg-[var(--color-severity-critical)] opacity-50">
        <span
          className="absolute right-0 top-1/2 h-2 w-2 -translate-y-1/2 rotate-45 border-r-2 border-t-2 border-[var(--color-severity-critical)]"
        />
      </div>
    </div>
  )
}

function NodeTag({ kind, label }: { kind: TagKind; label: string }) {
  const styles: Record<TagKind, string> = {
    kev:   "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
    epss:  "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)]",
    cwe:   "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
    crown: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
  }
  return (
    <span className={`rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-[0.04em] ${styles[kind]}`}>
      {label}
    </span>
  )
}


function TacticsStrip({ tactics }: { tactics: string[] }) {
  return (
    <div className="font-mono flex min-w-full px-6 pb-4 text-2xs uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
      {tactics.map((t, i) => (
        <Fragment key={i}>
          <div className="w-[200px] shrink-0 text-center">{t}</div>
          {i < tactics.length - 1 && <div className="min-w-[32px] flex-1" />}
        </Fragment>
      ))}
    </div>
  )
}


function ChainRecommendation({ recommendation }: { recommendation: MockChain["recommendation"] }) {
  return (
    <div className="grid grid-cols-1 gap-5 border-t border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-5 lg:grid-cols-[1fr_auto] lg:items-center">
      <div className="flex items-start gap-3">
        <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-[var(--color-accent-subtle)] text-[var(--color-accent)]">
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
          </svg>
        </div>
        <div>
          <div className="mb-0.5 text-sm font-semibold text-[var(--color-accent)]">
            {recommendation.title}
          </div>
          <div className="text-sm text-[var(--color-text-primary)]">{recommendation.body}</div>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{recommendation.meta}</p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        {recommendation.actions.map((action, i) => (
          <Button
            key={i}
            variant={action.primary ? "primary" : "secondary"}
            size="sm"
            disabled
          >
            {action.label}
          </Button>
        ))}
      </div>
    </div>
  )
}


function SeverityPill({ severity }: { severity: Severity }) {
  const isCritical = severity === "critical"
  return (
    <span
      className={`rounded px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.04em] ${
        isCritical
          ? "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]"
          : "bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)]"
      }`}
    >
      {isCritical ? "Critical chain" : "High chain"}
    </span>
  )
}

function ReachabilityTag({ reachability, label }: { reachability: Reachability; label: string }) {
  if (reachability === "public") {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-[var(--color-severity-critical-subtle)] px-1.5 py-0.5 text-2xs text-[var(--color-severity-critical-text)]">
        <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
          <circle cx="12" cy="12" r="10" />
          <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        {label}
      </span>
    )
  }
  return <MetaTag>{label}</MetaTag>
}

function MetaTag({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-2xs text-[var(--color-text-secondary)]">
      {children}
    </span>
  )
}


function GlobeIcon() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <circle cx="12" cy="12" r="10" />
      <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  )
}

function BoltIcon() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />
    </svg>
  )
}

function ShieldIcon() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
    </svg>
  )
}

function DatabaseIcon() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14a9 3 0 0 0 18 0V5M3 12a9 3 0 0 0 18 0" />
    </svg>
  )
}

function KeyIcon() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" />
    </svg>
  )
}

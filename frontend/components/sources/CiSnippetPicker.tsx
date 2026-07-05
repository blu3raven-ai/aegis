"use client"
import { useState } from "react"
import { Copy, Check } from "lucide-react"
import { cn } from "@/lib/shared/utils"

export type ScmType = "github" | "gitlab" | "bitbucket" | "azure_devops"

type Props = {
  sourceId: string
  defaultTab?: ScmType
  aegisUrl?: string
}

const TABS: { value: ScmType; label: string }[] = [
  { value: "github",       label: "GitHub Actions" },
  { value: "gitlab",       label: "GitLab CI" },
  { value: "bitbucket",    label: "Bitbucket Pipelines" },
  { value: "azure_devops", label: "Azure DevOps" },
]

function snippetFor(scm: ScmType, sourceId: string, aegisUrl: string): string {
  switch (scm) {
    case "github":
      return `# .github/workflows/security.yml
name: Aegis security scan
on:
  pull_request:
    types: [opened, synchronize, reopened]
jobs:
  aegis:
    runs-on: ubuntu-latest
    steps:
      - uses: blu3raven-ai/aegis@v1
        with:
          aegis-url:  ${aegisUrl}
          api-key:    \${{ secrets.AEGIS_API_KEY }}
          source-id:  ${sourceId}
          fail-on:    high
`
    case "gitlab":
      return `# .gitlab-ci.yml
include:
  - component: gitlab.com/blu3raven-ai/aegis/gitlab-component@v1
    inputs:
      aegis_url:     ${aegisUrl}
      aegis_api_key: $AEGIS_API_KEY
      source_id:     ${sourceId}
      fail_on:       high
`
    case "bitbucket":
      return `# bitbucket-pipelines.yml
pipelines:
  pull-requests:
    '**':
      - step:
          script:
            - pipe: docker://blu3raven-ai/aegis-pipe:v1
              variables:
                AEGIS_URL:     ${aegisUrl}
                AEGIS_API_KEY: $AEGIS_API_KEY
                SOURCE_ID:     ${sourceId}
                FAIL_ON:       high
`
    case "azure_devops":
      return `# azure-pipelines.yml
trigger:
- main
pool:
  vmImage: ubuntu-latest
steps:
- task: AegisSecurityScan@1
  inputs:
    aegis-url:  ${aegisUrl}
    aegis-api-key: $(AEGIS_API_KEY)
    source-id:  ${sourceId}
    fail-on:    high
`
  }
}

export function CiSnippetPicker({ sourceId, defaultTab = "github", aegisUrl }: Props) {
  const resolvedUrl = aegisUrl ?? (typeof window !== "undefined" ? window.location.origin : "")
  const [tab, setTab] = useState<ScmType>(defaultTab)
  const [copied, setCopied] = useState(false)

  async function copy() {
    await navigator.clipboard.writeText(snippetFor(tab, sourceId, resolvedUrl))
    setCopied(true)
    window.setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <nav
        className="flex gap-1 border-b border-[var(--color-border)]"
        role="tablist"
        aria-label="CI provider"
      >
        {TABS.map(t => {
          const active = tab === t.value
          return (
            <button
              key={t.value}
              role="tab"
              aria-selected={active}
              onClick={() => setTab(t.value)}
              className={cn(
                "-mb-px border-b-2 px-3 py-2 text-sm transition-colors",
                active
                  ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                  : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]",
              )}
            >
              {t.label}
            </button>
          )
        })}
      </nav>

      <div className="mt-4 space-y-2 text-xs text-[var(--color-text-secondary)]">
        <p>
          1. Create an API key with <code className="bg-[var(--color-surface-2)] px-1 py-0.5 rounded text-2xs">scan:trigger</code> scope in{" "}
          <a href="/settings/api-keys" className="text-[var(--color-accent)] underline">Settings → API Keys</a>.
        </p>
        <p>
          2. Add the key to your CI as a secret named <code className="bg-[var(--color-surface-2)] px-1 py-0.5 rounded text-2xs">AEGIS_API_KEY</code>.
        </p>
        <p>3. Add the snippet below to your CI config:</p>
      </div>

      <div className="relative mt-3">
        <pre className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-3 text-xs font-mono leading-relaxed overflow-x-auto whitespace-pre">
          {snippetFor(tab, sourceId, resolvedUrl)}
        </pre>
        <button
          type="button"
          onClick={copy}
          className="absolute top-2 right-2 inline-flex items-center gap-1 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-2xs font-semibold uppercase tracking-[0.14em] hover:bg-[var(--color-surface)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  )
}

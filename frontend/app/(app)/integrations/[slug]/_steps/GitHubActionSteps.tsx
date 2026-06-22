"use client";
import { useState } from "react";
import { Copy } from "lucide-react";

export function GitHubActionSteps({ aegisUrl }: { aegisUrl: string }) {
  const [copied, setCopied] = useState(false);

  const snippet = `name: Aegis security scan
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
          fail-on:    high
`;

  async function copy() {
    await navigator.clipboard.writeText(snippet);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="relative">
      <pre className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-3 text-xs font-mono leading-relaxed overflow-x-auto whitespace-pre">
        {snippet}
      </pre>
      <button
        onClick={copy}
        className="absolute top-2 right-2 inline-flex items-center gap-1 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-1 text-2xs font-semibold uppercase tracking-[0.14em] hover:bg-[var(--color-surface)]"
      >
        <Copy className="h-3 w-3" />
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

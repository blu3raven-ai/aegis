"use client"

export function EmptyApiKeysState({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center">
      <svg
        className="h-8 w-8 text-[var(--color-text-secondary)]"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" />
      </svg>
      <div>
        <p className="text-sm font-medium text-[var(--color-text-primary)]">No API keys</p>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
          Create a key to authenticate CLI tools, CI pipelines, and integrations.
        </p>
      </div>
      <button
        onClick={onCreate}
        className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-medium text-[var(--color-accent-on)] hover:opacity-90 transition-opacity"
      >
        Create API key
      </button>
    </div>
  )
}

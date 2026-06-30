import { LinkButton } from "@/components/ui/LinkButton"

export function EmptySbomState({ repoName }: { repoName?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]">
        <svg
          className="h-8 w-8"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.2}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z" />
        </svg>
      </div>

      <div className="flex flex-col gap-1">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">
          No SBOM available{repoName ? ` for ${repoName}` : ""}
        </p>
        <p className="max-w-xs text-sm text-[var(--color-text-secondary)]">
          Connect a source and run a dependency scan to generate one. SBOMs are produced automatically after each scan completes.
        </p>
      </div>

      <LinkButton href="/sources" variant="secondary" size="md">
        Go to Sources
      </LinkButton>
    </div>
  )
}

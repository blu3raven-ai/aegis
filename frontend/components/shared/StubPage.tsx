import Link from "next/link"
import { PageHeader } from "@/components/layout/PageHeader"
import { Card } from "@/components/ui/Card"

function StubIcon() {
  return (
    <div className="p-1.5 bg-[var(--color-accent-subtle)] rounded-lg">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        className="w-5 h-5 text-[var(--color-accent)]"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09Z" />
      </svg>
    </div>
  )
}

interface StubPageProps {
  title: string
  phase: number
  purpose: string
}

export function StubPage({ title, phase, purpose }: StubPageProps) {
  return (
    <>
      <PageHeader icon={<StubIcon />} title={title} />
      <Card padding="none" className="mx-auto mt-12 max-w-lg px-6 py-8 text-center">
        <p className="font-mono text-xs font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
          Coming in Phase {phase}
        </p>
        <p className="mt-3 text-sm text-[var(--color-text-secondary)]">
          {purpose}
        </p>
        <Link
          href="/"
          className="mt-6 inline-block text-sm text-[var(--color-accent)] hover:underline"
        >
          Back to Home
        </Link>
      </Card>
    </>
  )
}

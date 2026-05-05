import { PageHeader } from "@/components/layout/PageHeader"

export default function HelpPage() {
  const categories = [
    { title: "System Reliability", description: "Bug reports or unexpected dashboard behavior." },
    { title: "Innovation", description: "Feature requests or workflow improvements." },
    { title: "Clarity", description: "Questions regarding tool configuration or finding logic." },
    { title: "Feedback", description: "General thoughts on your experience so far." },
  ]

  return (
    <>
      <PageHeader
        icon={
          <div className="p-1.5 bg-blue-50 dark:bg-blue-950 rounded-lg">
            <svg className="w-5 h-5 text-blue-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
              <path d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 5.25h.008v.008H12v-.008Z" />
            </svg>
          </div>
        }
        title="Help & Support"
        org="Get help or share feedback"
      />

      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">
        <div className="mx-auto max-w-2xl space-y-8">
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-center">
            <p className="text-sm text-[var(--color-text-secondary)] leading-relaxed">
              If you encounter issues, have questions about our security logic, or want to suggest an improvement, please reach out via our support channel.
            </p>
          </div>

          <div>
            <p className="mb-4 text-[10px] font-bold uppercase tracking-wider text-[var(--color-text-secondary)]">
              What we're looking for
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              {categories.map((cat) => (
                <div key={cat.title} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
                  <h4 className="font-semibold text-sm text-[var(--color-text-primary)]">{cat.title}</h4>
                  <p className="mt-1 text-xs text-[var(--color-text-secondary)] leading-relaxed">{cat.description}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="text-center">
          <a
            href="https://aegis.com/support"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[var(--color-accent-hover)]"
          >
            Open Support
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
            </svg>
          </a>
          </div>
        </div>
      </main>
    </>
  )
}

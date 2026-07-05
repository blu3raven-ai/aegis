interface Tab<T extends string> {
  id: T
  label: string
}

export function DashboardTabs<T extends string>({
  tabs,
  activeTab,
  onChange,
}: {
  tabs: readonly Tab<T>[]
  activeTab: T
  onChange: (tab: T) => void
}) {
  return (
    <div className="rounded-[24px] border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
      <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${tabs.length}, minmax(0, 1fr))` }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => onChange(tab.id)}
            className={`rounded-2xl px-4 py-3 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
              activeTab === tab.id
                ? "bg-[var(--color-accent)]/10 font-semibold text-[var(--color-accent)]"
                : "font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
    </div>
  )
}

"use client"

export interface ViewMode {
  id: string
  label: string
  icon: React.ReactNode
}

interface Props {
  modes: ViewMode[]
  active: string
  onChange: (id: string) => void
  /** Optional counts per mode id, e.g. { list: 352, repository: 12, package: 28 } */
  counts?: Record<string, number>
}

const ICON_LIST = (
  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
    <line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" /><line x1="8" y1="18" x2="21" y2="18" />
    <line x1="3" y1="6" x2="3.01" y2="6" /><line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" />
  </svg>
)

const ICON_REPO = (
  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" />
    <rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
  </svg>
)

const ICON_PACKAGE = (
  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
    <polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" />
  </svg>
)

export const DEPENDENCIES_VIEW_MODES: ViewMode[] = [
  { id: "list", label: "List", icon: ICON_LIST },
  { id: "repository", label: "Repository", icon: ICON_REPO },
  { id: "package", label: "Package", icon: ICON_PACKAGE },
]



const ICON_RULE = (
  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" />
    <polyline points="10 9 9 9 8 9" />
  </svg>
)

export const CODE_SCANNING_VIEW_MODES: ViewMode[] = [
  { id: "list", label: "List", icon: ICON_LIST },
  { id: "repository", label: "Repository", icon: ICON_REPO },
  { id: "rule", label: "Rule", icon: ICON_RULE },
]

const ICON_KEY = (
  <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
  </svg>
)

export const SECRETS_VIEW_MODES: ViewMode[] = [
  { id: "list", label: "List", icon: ICON_LIST },
  { id: "repository", label: "Repository", icon: ICON_REPO },
  { id: "key", label: "Key", icon: ICON_KEY },
]

export const CONTAINER_VIEW_MODES: ViewMode[] = [
  { id: "list", label: "List", icon: ICON_LIST },
  { id: "repository", label: "Image", icon: ICON_REPO },
  { id: "package", label: "Package", icon: ICON_PACKAGE },
]

export function ViewModeToggle({ modes, active, onChange, counts }: Props) {
  return (
    <div className="flex rounded-lg border border-[var(--color-border)] overflow-hidden" role="radiogroup" aria-label="View mode">
      {modes.map((mode) => {
        const isActive = mode.id === active
        return (
          <button
            key={mode.id}
            type="button"
            role="radio"
            aria-checked={isActive}
            onClick={() => onChange(mode.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold transition-colors ${
              isActive
                ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                : "bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            } ${mode.id !== modes[0].id ? "border-l border-[var(--color-border)]" : ""}`}
          >
            {mode.icon}
            {mode.label}
            {counts?.[mode.id] != null && (
              <span className={`tabular-nums ${isActive ? "text-[var(--color-accent-on)]/70" : "text-[var(--color-text-secondary)]"}`}>
                {counts[mode.id]}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

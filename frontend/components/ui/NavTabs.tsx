import { useRef, type ReactNode } from "react"
import { cn } from "@/lib/shared/utils"
import { handleRovingKeyDown } from "./roving"

export interface NavTab<T extends string> {
  id: T
  label: string
  count?: number
  icon?: ReactNode
}

interface NavTabsProps<T extends string> {
  tabs: readonly NavTab<T>[]
  activeTab: T
  onChange: (tab: T) => void
  className?: string
  containerClassName?: string
  ariaLabel?: string
}

export function NavTabs<T extends string>({
  tabs,
  activeTab,
  onChange,
  className,
  containerClassName,
  ariaLabel,
}: NavTabsProps<T>) {
  const btnRefs = useRef<(HTMLButtonElement | null)[]>([])
  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      className={cn(
        "flex items-center gap-1 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6",
        containerClassName,
      )}
    >
      {tabs.map((tab, i) => {
        const active = tab.id === activeTab
        return (
          <button
            key={tab.id}
            ref={(el) => { btnRefs.current[i] = el }}
            type="button"
            role="tab"
            aria-selected={active}
            // Roving tabindex: only the selected tab is a tab stop; arrows move
            // between the rest (WAI-ARIA tablist keyboard pattern).
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(tab.id)}
            onKeyDown={(e) =>
              handleRovingKeyDown(e, {
                index: i,
                count: tabs.length,
                orientation: "horizontal",
                onMove: (n) => {
                  onChange(tabs[n].id)
                  btnRefs.current[n]?.focus()
                },
              })
            }
            className={cn(
              "-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-2.5 text-sm transition-colors",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:rounded-sm",
              active
                ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                : "border-transparent font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]",
              className,
            )}
          >
            {tab.icon && <span className="h-4 w-4 shrink-0">{tab.icon}</span>}
            {/* Grid-stack a bold ghost copy to reserve width and prevent layout shift on active toggle. */}
            <span className="relative grid">
              <span className="col-start-1 row-start-1">{tab.label}</span>
              <span
                aria-hidden="true"
                className="col-start-1 row-start-1 invisible font-semibold"
              >
                {tab.label}
              </span>
            </span>
            {typeof tab.count === "number" && (
              <span
                className={cn(
                  "ml-0.5 rounded-full px-1.5 py-0.5 text-2xs font-semibold tabular-nums",
                  active
                    ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                    : "bg-[var(--color-bg-section)] text-[var(--color-text-tertiary)]",
                )}
              >
                {tab.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

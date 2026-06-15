import { cn } from "@/lib/shared/utils"

type SearchInputSize = "sm" | "md"

interface SearchInputProps {
  value: string
  onChange: (v: string) => void
  placeholder: string
  /** sm = h-8 px-3 text-xs (table-row filter row), md = h-10 text-sm (page-level search). Default md. */
  size?: SearchInputSize
  /** Optional className appended to the wrapper (e.g. ml-auto, w-56). */
  className?: string
  /** Optional aria-label for screen readers when no visible label is rendered. */
  ariaLabel?: string
}

const sizeClasses: Record<SearchInputSize, { input: string; iconLeft: string; clearBtn: string }> = {
  sm: {
    input: "h-8 pl-8 pr-7 text-xs",
    iconLeft: "left-2.5 h-3.5 w-3.5",
    clearBtn: "right-1.5 h-3.5 w-3.5",
  },
  md: {
    input: "h-10 pl-9 pr-9 text-sm",
    iconLeft: "left-3 h-4 w-4",
    clearBtn: "right-2 h-4 w-4",
  },
}

export function SearchInput({
  value,
  onChange,
  placeholder,
  size = "md",
  className,
  ariaLabel,
}: SearchInputProps) {
  const cls = sizeClasses[size]
  return (
    <div className={cn("relative", className)}>
      <svg
        className={cn(
          "pointer-events-none absolute top-1/2 -translate-y-1/2 text-[var(--color-text-secondary)]",
          cls.iconLeft,
        )}
        viewBox="0 0 20 20"
        fill="currentColor"
        aria-hidden="true"
      >
        <path
          fillRule="evenodd"
          d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z"
          clipRule="evenodd"
        />
      </svg>
      <input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel}
        className={cn(
          "w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]",
          cls.input,
        )}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange("")}
          className={cn(
            "absolute top-1/2 -translate-y-1/2 rounded p-0.5 text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]",
            cls.clearBtn,
          )}
          aria-label="Clear search"
        >
          <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
      )}
    </div>
  )
}

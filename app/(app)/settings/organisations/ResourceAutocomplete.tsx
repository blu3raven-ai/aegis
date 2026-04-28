"use client"

import { useEffect, useRef, useState } from "react"

interface ResourceAutocompleteProps {
  value: string
  placeholder: string
  suggestions: string[]
  error?: string | null
  onChange: (value: string) => void
  onPick: (value: string) => void
}

export function ResourceAutocomplete({
  value,
  placeholder,
  suggestions,
  error,
  onChange,
  onPick,
}: ResourceAutocompleteProps) {
  const [showSuggestions, setShowSuggestions] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setShowSuggestions(false)
      }
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [])

  // Use a focus handler to trigger initial suggestions when empty
  const handleFocus = () => {
    if (suggestions.length === 0 || value === "") {
      onChange(value)
    }
    setShowSuggestions(true)
  }

  return (
    <div className="relative space-y-2" ref={containerRef}>
      <input
        value={value}
        onChange={(event) => {
          onChange(event.target.value)
          setShowSuggestions(true)
        }}
        onFocus={handleFocus}
        onClick={() => setShowSuggestions(true)}
        placeholder={placeholder}
        className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
      />
      {error && <p className="text-xs text-amber-600 dark:text-amber-400">{error}</p>}
      {showSuggestions && suggestions.length > 0 && (
        <div className="absolute z-10 mt-1 max-h-60 w-full overflow-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-1 shadow-lg">
          {suggestions.map((suggestion) => (
            <button
              key={suggestion}
              type="button"
              onMouseDown={(e) => {
                // Prevent focus-out from closing before click fires
                e.preventDefault()
                onPick(suggestion)
                setShowSuggestions(false)
              }}
              className="block w-full rounded-md px-2 py-1.5 text-left font-mono text-xs hover:bg-[var(--color-surface-raised)] transition-colors"
            >
              {suggestion}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

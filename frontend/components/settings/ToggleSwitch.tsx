"use client"

interface ToggleSwitchProps {
  checked: boolean
  onChange: (next: boolean) => void
  label: string
  /** Renders the switch non-interactive (e.g. a preview of an unshipped control). */
  disabled?: boolean
}

export function ToggleSwitch({ checked, onChange, label, disabled = false }: ToggleSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => {
        if (!disabled) onChange(!checked)
      }}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-50 ${
        checked
          ? "bg-[var(--color-accent)]"
          : "bg-[var(--color-toggle-off)]"
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
          checked ? "translate-x-4" : "translate-x-1"
        }`}
      />
    </button>
  )
}

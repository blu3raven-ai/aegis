"use client"

import { useEffect, useState } from "react"

import { THEME_CHANGE_EVENT, getStoredTheme, setTheme } from "@/lib/client/theme"

export function ThemeToggleButton() {
  const [isDark, setIsDark] = useState(false)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    function getEffectiveDark(): boolean {
      const theme = getStoredTheme()
      if (theme === "dark") return true
      if (theme === "light") return false
      return window.matchMedia("(prefers-color-scheme: dark)").matches
    }

    setIsDark(getEffectiveDark())
    setMounted(true)

    const mq = window.matchMedia("(prefers-color-scheme: dark)")
    function handleSystemChange() {
      if (getStoredTheme() === "system") setIsDark(mq.matches)
    }
    mq.addEventListener("change", handleSystemChange)
    return () => mq.removeEventListener("change", handleSystemChange)
  }, [])

  useEffect(() => {
    function handleThemeChange(e: Event) {
      const theme = (e as CustomEvent<{ theme: string }>).detail?.theme
      if (!theme) return
      if (theme === "dark") setIsDark(true)
      else if (theme === "light") setIsDark(false)
      else setIsDark(window.matchMedia("(prefers-color-scheme: dark)").matches)
    }
    window.addEventListener(THEME_CHANGE_EVENT, handleThemeChange)
    return () => window.removeEventListener(THEME_CHANGE_EVENT, handleThemeChange)
  }, [])

  function toggle() {
    setTheme(isDark ? "light" : "dark")
  }

  if (!mounted) {
    return <div className="h-9 w-9" aria-hidden />
  }

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      className="rounded-lg p-2 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
    >
      {isDark ? (
        <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" />
        </svg>
      ) : (
        <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
          <path d="M21.752 15.002A9.72 9.72 0 0 1 18 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 0 0 3 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 0 0 9.002-5.998Z" />
        </svg>
      )}
    </button>
  )
}

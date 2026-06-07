"use client"

import { useEffect } from "react"

export function ThemeProvider() {
  useEffect(() => {
    let mediaQuery: MediaQueryList | null = null
    let systemChangeHandler: (() => void) | null = null

    function applyTheme(theme: string) {
      const isDark =
        theme === "dark" ||
        (theme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches)

      if (isDark) document.documentElement.classList.add("dark")
      else document.documentElement.classList.remove("dark")

      if (systemChangeHandler && mediaQuery) {
        mediaQuery.removeEventListener("change", systemChangeHandler)
        systemChangeHandler = null
        mediaQuery = null
      }

      if (theme === "system") {
        mediaQuery = window.matchMedia("(prefers-color-scheme: dark)")
        systemChangeHandler = () => applyTheme("system")
        mediaQuery.addEventListener("change", systemChangeHandler)
      }
    }

    let savedTheme = "system"
    try {
      savedTheme = localStorage.getItem("theme") || "system"
    } catch { /* ignore */ }
    applyTheme(savedTheme)

    function handleThemeChange(e: Event) {
      const theme = (e as CustomEvent<{ theme: string }>).detail?.theme
      if (!theme) return
      try { localStorage.setItem("theme", theme) } catch { /* ignore */ }
      applyTheme(theme)
    }

    window.addEventListener("theme:change", handleThemeChange)

    return () => {
      window.removeEventListener("theme:change", handleThemeChange)
      if (systemChangeHandler && mediaQuery) {
        mediaQuery.removeEventListener("change", systemChangeHandler)
      }
    }
  }, [])

  return null
}

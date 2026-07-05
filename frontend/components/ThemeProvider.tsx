"use client"

import { useEffect } from "react"

import { THEME_CHANGE_EVENT, THEME_STORAGE_KEY, getStoredTheme } from "@/lib/client/theme"

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

    applyTheme(getStoredTheme())

    function handleThemeChange(e: Event) {
      const theme = (e as CustomEvent<{ theme: string }>).detail?.theme
      if (!theme) return
      try { localStorage.setItem(THEME_STORAGE_KEY, theme) } catch { /* ignore */ }
      applyTheme(theme)
    }

    window.addEventListener(THEME_CHANGE_EVENT, handleThemeChange)

    return () => {
      window.removeEventListener(THEME_CHANGE_EVENT, handleThemeChange)
      if (systemChangeHandler && mediaQuery) {
        mediaQuery.removeEventListener("change", systemChangeHandler)
      }
    }
  }, [])

  return null
}

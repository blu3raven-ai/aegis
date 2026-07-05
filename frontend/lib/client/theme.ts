"use client"

/**
 * Device-local theme preference — the single source of truth shared by the
 * header toggle, the settings Theme select, and the ThemeProvider that applies
 * it. Theme is per-device (localStorage), not a server/account setting, which is
 * why the settings caption reads "Affects this device only". Changing it goes
 * through `setTheme`, which ThemeProvider persists to localStorage and applies
 * to the root element live — no page reload, no server round-trip.
 */

export type ThemeChoice = "system" | "dark" | "light"

export const THEME_STORAGE_KEY = "theme"
export const THEME_CHANGE_EVENT = "theme:change"

/** The user's stored theme choice, or "system" when unset or unavailable. */
export function getStoredTheme(): ThemeChoice {
  try {
    const value = localStorage.getItem(THEME_STORAGE_KEY)
    if (value === "dark" || value === "light" || value === "system") return value
  } catch {
    /* ignore */
  }
  return "system"
}

/**
 * Apply and persist a theme choice across the app. ThemeProvider listens for
 * this event, writes it to localStorage, and toggles the root `.dark` class;
 * the header toggle updates its icon in step.
 */
export function setTheme(theme: ThemeChoice): void {
  window.dispatchEvent(new CustomEvent(THEME_CHANGE_EVENT, { detail: { theme } }))
}

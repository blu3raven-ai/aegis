"use client"

import { useEffect } from "react"
import { SaveBarProvider } from "./save-bar/SaveBarProvider"
import { GlobalSaveBar } from "./save-bar/GlobalSaveBar"

// Turns <main data-app-scroll> into a flex column for the duration of the
// settings page so that child divs can use flex-1 / min-h-0 to carve up the
// available height without relying on height:100% percentage resolution
// (which is unreliable when the parent's height comes only from flex-grow).
// Restored on unmount so other pages continue to use the default block layout.
function SettingsMainSetup() {
  useEffect(() => {
    const main = document.querySelector("main[data-app-scroll]") as HTMLElement | null
    if (!main) return
    const prev = { overflow: main.style.overflowY, display: main.style.display, flexDir: main.style.flexDirection }
    main.style.overflowY = "hidden"
    main.style.display = "flex"
    main.style.flexDirection = "column"
    return () => {
      main.style.overflowY = prev.overflow
      main.style.display = prev.display
      main.style.flexDirection = prev.flexDir
    }
  }, [])
  return null
}

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return (
    <SaveBarProvider>
      <SettingsMainSetup />
      {children}
      <GlobalSaveBar />
    </SaveBarProvider>
  )
}

"use client"

import { useEffect, useRef, useState } from "react"

/** Track an element's content width via ResizeObserver so SVG charts can render
 *  at true pixel dimensions (viewBox == pixel box), avoiding the horizontal
 *  distortion of `preserveAspectRatio="none"`. Returns 0 until the first
 *  measurement — callers should reserve height and render once width > 0. */
export function useMeasuredWidth<T extends HTMLElement = HTMLDivElement>() {
  const ref = useRef<T>(null)
  const [width, setWidth] = useState(0)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const observer = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width
      if (w && w > 0) setWidth(Math.round(w))
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [])
  return [ref, width] as const
}

"use client"

import { useEffect, useState } from "react"

export function useActiveSection(
  ids: readonly string[],
  rootMargin = "-80px 0px -70% 0px",
  rootSelector?: string,
): string | null {
  const [activeId, setActiveId] = useState<string | null>(ids[0] ?? null)

  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return
    const root = rootSelector ? (document.querySelector(rootSelector) ?? null) : null
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0]
        if (visible) setActiveId(visible.target.id)
      },
      { root, rootMargin, threshold: 0 },
    )
    for (const id of ids) {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    }
    return () => observer.disconnect()
  }, [ids, rootMargin, rootSelector])

  return activeId
}

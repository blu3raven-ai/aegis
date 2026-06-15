"use client"

import { useEffect, useState } from "react"
import { apiClient } from "../api-client.ts"

export interface Branding {
  name: string | null
  logoDataUrl: string | null
}

const NULL_BRANDING: Branding = {
  name: null,
  logoDataUrl: null,
}

let cachedBranding: Branding = NULL_BRANDING
let cacheTimestamp = 0
const CACHE_TTL_MS = 60_000

export async function fetchBranding(): Promise<Branding> {
  const now = Date.now()
  if (cacheTimestamp > 0 && now - cacheTimestamp < CACHE_TTL_MS) {
    return cachedBranding
  }
  try {
    const data = await apiClient<Branding>("/api/v1/branding")
    cachedBranding = data
    cacheTimestamp = Date.now()
    return data
  } catch {
    return NULL_BRANDING
  }
}

/** Invalidate the cache so the next useBranding() call refetches. */
export function invalidateBrandingCache() {
  cacheTimestamp = 0
}

/**
 * True when no customer name is set. NULL is the only sentinel —
 * never compare against literal strings like "Blu3Raven".
 */
export function isVendorBranded(name: string | null | undefined): boolean {
  return name == null
}

export function useBranding(): Branding & {
  isLoading: boolean
  logoSrc: string
  isVendor: boolean
} {
  const [branding, setBranding] = useState<Branding>(cachedBranding)
  const [isLoading, setIsLoading] = useState(cacheTimestamp === 0)

  useEffect(() => {
    fetchBranding().then((b) => {
      setBranding(b)
      setIsLoading(false)
    })
  }, [])

  const logoSrc = branding.logoDataUrl ?? "/logo-brand.png"
  const isVendor = isVendorBranded(branding.name)
  return { ...branding, logoSrc, isVendor, isLoading }
}

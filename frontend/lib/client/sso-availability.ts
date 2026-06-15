"use client"

import { useEffect, useState } from "react"

export interface SsoAvailability {
  enabled: boolean
  protocol: "saml" | "oidc" | null
}

let cached: SsoAvailability | null = null

export function ssoLoginUrl(protocol: SsoAvailability["protocol"]): string | null {
  if (protocol === "saml") return "/auth/sso/saml/login"
  if (protocol === "oidc") return "/auth/sso/oidc/login"
  return null
}

export function useSsoAvailability(): SsoAvailability | null {
  const [data, setData] = useState<SsoAvailability | null>(cached)

  useEffect(() => {
    if (cached) return
    let alive = true
    fetch("/api/v1/sso/sso-availability", { credentials: "omit" })
      .then((r) => (r.ok ? r.json() : Promise.reject(r)))
      .then((d: SsoAvailability) => { cached = d; if (alive) setData(d) })
      .catch(() => { if (alive) setData({ enabled: false, protocol: null }) })
    return () => { alive = false }
  }, [])

  return data
}

"use client"

import type { Tier } from "@/lib/shared/license/types"
import { canUseTier } from "@/lib/shared/license/gate"
import { UpgradeBanner } from "./UpgradeBanner"

interface TierGateProps {
  currentTier: Tier
  requiredTier: Tier
  feature: string
  children: React.ReactNode
}

export function TierGate({ currentTier, requiredTier, feature, children }: TierGateProps) {
  if (canUseTier(currentTier, requiredTier)) {
    return <>{children}</>
  }
  return <UpgradeBanner requiredTier={requiredTier} feature={feature} />
}

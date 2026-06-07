import type { Tier } from "./types"
import { TIER_ORDER } from "./types"

export function canUseTier(current: Tier, required: Tier): boolean {
  return TIER_ORDER[current] >= TIER_ORDER[required]
}

/**
 * In-memory rate limiter for auth endpoints.
 *
 * Tracks failed attempts per key (username or IP) with a sliding window.
 * Not shared across processes — suitable for single-instance deployments.
 */

interface Entry {
  attempts: number
  resetAt: number
}

const store = new Map<string, Entry>()

const WINDOW_MS = 15 * 60 * 1000 // 15 minutes
const MAX_ATTEMPTS = 5

/** Prune expired entries periodically to prevent memory growth. */
let lastPrune = Date.now()
function prune() {
  const now = Date.now()
  if (now - lastPrune < 60_000) return
  lastPrune = now
  for (const [key, entry] of store) {
    if (now > entry.resetAt) store.delete(key)
  }
}

/**
 * Check if a key is rate-limited.
 * Returns the number of seconds until the limit resets, or 0 if allowed.
 */
export function isRateLimited(key: string): number {
  prune()
  const now = Date.now()
  const entry = store.get(key)
  if (!entry || now > entry.resetAt) return 0
  if (entry.attempts >= MAX_ATTEMPTS) {
    return Math.ceil((entry.resetAt - now) / 1000)
  }
  return 0
}

/** Record a failed attempt for a key. */
export function recordFailedAttempt(key: string): void {
  const now = Date.now()
  const entry = store.get(key)
  if (!entry || now > entry.resetAt) {
    store.set(key, { attempts: 1, resetAt: now + WINDOW_MS })
  } else {
    entry.attempts++
  }
}

/** Clear rate limit for a key (e.g., on successful login). */
export function clearRateLimit(key: string): void {
  store.delete(key)
}

interface PendingEntry {
  secret: string
  expiresAt: number
}

const _store = new Map<string, PendingEntry>()

export function setPending(userId: string, secret: string): void {
  _store.set(userId, { secret, expiresAt: Date.now() + 5 * 60 * 1000 })
}

export function getPending(userId: string): string | null {
  const entry = _store.get(userId)
  if (!entry) return null
  if (entry.expiresAt < Date.now()) {
    _store.delete(userId)
    return null
  }
  return entry.secret
}

export function clearPending(userId: string): void {
  _store.delete(userId)
}

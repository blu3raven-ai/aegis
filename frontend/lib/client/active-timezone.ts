/**
 * The active display time zone for date/time formatting across the app.
 *
 * The account "Time zone" preference is synced here (see TimeZoneSync) so every
 * shared date formatter renders in the user's chosen zone instead of whatever
 * zone the browser happens to be in. `undefined` means "use the runtime
 * default" (browser-local) — the state before the profile has loaded, and the
 * safe fallback for an unrecognised zone.
 */
let active: string | undefined

/** IANA zone to format in, or `undefined` to use the runtime (browser) default. */
export function getActiveTimeZone(): string | undefined {
  return active
}

/**
 * Set the active zone from the account profile. A blank value clears back to the
 * runtime default. An unrecognised IANA name is rejected (kept as the default)
 * so no formatter call site can throw a RangeError on a bad stored value.
 */
export function setActiveTimeZone(tz: string | null | undefined): void {
  const candidate = tz?.trim()
  if (!candidate) {
    active = undefined
    return
  }
  try {
    // Constructing with an unknown time zone throws RangeError.
    new Intl.DateTimeFormat("en-US", { timeZone: candidate })
    active = candidate
  } catch {
    active = undefined
  }
}

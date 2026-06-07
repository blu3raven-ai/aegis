import "server-only"

/**
 * Structured server-side logger.
 *
 * Usage:
 *   const log = createLogger("session")
 *   log.info("User authenticated", userId)
 *   log.error("Decryption failed")
 */
function createLogger(module: string) {
  const prefix = `[${module}]`
  return {
    info: (...args: unknown[]) => console.info(prefix, ...args),
    warn: (...args: unknown[]) => console.warn(prefix, ...args),
    error: (...args: unknown[]) => console.error(prefix, ...args),
  }
}

export { createLogger }

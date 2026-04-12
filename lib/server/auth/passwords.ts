import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "crypto"
import { promisify } from "util"

const scrypt = promisify(scryptCallback)
const KEY_LENGTH = 64

const MIN_PASSWORD_LENGTH = 12

export function validatePasswordStrength(password: string): string | null {
  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`
  }
  return null
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16)
  const key = (await scrypt(password, salt, KEY_LENGTH)) as Buffer
  return `scrypt:v1:${salt.toString("hex")}:${key.toString("hex")}`
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  try {
    const [algorithm, version, saltHex, keyHex] = storedHash.split(":")
    if (algorithm !== "scrypt" || version !== "v1" || !saltHex || !keyHex) return false
    const salt = Buffer.from(saltHex, "hex")
    const expected = Buffer.from(keyHex, "hex")
    if (salt.length === 0 || expected.length !== KEY_LENGTH) return false

    const actual = (await scrypt(password, salt, expected.length)) as Buffer
    return timingSafeEqual(actual, expected)
  } catch {
    return false
  }
}

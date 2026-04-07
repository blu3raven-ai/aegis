import { generateSecret, generateURI, verifySync } from "otplib"

export function generateTotpSecret(): string {
  return generateSecret()
}

export function buildOtpauthUri(secret: string, username: string): string {
  return generateURI({
    strategy: "totp",
    issuer: "Security Portal",
    label: username,
    secret,
  })
}

export function verifyTotpCode(code: string, secret: string): boolean {
  if (!/^\d{6}$/.test(code)) return false
  try {
    return verifySync({ token: code, secret }).valid
  } catch {
    return false
  }
}

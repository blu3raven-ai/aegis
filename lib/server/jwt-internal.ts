import { createHmac } from "crypto"
import type { UserRole } from "../shared/auth/roles.ts"

function b64url(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input) : input
  return buf.toString("base64url")
}

function getJwtKey(): Buffer {
  const secret = process.env.JWT_SHARED_SECRET ?? ""
  if (!secret && process.env.NODE_ENV !== "production") return Buffer.from("dev-secret")
  if (!secret) throw new Error("JWT_SHARED_SECRET is not set")
  if (/^[0-9a-f]{64}$/i.test(secret)) {
    return Buffer.from(secret, "hex")
  }
  return Buffer.from(secret, "utf8")
}

export function signInternalJwt(sub: string, role: UserRole, roleId?: string | null): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))
  const now = Math.floor(Date.now() / 1000)
  const payload = b64url(
    JSON.stringify({ sub, role, roleId: roleId ?? undefined, iat: now, exp: now + 30 })
  )
  const sig = b64url(
    createHmac("sha256", getJwtKey()).update(`${header}.${payload}`).digest()
  )
  return `${header}.${payload}.${sig}`
}

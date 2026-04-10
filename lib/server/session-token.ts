import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto"
import type { UserRole } from "../shared/auth/roles.ts"
import type { UserStatus } from "./auth/users.ts"

export interface SessionPayload {
  userId: string
  username: string
  role: UserRole
  roleId?: string | null
  status: UserStatus
  sessionVersion: number
  exp: number
}

export interface MfaPendingPayload {
  userId: string
  exp: number
  purpose: "mfa_pending"
}

export type AnySessionPayload = SessionPayload | MfaPendingPayload

export function encryptMfaSession(payload: MfaPendingPayload): string {
  const key = getKey()
  const iv = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", key, iv)
  const json = JSON.stringify(payload)
  const encrypted = Buffer.concat([cipher.update(json, "utf8"), cipher.final()])
  const tag = cipher.getAuthTag()
  return `${iv.toString("hex")}.${encrypted.toString("hex")}.${tag.toString("hex")}`
}

export function decryptMfaSession(token: string): MfaPendingPayload | null {
  try {
    const parts = token.split(".")
    if (parts.length !== 3) return null
    const [ivHex, ciphertextHex, tagHex] = parts
    const key = getKey()
    const iv = Buffer.from(ivHex, "hex")
    const ciphertext = Buffer.from(ciphertextHex, "hex")
    const tag = Buffer.from(tagHex, "hex")

    const decipher = createDecipheriv("aes-256-gcm", key, iv)
    decipher.setAuthTag(tag)
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    const payload = JSON.parse(decrypted.toString("utf8")) as MfaPendingPayload

    if (payload.purpose !== "mfa_pending") return null
    if (payload.exp < Math.floor(Date.now() / 1000)) return null
    return payload
  } catch {
    return null
  }
}

function getKey(): Buffer {
  const secret = process.env.SESSION_SECRET || ""

  if (!secret && process.env.NODE_ENV === "production") {
    throw new Error("SESSION_SECRET must be set in production")
  }

  if (/^[0-9a-f]{64}$/i.test(secret)) {
    return Buffer.from(secret, "hex")
  }
  return createHash("sha256").update(secret).digest()
}

export function encryptSession(payload: SessionPayload): string {
  const key = getKey()
  const iv = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", key, iv)
  const json = JSON.stringify(payload)
  const encrypted = Buffer.concat([cipher.update(json, "utf8"), cipher.final()])
  const tag = cipher.getAuthTag()
  return `${iv.toString("hex")}.${encrypted.toString("hex")}.${tag.toString("hex")}`
}

export function decryptSession(token: string): SessionPayload | null {
  try {
    const parts = token.split(".")
    if (parts.length !== 3) return null
    const [ivHex, ciphertextHex, tagHex] = parts
    const key = getKey()
    const iv = Buffer.from(ivHex, "hex")
    const ciphertext = Buffer.from(ciphertextHex, "hex")
    const tag = Buffer.from(tagHex, "hex")

    const decipher = createDecipheriv("aes-256-gcm", key, iv)
    decipher.setAuthTag(tag)
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    const payload = JSON.parse(decrypted.toString("utf8")) as SessionPayload

    if (payload.exp < Math.floor(Date.now() / 1000)) return null
    return payload
  } catch {
    return null
  }
}

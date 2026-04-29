"use client"

import { useEffect, useRef, useState } from "react"
import { fetchCurrentUser, type CurrentUser } from "@/lib/client/auth"
import { EmailModal } from "./EmailModal"
import { PasswordModal } from "./PasswordModal"
import { TotpSetupModal } from "./TotpSetupModal"
import { UsernameModal } from "./UsernameModal"
import { Dialog } from "@/components/layout/Dialog"
import { sectionHeadingClass } from "@/lib/shared/settings-styles"
import { useLicense } from "@/lib/client/license/client"
import Link from "next/link"

type OpenModal = "username" | "email" | "password" | "totp" | null
const actionBtnClass =
  "rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm font-medium text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)]"

function SettingsRow({
  label,
  description,
  value,
  action,
}: {
  label: string
  description: string
  value: React.ReactNode
  action: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-4">
      <div className="min-w-0">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">{label}</p>
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">{description}</p>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <span className="text-sm text-[var(--color-text-secondary)]">{value}</span>
        {action}
      </div>
    </div>
  )
}

export function AccountContent() {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [loading, setLoading] = useState(true)
  const [openModal, setOpenModal] = useState<OpenModal>(null)
  const { tier } = useLicense()
  const isEnterprise = tier === "enterprise"

  const [avatarUploading, setAvatarUploading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Dialog state
  const [showConfirmDisableTotp, setShowConfirmDisableTotp] = useState(false)
  const [showErrorDialog, setShowErrorDialog] = useState<string | null>(null)

  async function loadUser() {
    const currentUser = await fetchCurrentUser()
    setUser(currentUser)
    setLoading(false)
  }

  useEffect(() => {
    void loadUser()
  }, [])

  async function handleAvatarChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    if (!file.type.startsWith("image/")) {
      setShowErrorDialog("Please select an image file.")
      return
    }
    if (file.size > 100_000) {
      setShowErrorDialog("Image too large. Max 100KB.")
      return
    }
    setAvatarUploading(true)
    try {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = () => resolve(reader.result as string)
        reader.onerror = reject
        reader.readAsDataURL(file)
      })
      const res = await fetch("/api/settings/account/avatar", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ avatarUrl: dataUrl }),
      })
      if (res.ok) await loadUser()
      else setShowErrorDialog("Failed to upload avatar.")
    } catch {
      setShowErrorDialog("Failed to upload avatar.")
    } finally {
      setAvatarUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ""
    }
  }

  async function handleRemoveAvatar() {
    setAvatarUploading(true)
    try {
      const res = await fetch("/api/settings/account/avatar", { method: "DELETE" })
      if (res.ok) await loadUser()
      else setShowErrorDialog("Failed to remove avatar.")
    } catch {
      setShowErrorDialog("Failed to remove avatar.")
    } finally {
      setAvatarUploading(false)
    }
  }

  async function handleDisableTotp() {
    setShowConfirmDisableTotp(false)
    const res = await fetch("/api/settings/account/totp", { method: "DELETE" })
    if (res.ok) {
      await loadUser()
    } else {
      setShowErrorDialog("Failed to disable two-factor authentication.")
    }
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-10 animate-pulse rounded-lg bg-[var(--color-surface-raised)]" />
        <div className="h-24 animate-pulse rounded-lg bg-[var(--color-surface-raised)]" />
      </div>
    )
  }
  if (!user) return null

  return (
    <div className="space-y-8">
      <Dialog
        open={showConfirmDisableTotp}
        onClose={() => setShowConfirmDisableTotp(false)}
        onConfirm={handleDisableTotp}
        title="Remove Two-Factor Authentication"
        description="This will remove two-factor authentication from your account. Your account will be less secure."
        confirmLabel="Remove 2FA"
        variant="danger"
      />
      <Dialog
        open={showErrorDialog !== null}
        onClose={() => setShowErrorDialog(null)}
        title="Error"
        description={showErrorDialog ?? ""}
        confirmLabel="OK"
      />

      {/* Profile photo */}
      <div>
        <p className={sectionHeadingClass}>Profile</p>
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-4">
          <div className="flex items-center gap-4">
            <div className="relative">
              {user.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.username}
                  className="h-16 w-16 rounded-full object-cover"
                />
              ) : (
                <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--color-accent)] text-lg font-bold text-[var(--color-accent-on)]">
                  {user.username.slice(0, 2).toUpperCase()}
                </div>
              )}
              {avatarUploading && (
                <div className="absolute inset-0 flex items-center justify-center rounded-full bg-[var(--color-bg)]/60">
                  <div className="h-5 w-5 rounded-full border-2 border-[var(--color-accent)] border-t-transparent motion-safe:animate-spin" />
                </div>
              )}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-[var(--color-text-primary)]">{user.username}</p>
              <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
                {user.avatarUrl ? "JPG, PNG, or GIF. Max 100KB." : "Add a profile photo. JPG, PNG, or GIF. Max 100KB."}
              </p>
              <div className="mt-2 flex items-center gap-2">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/gif,image/webp"
                  onChange={handleAvatarChange}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={avatarUploading}
                  className={`${actionBtnClass} text-xs`}
                >
                  {user.avatarUrl ? "Change" : "Upload"}
                </button>
                {user.avatarUrl && (
                  <button
                    type="button"
                    onClick={handleRemoveAvatar}
                    disabled={avatarUploading}
                    className="text-xs font-medium text-red-500 transition-colors hover:text-red-600"
                  >
                    Remove
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div>
        <p className={sectionHeadingClass}>Account</p>
        <div className="divide-y divide-[var(--color-border)] rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
          <SettingsRow
            label="Username"
            description="Your login name."
            value={user.username}
            action={
              <button type="button" onClick={() => setOpenModal("username")} className={actionBtnClass}>
                Edit
              </button>
            }
          />
          <SettingsRow
            label="Email"
            description="Used to sign in and receive notifications."
            value={user.email ?? <span className="italic text-[var(--color-text-secondary)]">Not set</span>}
            action={
              <button type="button" onClick={() => setOpenModal("email")} className={actionBtnClass}>
                {user.email ? "Edit" : "Add"}
              </button>
            }
          />
        </div>
      </div>

      <div>
        <p className={sectionHeadingClass}>Security</p>
        <div className="divide-y divide-[var(--color-border)] rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
          <SettingsRow
            label="Password"
            description="Used to sign in to your account."
            value="********"
            action={
              <button type="button" onClick={() => setOpenModal("password")} className={actionBtnClass}>
                Edit
              </button>
            }
          />
          <SettingsRow
            label="Two-factor authentication"
            description={isEnterprise ? "Add a one-time code requirement on every sign-in." : "Available on the Enterprise plan."}
            value={
              !isEnterprise ? (
                <span className="rounded-full bg-purple-500/10 px-2.5 py-0.5 text-xs font-semibold text-purple-500">
                  Enterprise
                </span>
              ) : user.totpEnabled ? (
                <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-500">
                  Enabled
                </span>
              ) : (
                <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 text-xs font-medium text-[var(--color-text-secondary)]">
                  Not set up
                </span>
              )
            }
            action={
              !isEnterprise ? (
                <Link
                  href="/settings/license"
                  className="rounded-lg border border-purple-500/20 px-3 py-1.5 text-sm font-semibold text-purple-500 transition-colors hover:bg-purple-500/5 focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
                >
                  Upgrade
                </Link>
              ) : user.totpEnabled ? (
                <button
                  type="button"
                  onClick={() => setShowConfirmDisableTotp(true)}
                  className="text-sm font-medium text-red-500 transition-colors hover:text-red-600"
                >
                  Remove
                </button>
              ) : (
                <button type="button" onClick={() => setOpenModal("totp")} className={actionBtnClass}>
                  Set up
                </button>
              )
            }
          />
        </div>
      </div>

      <div className="flex items-center justify-between border-t border-[var(--color-border)] pt-4">
        <div>
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Sign out</p>
          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
            End your current session.
          </p>
        </div>
        <button
          type="button"
          onClick={async () => {
            await fetch("/api/logout", { method: "POST" })
            window.location.href = "/login"
          }}
          className="rounded-lg border border-red-500/20 px-4 py-2 text-sm font-medium text-red-500 transition-colors hover:border-red-500/30 hover:bg-red-500/5"
        >
          Sign out
        </button>
      </div>

      {openModal === "email" && (
        <EmailModal
          initialEmail={user.email ?? null}
          onClose={() => setOpenModal(null)}
          onSuccess={async () => {
            setOpenModal(null)
            await loadUser()
          }}
        />
      )}
      {openModal === "username" && (
        <UsernameModal
          initialUsername={user.username}
          onClose={() => setOpenModal(null)}
          onSuccess={async () => {
            setOpenModal(null)
            await loadUser()
          }}
        />
      )}
      {openModal === "password" && (
        <PasswordModal
          username={user.username}
          onClose={() => setOpenModal(null)}
          onSuccess={() => setOpenModal(null)}
        />
      )}
      {openModal === "totp" && (
        <TotpSetupModal
          onClose={() => setOpenModal(null)}
          onSuccess={async () => {
            setOpenModal(null)
            await loadUser()
          }}
        />
      )}
    </div>
  )
}

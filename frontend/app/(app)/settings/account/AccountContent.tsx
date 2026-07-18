"use client"

import { useEffect, useRef, useState } from "react"
import { fetchCurrentUser, type CurrentUser } from "@/lib/client/auth"
import { apiClient } from "@/lib/client/api-client.ts"
import { Button, Spinner } from "@/components/ui/Button"
import { Skeleton } from "@/components/ui/Skeleton"
import { StatusBadge } from "@/components/ui/StatusBadge"
import { EmailModal } from "./EmailModal"
import { DisableTotpModal } from "./DisableTotpModal"
import { PasswordModal } from "./PasswordModal"
import { TotpSetupModal } from "./TotpSetupModal"
import { UsernameModal } from "./UsernameModal"
import { Dialog } from "@/components/layout/Dialog"
import { SettingsCard } from "@/components/settings/SettingsCard"
import { SettingsRow } from "@/components/settings/SettingsRow"

type OpenModal = "username" | "email" | "password" | "totp" | null

/**
 * Identity + authentication editor. Rendered inside the Security section modal
 * as two inner sub-cards (Identity, Authentication). The component owns the
 * /me load, avatar upload, and the credential modals.
 */
export function AccountContent({ children }: { children?: React.ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [loading, setLoading] = useState(true)
  const [openModal, setOpenModal] = useState<OpenModal>(null)

  const [avatarUploading, setAvatarUploading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

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
      try {
        await apiClient("/api/v1/settings/account/avatar", {
          method: "PUT",
          body: { avatarUrl: dataUrl },
        })
        await loadUser()
      } catch {
        setShowErrorDialog("Failed to upload avatar.")
        return
      }
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
      await apiClient("/api/v1/settings/account/avatar", { method: "DELETE" })
      await loadUser()
    } catch {
      setShowErrorDialog("Failed to remove avatar.")
    } finally {
      setAvatarUploading(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-20 rounded-md" />
        <Skeleton className="h-24 rounded-md" />
      </div>
    )
  }
  if (!user) return null

  return (
    <>
      <DisableTotpModal
        open={showConfirmDisableTotp}
        onClose={() => setShowConfirmDisableTotp(false)}
        onSuccess={async () => {
          setShowConfirmDisableTotp(false)
          await loadUser()
        }}
      />
      <Dialog
        open={showErrorDialog !== null}
        onClose={() => setShowErrorDialog(null)}
        title="Error"
        description={showErrorDialog ?? ""}
        confirmLabel="OK"
      />

      <SettingsCard heading="Profile">
        <div className="flex items-center gap-4 border-b border-[var(--color-border)] px-4 py-4">
          <div className="relative">
            {user.avatarUrl ? (
              <img
                src={user.avatarUrl}
                alt={user.username}
                className="h-14 w-14 rounded-full object-cover"
              />
            ) : (
              <div className="grid h-14 w-14 place-items-center rounded-full bg-[var(--color-accent)] text-base font-bold text-[var(--color-accent-on)]">
                {user.username.slice(0, 2).toUpperCase()}
              </div>
            )}
            {avatarUploading && (
              <div className="absolute inset-0 flex items-center justify-center rounded-full bg-[var(--color-bg)]/60">
                <Spinner className="h-5 w-5 text-[var(--color-accent)]" />
              </div>
            )}
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-[var(--color-text-primary)]">
              {user.username}
            </p>
            <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
              {user.avatarUrl
                ? "JPG, PNG, or GIF · max 100KB"
                : "Add a profile photo: JPG, PNG, or GIF · max 100KB"}
            </p>
            <div className="mt-2 flex items-center gap-3">
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/gif,image/webp"
                onChange={handleAvatarChange}
                className="hidden"
              />
              <Button
                variant="secondary"
                size="xs"
                onClick={() => fileInputRef.current?.click()}
                disabled={avatarUploading}
              >
                {user.avatarUrl ? "Change" : "Upload"}
              </Button>
              {user.avatarUrl && (
                <Button
                  variant="ghost"
                  size="xs"
                  onClick={handleRemoveAvatar}
                  disabled={avatarUploading}
                  className="text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical-text)]"
                >
                  Remove
                </Button>
              )}
            </div>
          </div>
        </div>
        <SettingsRow label="Username" description="Your login name">
          <span className="text-sm text-[var(--color-text-secondary)]">
            {user.username}
          </span>
          <Button variant="secondary" size="xs" onClick={() => setOpenModal("username")}>
            Edit
          </Button>
        </SettingsRow>
        <SettingsRow
          label="Email"
          description="Used to sign in and receive notifications"
        >
          <span className="text-sm text-[var(--color-text-secondary)]">
            {user.email ?? (
              <span className="italic text-[var(--color-text-tertiary)]">
                Not set
              </span>
            )}
          </span>
          <Button variant="secondary" size="xs" onClick={() => setOpenModal("email")}>
            {user.email ? "Edit" : "Add"}
          </Button>
        </SettingsRow>
        {/* Preferences (time zone / theme) are injected here so they share the
            Profile card rather than sitting in a separate card. */}
        {children}
      </SettingsCard>

      <SettingsCard heading="Authentication">
        <SettingsRow label="Password" description="Used to sign in to your account">
          <span className="text-sm text-[var(--color-text-secondary)]">
            ••••••••
          </span>
          <Button variant="secondary" size="xs" onClick={() => setOpenModal("password")}>
            Edit
          </Button>
        </SettingsRow>
        <SettingsRow
          label="Two-factor authentication"
          description="Require a one-time code on every sign-in"
        >
          {user.totpEnabled ? (
            <>
              <StatusBadge tone="ok">Enabled</StatusBadge>
              <Button
                variant="ghost"
                size="xs"
                onClick={() => setShowConfirmDisableTotp(true)}
                className="text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical-text)]"
              >
                Remove
              </Button>
            </>
          ) : (
            <>
              <StatusBadge tone="neutral">Not set up</StatusBadge>
              <Button variant="secondary" size="xs" onClick={() => setOpenModal("totp")}>
                Set up
              </Button>
            </>
          )}
        </SettingsRow>
      </SettingsCard>

      <EmailModal
        open={openModal === "email"}
        initialEmail={user.email ?? null}
        onClose={() => setOpenModal(null)}
        onSuccess={async () => {
          setOpenModal(null)
          await loadUser()
        }}
      />
      <UsernameModal
        open={openModal === "username"}
        initialUsername={user.username}
        onClose={() => setOpenModal(null)}
        onSuccess={async () => {
          setOpenModal(null)
          await loadUser()
        }}
      />
      <PasswordModal
        open={openModal === "password"}
        username={user.username}
        onClose={() => setOpenModal(null)}
        onSuccess={() => setOpenModal(null)}
      />
      <TotpSetupModal
        open={openModal === "totp"}
        onClose={() => setOpenModal(null)}
        onSuccess={async () => {
          setOpenModal(null)
          await loadUser()
        }}
      />
    </>
  )
}

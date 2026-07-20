"use client"

import { useEffect, useRef, useState } from "react"
import Link from "next/link"
import { useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/Button"

type Status = "pending" | "success" | "error"

export function VerifyEmailClient() {
  const params = useSearchParams()
  const token = params.get("token") ?? ""
  const [status, setStatus] = useState<Status>("pending")
  const [message, setMessage] = useState("Confirming your new email address…")
  // Confirm exactly once per mount, even under React strict-mode double-invoke.
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true

    if (!token) {
      setStatus("error")
      setMessage("This link is missing its verification token.")
      return
    }

    void (async () => {
      try {
        const resp = await fetch("/api/v1/auth/email/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ token }),
        })
        if (resp.ok) {
          setStatus("success")
          setMessage("Your email address has been updated.")
        } else {
          const data = await resp.json().catch(() => null)
          setStatus("error")
          setMessage(data?.detail || "This verification link is invalid or has expired.")
        }
      } catch {
        setStatus("error")
        setMessage("Could not reach the server. Please try again.")
      }
    })()
  }, [token])

  return (
    <div className="text-center">
      <h1 className="text-xl font-bold text-[var(--color-text-primary)]">
        {status === "success" ? "Email confirmed" : "Email verification"}
      </h1>
      <p
        className="mt-2 text-sm text-[var(--color-text-secondary)]"
        role={status === "error" ? "alert" : "status"}
        aria-live="polite"
      >
        {message}
      </p>
      {status !== "pending" && (
        <div className="mt-6">
          <Link href="/settings/account">
            <Button variant="primary" size="md" className="w-full">
              Go to account settings
            </Button>
          </Link>
        </div>
      )}
    </div>
  )
}

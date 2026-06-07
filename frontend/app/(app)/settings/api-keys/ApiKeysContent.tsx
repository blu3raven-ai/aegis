"use client"

import { useEffect, useState, type MutableRefObject } from "react"
import { listApiKeys, createApiKey, revokeApiKey, type ApiKey, type CreatedApiKey } from "@/lib/client/api-keys-api"
import { ApiKeysTable } from "@/components/shared/api-keys/ApiKeysTable"
import { CreateApiKeyDialog } from "@/components/shared/api-keys/CreateApiKeyDialog"
import { CreatedKeyDialog } from "@/components/shared/api-keys/CreatedKeyDialog"
import { RevokeKeyConfirmDialog } from "@/components/shared/api-keys/RevokeKeyConfirmDialog"
import { EmptyApiKeysState } from "@/components/shared/api-keys/EmptyApiKeysState"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

interface ApiKeysContentProps {
  /**
   * When provided, the section's "Create token" button lives in the parent
   * SettingsSection header instead of in its own row.
   */
  createTriggerRef?: MutableRefObject<(() => void) | null>
}

export function ApiKeysContent({ createTriggerRef }: ApiKeysContentProps = {}) {
  const [keys, setKeys] = useState<ApiKey[] | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [createdToken, setCreatedToken] = useState<string | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<ApiKey | null>(null)

  async function load() {
    const data = await listApiKeys(ORG_ID)
    setKeys(data)
  }

  useEffect(() => {
    void load()
  }, [])

  useEffect(() => {
    if (!createTriggerRef) return
    createTriggerRef.current = () => setShowCreate(true)
    return () => {
      createTriggerRef.current = null
    }
  }, [createTriggerRef])

  async function handleCreate(payload: {
    name: string
    scopes: string[]
    expires_in_days: number | null
  }) {
    const created: CreatedApiKey = await createApiKey(ORG_ID, payload)
    setShowCreate(false)
    setCreatedToken(created.token)
    void load()
  }

  async function handleRevoke() {
    if (!revokeTarget) return
    await revokeApiKey(revokeTarget.id, ORG_ID)
    setRevokeTarget(null)
    void load()
  }

  return (
    <div className="flex flex-col gap-6">
      {!createTriggerRef && (
        <div className="flex items-center justify-between">
          <button
            onClick={() => setShowCreate(true)}
            className="ml-auto rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-medium text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]"
          >
            Create Token
          </button>
        </div>
      )}

      {keys !== null && keys.length === 0 ? (
        <EmptyApiKeysState />
      ) : (
        <ApiKeysTable keys={keys} onRevoke={setRevokeTarget} />
      )}

      <CreateApiKeyDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onSubmit={handleCreate}
      />

      {createdToken && (
        <CreatedKeyDialog
          token={createdToken}
          onClose={() => setCreatedToken(null)}
        />
      )}

      <RevokeKeyConfirmDialog
        apiKey={revokeTarget}
        onConfirm={handleRevoke}
        onCancel={() => setRevokeTarget(null)}
      />
    </div>
  )
}

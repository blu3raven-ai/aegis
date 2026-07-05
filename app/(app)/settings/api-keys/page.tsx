"use client"

import { useEffect, useState } from "react"
import { listApiKeys, createApiKey, revokeApiKey, type ApiKey, type CreatedApiKey } from "@/lib/client/api-keys-api"
import { ApiKeysTable } from "@/components/shared/api-keys/ApiKeysTable"
import { CreateApiKeyDialog } from "@/components/shared/api-keys/CreateApiKeyDialog"
import { CreatedKeyDialog } from "@/components/shared/api-keys/CreatedKeyDialog"
import { RevokeKeyConfirmDialog } from "@/components/shared/api-keys/RevokeKeyConfirmDialog"
import { EmptyApiKeysState } from "@/components/shared/api-keys/EmptyApiKeysState"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

export default function ApiKeysPage() {
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
    <div className="mx-auto max-w-5xl p-6 lg:p-10 flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">API Keys</h1>
          <p className="mt-0.5 text-sm text-[var(--color-text-secondary)]">
            Manage tokens for CLI tools, CI pipelines, and integrations.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-medium text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]"
        >
          Create API key
        </button>
      </div>

      {keys !== null && keys.length === 0 ? (
        <EmptyApiKeysState onCreate={() => setShowCreate(true)} />
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

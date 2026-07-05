"use client"

import { useEffect, useState } from "react"
import { listApiKeys, createApiKey, revokeApiKey, type ApiKey, type CreatedApiKey } from "@/lib/client/api-keys-api"
import { Button } from "@/components/ui/Button"
import { ApiKeysTable } from "@/components/shared/api-keys/ApiKeysTable"
import { CreateApiKeyDialog } from "@/components/shared/api-keys/CreateApiKeyDialog"
import { CreatedKeyDialog } from "@/components/shared/api-keys/CreatedKeyDialog"
import { RevokeKeyConfirmDialog } from "@/components/shared/api-keys/RevokeKeyConfirmDialog"
import { EmptyApiKeysState } from "@/components/shared/api-keys/EmptyApiKeysState"

export function ApiKeysContent() {
  const [keys, setKeys] = useState<ApiKey[] | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [createdToken, setCreatedToken] = useState<string | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<ApiKey | null>(null)

  async function load() {
    const data = await listApiKeys()
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
    const created: CreatedApiKey = await createApiKey(payload)
    setShowCreate(false)
    setCreatedToken(created.token)
    void load()
  }

  async function handleRevoke() {
    if (!revokeTarget) return
    await revokeApiKey(revokeTarget.id)
    setRevokeTarget(null)
    void load()
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <Button variant="primary" size="sm" className="ml-auto" onClick={() => setShowCreate(true)}>
          Create Token
        </Button>
      </div>

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

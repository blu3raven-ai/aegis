"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { PageHeader } from "@/components/layout/PageHeader"
import { ImagesIcon } from "@/lib/shared/ui/page-icons"
import { ImagesInventoryPanel } from "./ImagesInventoryPanel"
import { AddConnectionModal } from "@/components/sources/AddConnectionModal"

export function ImagesPageClient() {
  const [count, setCount] = useState<number | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  // Bumping this remounts ImagesInventoryPanel so it re-fetches after a new
  // connection is created. The panel doesn't expose an imperative reload API.
  const [reloadKey, setReloadKey] = useState(0)

  return (
    <>
      <PageHeader
        icon={<ImagesIcon />}
        title="Container images"
        description="OS-level vulns, misconfig, and secrets across your registries"
        count={count}
        controls={
          <Button
            variant="primary"
            size="sm"
            onClick={() => setShowAddModal(true)}
            leadingIcon={
              <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.25} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 5v14M5 12h14" />
              </svg>
            }
          >
            Add source
          </Button>
        }
      />
      <ImagesInventoryPanel key={reloadKey} onCountChange={setCount} />
      {showAddModal && (
        <AddConnectionModal
          lockedCategory="container-registry"
          onClose={() => setShowAddModal(false)}
          onCreated={() => {
            setShowAddModal(false)
            setReloadKey((k) => k + 1)
          }}
        />
      )}
    </>
  )
}

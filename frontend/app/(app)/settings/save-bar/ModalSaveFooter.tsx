"use client"

import { Button } from "@/components/ui/Button"
import { SaveBarContent, useSavedFlash } from "./SaveBarContent"
import { useSaveBarAggregate } from "./SaveBarProvider"

/**
 * Sticky footer for a settings section modal. Reads the modal-scoped save-bar
 * aggregate: when a section is dirty it shows the same "Unsaved changes ·
 * Discard · Save" row as the page-level GlobalSaveBar; otherwise it shows a
 * Close button. Sections that save immediately (no dirty state) only ever see
 * Close.
 */
export function ModalSaveFooter({ onClose }: { onClose: () => void }) {
  const { anyDirty, anySaving, totalCount, error, saveAll, discardAll } = useSaveBarAggregate()
  const showSaved = useSavedFlash(anySaving, anyDirty, error)
  const showSaveRow = anyDirty || anySaving || showSaved || !!error

  if (!showSaveRow) {
    return (
      <div className="flex justify-end">
        <Button variant="ghost" size="md" onClick={onClose}>
          Close
        </Button>
      </div>
    )
  }

  return (
    <SaveBarContent
      anyDirty={anyDirty}
      anySaving={anySaving}
      totalCount={totalCount}
      error={error}
      showSaved={showSaved}
      onDiscard={discardAll}
      onSave={() => void saveAll()}
    />
  )
}

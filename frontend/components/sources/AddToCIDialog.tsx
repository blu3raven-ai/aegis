"use client"
import { Dialog } from "@/components/layout/Dialog"
import { CiSnippetPicker, type ScmType } from "./CiSnippetPicker"

type Props = {
  open: boolean
  onClose: () => void
  sourceId: string
  defaultTab?: ScmType
}

export function AddToCIDialog({ open, onClose, sourceId, defaultTab }: Props) {
  return (
    <Dialog open={open} onClose={onClose} title="Add Aegis to your CI">
      <CiSnippetPicker sourceId={sourceId} defaultTab={defaultTab} />
    </Dialog>
  )
}

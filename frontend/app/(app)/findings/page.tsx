"use client"

import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"

export default function FindingsPage() {
  return <FindingsBoardView pageTitle="Findings" pageIcon={<FindingsIcon />} />
}

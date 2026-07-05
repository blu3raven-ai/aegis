"use client"

import { useHasPermission } from "@/lib/client/use-permission"
import { RunnersContent } from "../runners/RunnersContent"
import type { DetailComponentProps } from "../registry"

export function RunnersDetail(_: DetailComponentProps) {
  const { allowed: canEdit } = useHasPermission("manage_runners")
  return <RunnersContent canEdit={canEdit} />
}

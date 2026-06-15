"use client"

import { useEffect, useState } from "react"

import { listDestinations } from "@/lib/client/destinations-api"
import { RoutingView } from "../RoutingView"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

export default function RoutingPage() {
  // keyHint forces RoutingView to re-fetch when destinations change.
  // We track destination count to detect adds/removes from the Add channel modal.
  const [destCount, setDestCount] = useState(0)

  useEffect(() => {
    listDestinations(ORG_ID)
      .then((rows) => setDestCount(rows.length))
      .catch(() => {})
  }, [])

  return <RoutingView orgId={ORG_ID} keyHint={destCount} />
}

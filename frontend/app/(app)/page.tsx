import { Suspense } from "react"
import { HomeShell } from "./HomeShell"

export default function HomePage() {
  return (
    <Suspense fallback={null}>
      <HomeShell />
    </Suspense>
  )
}

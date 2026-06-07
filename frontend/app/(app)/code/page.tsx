import { redirect } from "next/navigation"

export const metadata = { title: "Code Scanning" }

export default function CodeLandingPage() {
  redirect("/findings?scanner=sast")
}

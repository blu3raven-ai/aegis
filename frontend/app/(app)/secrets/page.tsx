import { redirect } from "next/navigation"

export const metadata = { title: "Secret Scanning" }

export default function SecretsLandingPage() {
  redirect("/findings?scanner=secrets")
}

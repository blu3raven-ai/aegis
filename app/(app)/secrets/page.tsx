import { redirect } from "next/navigation"

export default function SecretsLandingPage() {
  redirect("/secrets/dashboard")
}

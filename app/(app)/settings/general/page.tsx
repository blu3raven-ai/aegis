import { redirect } from "next/navigation"

export default async function GeneralSettingsPage() {
  redirect("/settings/account")
}

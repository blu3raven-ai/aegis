import { redirect } from "next/navigation"

export const metadata = { title: "Repositories" }

export default function ReposIndexPage() {
  redirect("/sources?tab=repositories")
}

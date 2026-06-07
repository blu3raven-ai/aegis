import { redirect } from "next/navigation"

export default function SlaPoliciesRedirect() {
  redirect("/rules?category=sla")
}

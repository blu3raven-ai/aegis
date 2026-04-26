import { redirect } from "next/navigation"
import { getSession } from "@/lib/server/session"
import { getRoleCountServer, getTeamCountServer, getUserCountServer } from "@/lib/server/settings-api"
import { SidebarNav } from "./SidebarNav"

export default async function SettingsLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const session = await getSession()
  if (!session) redirect("/login")

  const [teamCount, roleCount, memberCount] = await Promise.all([
    getTeamCountServer({ id: session.userId, role: session.role, roleId: session.roleId }),
    getRoleCountServer({ id: session.userId, role: session.role, roleId: session.roleId }),
    getUserCountServer({ id: session.userId, role: session.role, roleId: session.roleId }),
  ])

  return (
    <div className="h-full md:flex min-h-0 overflow-hidden">
      <SidebarNav
        teamCount={teamCount}
        roleCount={roleCount}
        memberCount={memberCount}
      />
      <main className="flex-1 min-w-0 overflow-y-auto bg-[var(--color-bg)]">
        {children}
      </main>
    </div>
  )
}

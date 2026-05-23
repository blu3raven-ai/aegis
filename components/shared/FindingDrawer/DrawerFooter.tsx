// components/shared/FindingDrawer/DrawerFooter.tsx

export function DrawerFooter({ children }: { children: React.ReactNode }) {
  return (
    <div className="shrink-0 border-t border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      {children}
    </div>
  )
}

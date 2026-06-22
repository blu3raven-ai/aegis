"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react"

export interface SaveBarSection {
  id: string
  dirty: boolean
  saving: boolean
  count: number
  error: string | null
}

interface SectionRegistration extends SaveBarSection {
  onSave: () => Promise<void> | void
  onDiscard: () => void
}

interface SaveBarApiContextValue {
  register: (reg: SectionRegistration) => void
  unregister: (id: string) => void
}

// Stable context: register/unregister are memoised with [] deps and never
// change reference. useSaveBarSection reads only here so its effect deps
// don't fire when sections state changes, preventing a cascade re-register
// loop that previously caused an OOM renderer crash.
const SaveBarApiContext = createContext<SaveBarApiContextValue | null>(null)

// State context: a new Map reference each time any section mutates.
// Only useSaveBarAggregate (read-only) subscribes here.
const SaveBarStateContext = createContext<ReadonlyMap<string, SectionRegistration>>(new Map())

export function SaveBarProvider({ children }: { children: ReactNode }) {
  const [sections, setSections] = useState<ReadonlyMap<string, SectionRegistration>>(
    () => new Map(),
  )

  const register = useCallback((reg: SectionRegistration) => {
    setSections((prev) => {
      const next = new Map(prev)
      next.set(reg.id, reg)
      return next
    })
  }, [])

  const unregister = useCallback((id: string) => {
    setSections((prev) => {
      if (!prev.has(id)) return prev
      const next = new Map(prev)
      next.delete(id)
      return next
    })
  }, [])

  const apiValue = useMemo<SaveBarApiContextValue>(
    () => ({ register, unregister }),
    [register, unregister],
  )

  return (
    <SaveBarApiContext.Provider value={apiValue}>
      <SaveBarStateContext.Provider value={sections}>
        {children}
      </SaveBarStateContext.Provider>
    </SaveBarApiContext.Provider>
  )
}

interface UseSaveBarSectionArgs {
  id: string
  dirty: boolean
  saving?: boolean
  count?: number
  error?: string | null
  onSave: () => Promise<void> | void
  onDiscard: () => void
}

// Sections that own draft state register here so the GlobalSaveBar at the
// settings layout root can aggregate dirty counts and fire save/discard for
// every dirty section in one shot. Closures are held in refs so the section
// only re-registers when its observable state (dirty/saving/count/error)
// actually changes, not on every parent render.
export function useSaveBarSection({
  id,
  dirty,
  saving = false,
  count = 0,
  error = null,
  onSave,
  onDiscard,
}: UseSaveBarSectionArgs) {
  const ctx = useContext(SaveBarApiContext)
  const onSaveRef = useRef(onSave)
  const onDiscardRef = useRef(onDiscard)
  onSaveRef.current = onSave
  onDiscardRef.current = onDiscard

  useEffect(() => {
    if (!ctx) return
    ctx.register({
      id,
      dirty,
      saving,
      count,
      error,
      onSave: () => onSaveRef.current(),
      onDiscard: () => onDiscardRef.current(),
    })
    return () => ctx.unregister(id)
  }, [ctx, id, dirty, saving, count, error])
}

export interface SaveBarAggregate {
  anyDirty: boolean
  anySaving: boolean
  totalCount: number
  error: string | null
  saveAll: () => Promise<void>
  discardAll: () => void
}

export function useSaveBarAggregate(): SaveBarAggregate {
  const sections = useContext(SaveBarStateContext)

  return useMemo<SaveBarAggregate>(() => {
    const list = Array.from(sections.values())
    const dirtySections = list.filter((s) => s.dirty)
    const anyDirty = dirtySections.length > 0
    const anySaving = list.some((s) => s.saving)
    const totalCount = dirtySections.reduce((sum, s) => sum + Math.max(0, s.count), 0)
    const error = list.find((s) => s.error)?.error ?? null

    const saveAll = async () => {
      await Promise.allSettled(dirtySections.map((s) => Promise.resolve(s.onSave())))
    }
    const discardAll = () => {
      dirtySections.forEach((s) => s.onDiscard())
    }

    return { anyDirty, anySaving, totalCount, error, saveAll, discardAll }
  }, [sections])
}

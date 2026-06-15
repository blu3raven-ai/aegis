"use client"

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useCallback,
  type ReactNode,
} from "react"
import type { SSEEventMap, SSEEventType } from "@/lib/shared/sse-types"

type Listener<T extends SSEEventType = SSEEventType> = (data: SSEEventMap[T]) => void

interface SSEContextValue {
  subscribe: <T extends SSEEventType>(eventType: T, listener: Listener<T>) => () => void
  connected: boolean
}

const SSEContext = createContext<SSEContextValue | null>(null)

const CHANNEL_NAME = "aegis-sse"
const RECONNECT_JITTER_MS = 3000
const FALLBACK_AFTER_FAILURES = 3

export function SSEProvider({ children }: { children: ReactNode }) {
  const listenersRef = useRef<Map<string, Set<Listener<any>>>>(new Map())
  const connectedRef = useRef(false)
  const isLeaderRef = useRef(false)
  const failCountRef = useRef(0)
  const eventSourceRef = useRef<EventSource | null>(null)
  const channelRef = useRef<BroadcastChannel | null>(null)

  const dispatch = useCallback((eventType: string, data: unknown) => {
    const listeners = listenersRef.current.get(eventType)
    if (listeners) {
      for (const fn of listeners) {
        try { fn(data) } catch { /* ignore listener errors */ }
      }
    }
  }, [])

  const handleSSEMessage = useCallback((eventType: string, data: string) => {
    try {
      const parsed = JSON.parse(data)
      dispatch(eventType, parsed)
      channelRef.current?.postMessage({ eventType, data: parsed })
    } catch { /* ignore parse errors */ }
  }, [dispatch])

  // BroadcastChannel for cross-tab sharing
  useEffect(() => {
    if (typeof BroadcastChannel === "undefined") return

    const channel = new BroadcastChannel(CHANNEL_NAME)
    channelRef.current = channel

    channel.onmessage = (e: MessageEvent) => {
      const { eventType, data, type } = e.data ?? {}
      if (type === "leader-ping") {
        if (isLeaderRef.current) {
          channel.postMessage({ type: "leader-pong" })
        }
        return
      }
      if (type === "leader-pong") return
      if (type === "leader-down") {
        tryBecomeLeader()
        return
      }
      if (eventType && data) {
        dispatch(eventType, data)
      }
    }

    return () => {
      if (isLeaderRef.current) {
        channel.postMessage({ type: "leader-down" })
      }
      channel.close()
      channelRef.current = null
    }
  }, [dispatch])

  // Leader election
  const tryBecomeLeader = useCallback(() => {
    if (isLeaderRef.current) return
    const channel = channelRef.current
    if (!channel) {
      isLeaderRef.current = true
      openEventSource()
      return
    }

    let gotPong = false
    const handler = (e: MessageEvent) => {
      if (e.data?.type === "leader-pong") gotPong = true
    }
    channel.addEventListener("message", handler)
    channel.postMessage({ type: "leader-ping" })

    setTimeout(() => {
      channel.removeEventListener("message", handler)
      if (!gotPong) {
        isLeaderRef.current = true
        openEventSource()
      }
    }, 200)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // EventSource connection
  const openEventSource = useCallback(() => {
    if (eventSourceRef.current) return

    const jitter = Math.random() * RECONNECT_JITTER_MS
    setTimeout(() => {
      const es = new EventSource("/api/v1/events/stream")
      eventSourceRef.current = es

      const eventTypes: SSEEventType[] = [
        "scan.progress", "scan.completed", "scan.failed",
        "source.synced", "runner.status", "notification.new",
      ]
      for (const et of eventTypes) {
        es.addEventListener(et, ((e: MessageEvent) => {
          failCountRef.current = 0
          handleSSEMessage(et, e.data)
        }) as EventListener)
      }

      es.onopen = () => {
        connectedRef.current = true
        failCountRef.current = 0
      }

      es.onerror = () => {
        connectedRef.current = false
        failCountRef.current += 1
        if (failCountRef.current >= FALLBACK_AFTER_FAILURES) {
          es.close()
          eventSourceRef.current = null
          isLeaderRef.current = false
        }
      }
    }, jitter)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [handleSSEMessage])

  // Visibility change: sync on tab foreground
  useEffect(() => {
    function onVisible() {
      if (document.visibilityState === "visible") {
        dispatch("scan.progress", { _refresh: true })
      }
    }
    document.addEventListener("visibilitychange", onVisible)
    return () => document.removeEventListener("visibilitychange", onVisible)
  }, [dispatch])

  // Startup
  useEffect(() => {
    tryBecomeLeader()
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
    }
  }, [tryBecomeLeader])

  // Context value
  const subscribe = useCallback(<T extends SSEEventType>(
    eventType: T,
    listener: Listener<T>,
  ): (() => void) => {
    const listeners = listenersRef.current
    if (!listeners.has(eventType)) {
      listeners.set(eventType, new Set())
    }
    listeners.get(eventType)!.add(listener as Listener<any>)
    return () => {
      listeners.get(eventType)?.delete(listener as Listener<any>)
    }
  }, [])

  const value: SSEContextValue = {
    subscribe,
    connected: connectedRef.current,
  }

  return <SSEContext.Provider value={value}>{children}</SSEContext.Provider>
}

// Hook
export function useSSE<T extends SSEEventType>(
  eventType: T,
  handler: (data: SSEEventMap[T]) => void,
): void {
  const ctx = useContext(SSEContext)
  const handlerRef = useRef(handler)
  handlerRef.current = handler

  useEffect(() => {
    if (!ctx) return
    return ctx.subscribe(eventType, (data) => handlerRef.current(data))
  }, [ctx, eventType])
}

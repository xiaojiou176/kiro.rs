import { useEffect, useMemo, useRef, useState } from 'react'
import type { AccountState, ObservabilitySnapshot } from '@/types/api'
import { normalizeAccount, normalizeSnapshot } from '@/lib/observability-normalize'

const WINDOW_MS = 15 * 60 * 1000

export interface AccountHistorySlice {
  id: number
  rateRps: number
  safeLo: number
  safeHi: number
  inflight: number
  maxInflight: number
  state: AccountState
  rpm: number
  upstream429: number
}

export interface ObservabilityHistoryPoint {
  ts: number
  label: string
  global429: number
  totalRateRps: number
  accounts: Record<number, AccountHistorySlice>
}

export interface StateTransitionMarker {
  ts: number
  label: string
  accountId: number
  from: AccountState
  to: AccountState
}

export interface SessionMigration {
  sessionId: string
  fromAccountId: number
  toAccountId: number
  at: number
  reason: 'forced_open'
}

function formatLabel(ts: number): string {
  const d = new Date(ts)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

function snapshotToPoint(
  snap: ObservabilitySnapshot,
  ts: number,
): ObservabilityHistoryPoint {
  const accounts: Record<number, AccountHistorySlice> = {}
  let totalRateRps = 0
  for (const raw of snap.accounts) {
    const a = normalizeAccount(raw)
    if (a.disabled || a.state === 'DISABLED') continue
    accounts[a.id] = {
      id: a.id,
      rateRps: a.currentRateRps,
      safeLo: a.learnedSafeRpsLo,
      safeHi: a.learnedSafeRpsHi,
      inflight: a.currentInflight,
      maxInflight: a.currentMaxInflight,
      state: a.state,
      rpm: a.rpm,
      upstream429: a.upstream429Rate5m,
    }
    totalRateRps += a.currentRateRps
  }
  return {
    ts,
    label: formatLabel(ts),
    global429: snap.globalUpstream429Rate5m ?? 0,
    totalRateRps,
    accounts,
  }
}

export function useObservabilityHistory(
  data: ObservabilitySnapshot | undefined,
  dataUpdatedAt: number,
) {
  const [history, setHistory] = useState<ObservabilityHistoryPoint[]>([])
  const [stateMarkers, setStateMarkers] = useState<StateTransitionMarker[]>([])
  const [sessionMigrations, setSessionMigrations] = useState<
    Map<string, SessionMigration>
  >(new Map())

  const prevStatesRef = useRef<Map<number, AccountState>>(new Map())
  const prevSessionsRef = useRef<Record<string, number>>({})

  useEffect(() => {
    if (!data) return
    const snap = normalizeSnapshot(data)
    const now = Date.now()
    const point = snapshotToPoint(snap, now)

    const prevStates = prevStatesRef.current
    const newMarkers: StateTransitionMarker[] = []
    for (const a of snap.accounts) {
      const norm = normalizeAccount(a)
      const prev = prevStates.get(norm.id)
      if (prev != null && prev !== norm.state) {
        newMarkers.push({
          ts: now,
          label: point.label,
          accountId: norm.id,
          from: prev,
          to: norm.state,
        })
      }
      prevStates.set(norm.id, norm.state)
    }

    if (newMarkers.length > 0) {
      setStateMarkers((prev) => {
        const merged = [...prev, ...newMarkers]
        const cutoff = now - WINDOW_MS
        return merged.filter((m) => m.ts >= cutoff)
      })
    }

    const prevSessions = prevSessionsRef.current
    const openIds = new Set(
      snap.accounts
        .filter((a) => normalizeAccount(a).state === 'OPEN')
        .map((a) => a.id),
    )
    const migrations = new Map<string, SessionMigration>()
    for (const [sid, accountId] of Object.entries(snap.sessionToAccount)) {
      const prevId = prevSessions[sid]
      if (
        prevId != null &&
        prevId !== accountId &&
        openIds.has(prevId)
      ) {
        migrations.set(sid, {
          sessionId: sid,
          fromAccountId: prevId,
          toAccountId: accountId,
          at: now,
          reason: 'forced_open',
        })
      }
    }
    if (migrations.size > 0) {
      setSessionMigrations((prev) => {
        const next = new Map(prev)
        for (const [k, v] of migrations) next.set(k, v)
        return next
      })
    }
    prevSessionsRef.current = { ...snap.sessionToAccount }

    setHistory((prev) => {
      const last = prev.length > 0 ? prev[prev.length - 1] : undefined
      if (last && now - last.ts < 4000) {
        const replaced = [...prev.slice(0, -1), point]
        const cutoff = now - WINDOW_MS
        return replaced.filter((p) => p.ts >= cutoff)
      }
      const next = [...prev, point]
      const cutoff = now - WINDOW_MS
      return next.filter((p) => p.ts >= cutoff)
    })
  }, [data, dataUpdatedAt])

  const accountIds = useMemo(() => {
    const ids = new Set<number>()
    for (const p of history) {
      for (const id of Object.keys(p.accounts)) ids.add(Number(id))
    }
    return Array.from(ids).sort((a, b) => a - b)
  }, [history])

  const lastUpdated = history.length > 0 ? history[history.length - 1].ts : undefined

  return {
    history,
    stateMarkers,
    sessionMigrations,
    accountIds,
    lastUpdated,
    windowMinutes: WINDOW_MS / 60_000,
  }
}

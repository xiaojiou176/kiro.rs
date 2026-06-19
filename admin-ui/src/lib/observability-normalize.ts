import type {
  AccountObservability,
  AccountState,
  BottleneckDimension,
  ObservabilitySnapshot,
} from '@/types/api'

const DEFAULT_STATE: AccountState = 'HEALTHY'
const DEFAULT_BOTTLENECK: BottleneckDimension = 'Mixed'

/** 归一化后的账号观测（所有调度字段保证有值） */
export type NormalizedAccountObservability = Required<
  Pick<
    AccountObservability,
    | 'state'
    | 'stateReason'
    | 'reopenInMs'
    | 'currentMaxInflight'
    | 'currentInflight'
    | 'currentRateRps'
    | 'learnedSafeRpsLo'
    | 'learnedSafeRpsHi'
    | 'p80HeldMs'
    | 'learnedOptimalTSecs'
    | 'bottleneckDimension'
    | 'upstream429Rate5m'
    | 'consecutiveThrottles'
  >
> &
  AccountObservability

export function normalizeAccount(raw: AccountObservability): NormalizedAccountObservability {
  return {
    ...raw,
    state: raw.state ?? DEFAULT_STATE,
    stateReason: raw.stateReason ?? '',
    reopenInMs: raw.reopenInMs ?? 0,
    currentMaxInflight: raw.currentMaxInflight ?? 0,
    currentInflight: raw.currentInflight ?? 0,
    currentRateRps: raw.currentRateRps ?? raw.limiterRateRps ?? 0,
    learnedSafeRpsLo: raw.learnedSafeRpsLo ?? 0,
    learnedSafeRpsHi: raw.learnedSafeRpsHi ?? 0,
    p80HeldMs: raw.p80HeldMs ?? 0,
    learnedOptimalTSecs: raw.learnedOptimalTSecs ?? 0,
    bottleneckDimension: raw.bottleneckDimension ?? DEFAULT_BOTTLENECK,
    upstream429Rate5m: raw.upstream429Rate5m ?? 0,
    consecutiveThrottles: raw.consecutiveThrottles ?? 0,
  }
}

export function normalizeSnapshot(
  raw: ObservabilitySnapshot,
): ObservabilitySnapshot {
  return {
    ...raw,
    accounts: (raw.accounts ?? []).map(normalizeAccount),
    globalUpstream429Rate5m: raw.globalUpstream429Rate5m ?? 0,
    accountStateCounts: raw.accountStateCounts ?? {},
    schedulingMode: raw.schedulingMode ?? 'unknown',
    sessionToAccount: raw.sessionToAccount ?? {},
    pinnedSessions: raw.pinnedSessions ?? {},
    sessionPriority: raw.sessionPriority ?? {},
  }
}

export function hasSchedulerFields(raw: ObservabilitySnapshot): boolean {
  if (raw.globalUpstream429Rate5m != null) return true
  return (raw.accounts ?? []).some(
    (a) => a.state != null || a.currentRateRps != null,
  )
}

export function stateDotColor(state: AccountState): string {
  switch (state) {
    case 'HEALTHY':
      return 'bg-emerald-500'
    case 'HALF_OPEN':
      return 'bg-amber-500'
    case 'OPEN':
      return 'bg-red-500'
    default:
      return 'bg-muted-foreground'
  }
}

export function stateCountKey(state: AccountState): string {
  switch (state) {
    case 'HEALTHY':
      return 'Healthy'
    case 'OPEN':
      return 'Open'
    case 'HALF_OPEN':
      return 'HalfOpen'
    case 'DISABLED':
      return 'Disabled'
    default:
      return state
  }
}

export function bottleneckLabel(d: BottleneckDimension): string {
  switch (d) {
    case 'SendRate':
      return 'SendRate'
    case 'Inflight':
      return 'Inflight'
    case 'Rpm':
      return 'Rpm'
    case 'Mixed':
      return 'Mixed'
    default:
      return d
  }
}

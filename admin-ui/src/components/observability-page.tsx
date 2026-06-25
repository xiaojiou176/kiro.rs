import { useMemo, useState, useEffect } from 'react'
import { toast } from 'sonner'
import {
  Activity,
  ArrowRightLeft,
  Circle,
  HeartPulse,
  Pin,
  PinOff,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Timer,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  useObservability,
  usePinSession,
  useUnpinSession,
  useSetSessionPriority,
} from '@/hooks/use-observability'
import { useObservabilityHistory } from '@/hooks/use-observability-history'
import { ObservabilityTrendCharts } from '@/components/observability-charts'
import {
  bottleneckLabel,
  hasSchedulerFields,
  normalizeAccount,
  normalizeSnapshot,
  stateDotColor,
} from '@/lib/observability-normalize'
import { cn, extractErrorMessage } from '@/lib/utils'
import type { AccountState } from '@/types/api'
import type { NormalizedAccountObservability } from '@/lib/observability-normalize'

function shortSessionId(id: string): string {
  if (id.length <= 12) return id
  return `${id.slice(0, 8)}…${id.slice(-4)}`
}

function formatCooldown(ms: number): string {
  if (ms <= 0) return '—'
  const s = Math.ceil(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  const rem = s % 60
  return rem > 0 ? `${m}m ${rem}s` : `${m}m`
}

function formatRatePercent(rate: number): string {
  if (rate <= 0) return '0%'
  return `${(rate * 100).toFixed(1)}%`
}

function formatLastUpdated(ts: number | undefined): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function stateBadgeVariant(
  state: AccountState,
): 'success' | 'warning' | 'destructive' | 'secondary' {
  switch (state) {
    case 'HEALTHY':
      return 'success'
    case 'HALF_OPEN':
      return 'warning'
    case 'OPEN':
      return 'destructive'
    default:
      return 'secondary'
  }
}

function stateLabel(state: AccountState): string {
  switch (state) {
    case 'HEALTHY':
      return 'Healthy'
    case 'OPEN':
      return 'Open'
    case 'HALF_OPEN':
      return 'Half Open'
    case 'DISABLED':
      return 'Disabled'
    default:
      return state
  }
}

function StateIcon({ state }: { state: AccountState }) {
  switch (state) {
    case 'HEALTHY':
      return <ShieldCheck className="h-4 w-4 text-emerald-500" />
    case 'HALF_OPEN':
      return <Activity className="h-4 w-4 text-amber-500" />
    case 'OPEN':
      return <ShieldAlert className="h-4 w-4 text-red-500" />
    default:
      return <Circle className="h-4 w-4 text-muted-foreground" />
  }
}

function accountLabel(id: number, email: string | null | undefined): string {
  if (email) return `#${id} · ${email}`
  return `#${id}`
}

// ── 账号失衡/过载判定（#20）──────────────────────────────────
/**
 * 「失衡/过载」= 该号最近 5min 上游 429 率 > 5%（与后端 rebalance429RateThreshold 对齐），
 * 或 inflight 占满（current >= max，且 max>0 防 0/0 误报）。命中任一即视为出事：
 * 卡片标红 + 列表置顶 + 影响全局健康灯。阈值集中在此，别散落魔法数。
 */
const IMBALANCE_429_RATE = 0.05

function isAccountImbalanced(acct: NormalizedAccountObservability): boolean {
  if (acct.upstream429Rate5m > IMBALANCE_429_RATE) return true
  if (acct.currentMaxInflight > 0 && acct.currentInflight >= acct.currentMaxInflight) return true
  return false
}

// ── Thread 视角：六档相位 helpers ──────────────────────────────
type ThreadPhaseT = import('@/types/api').ThreadPhase

/** 相位严重度（排序用，越大越该先看） */
function phaseSeverity(p: ThreadPhaseT): number {
  switch (p) {
    case 'errored':
      return 5
    case 'rateLimited':
      return 4
    case 'justMigrated':
      return 3
    case 'queued':
      return 2
    case 'running':
      return 1
    case 'idle':
      return 0
    default:
      return 0
  }
}

/** 状态灯圆点配色（复用账号态色系 + 蓝/⏳新色） */
function phaseDotColor(p: ThreadPhaseT): string {
  switch (p) {
    case 'running':
      return 'bg-emerald-500'
    case 'rateLimited':
      return 'bg-amber-500'
    case 'queued':
      return 'bg-sky-500'
    case 'justMigrated':
      return 'bg-blue-500'
    case 'errored':
      return 'bg-red-500'
    case 'idle':
      return 'bg-muted-foreground'
    default:
      return 'bg-muted-foreground'
  }
}

/** 相位中文标签（说人话，状态描述的是绑定账号，除 idle） */
function phaseLabel(p: ThreadPhaseT): string {
  switch (p) {
    case 'running':
      return '正常跑'
    case 'rateLimited':
      return '被限流（绑定号静养）'
    case 'queued':
      return '排队中（绑定号忙满）'
    case 'justMigrated':
      return '刚迁号'
    case 'errored':
      return '出错'
    case 'idle':
      return '闲置'
    default:
      return p
  }
}

function phaseBadgeVariant(
  p: ThreadPhaseT,
): 'success' | 'warning' | 'destructive' | 'secondary' {
  switch (p) {
    case 'running':
      return 'success'
    case 'rateLimited':
    case 'justMigrated':
    case 'queued':
      return 'warning'
    case 'errored':
      return 'destructive'
    default:
      return 'secondary'
  }
}

/** 距上次活动毫秒 → 人话 */
function formatSince(ms: number): string {
  // 后端对「无活动」的合成会话(pin-only/priority-only)用 i64::MAX 哨兵。
  // 超过 ~10 年(含 MAX)视为「无活动」，显示 —，别渲染成 2562047788015h 这种垃圾。
  if (ms < 0 || ms > 315_360_000_000) return '从未活动'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s 前`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m 前`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m 前`
}

type ThreadSortKey = 'phase' | 'recent' | 'account'

function useLiveCountdown(ms: number): number {
  const [display, setDisplay] = useState(ms)
  useEffect(() => {
    setDisplay(ms)
    if (ms <= 0) return
    const iv = window.setInterval(() => {
      setDisplay((d) => Math.max(0, d - 1000))
    }, 1000)
    return () => window.clearInterval(iv)
  }, [ms])
  return display
}

export function ObservabilityPage() {
  const { data: rawData, isLoading, isFetching, refetch, error, dataUpdatedAt } =
    useObservability()

  const data = useMemo(
    () => (rawData ? normalizeSnapshot(rawData) : undefined),
    [rawData],
  )
  const schedulerReady = rawData ? hasSchedulerFields(rawData) : false

  const { history, stateMarkers, sessionMigrations, accountIds, lastUpdated } =
    useObservabilityHistory(data, dataUpdatedAt)

  const accountMap = useMemo(() => {
    const m = new Map<number, NormalizedAccountObservability>()
    for (const a of data?.accounts ?? []) m.set(a.id, normalizeAccount(a))
    return m
  }, [data?.accounts])

  // #22：会话 → thread 真名映射（复用 Thread 视角同一数据源 data.threads，别新造一套）。
  // 账号卡区的「绑定会话」chip 用它把裸 UUID 换成真名；拿不到才回退 shortSessionId。
  const sessionNameMap = useMemo(() => {
    const m = new Map<string, string>()
    for (const t of data?.threads ?? []) {
      if (t.threadName) m.set(t.sessionId, t.threadName)
    }
    return m
  }, [data?.threads])

  // #20：账号卡列表「失衡优先」排序——出事的号（429率高/inflight 满）浮到最前，其余按 id 稳定排。
  const sortedAccounts = useMemo(() => {
    const list = (data?.accounts ?? []).map(normalizeAccount)
    return list.sort((a, b) => {
      const ia = isAccountImbalanced(a) ? 1 : 0
      const ib = isAccountImbalanced(b) ? 1 : 0
      if (ia !== ib) return ib - ia
      return a.id - b.id
    })
  }, [data?.accounts])

  // #20：存在任一失衡号 → 全局健康那行整体变色（黄/红）。
  const hasImbalance = useMemo(
    () => sortedAccounts.some(isAccountImbalanced),
    [sortedAccounts],
  )

  const sessionRows = useMemo(() => {
    if (!data) return []
    const ids = new Set<string>()
    for (const sid of Object.keys(data.sessionToAccount)) ids.add(sid)
    for (const sid of Object.keys(data.pinnedSessions)) ids.add(sid)
    for (const sid of Object.keys(data.sessionPriority)) ids.add(sid)
    return Array.from(ids).sort()
  }, [data])

  // ── Thread 视角面板：搜索 + 排序 ──────────────────────────────
  const [threadQuery, setThreadQuery] = useState('')
  const [threadSort, setThreadSort] = useState<ThreadSortKey>('phase')
  // SubAgent threads（无 threadName，主 Agent 才有命名）默认隐藏——它们噪声大、不是用户主线关注的对话。
  const [showSubAgents, setShowSubAgents] = useState(false)

  const threadRows = useMemo(() => {
    const all = data?.threads ?? []
    const q = threadQuery.trim().toLowerCase()
    // ① SubAgent 隐藏：默认只显示有 threadName 的主 Agent thread；
    //    勾选「显示 SubAgent」或用搜索框时才放进无标题的（搜索时仍按关键词过滤）。
    const base = showSubAgents
      ? all
      : all.filter((t) => !!t.threadName || !!t.pinnedAccountId)
    // ② 搜索过滤（搜索框非空时，跨全部 thread 含 SubAgent 搜，方便按 UUID 找特定 SubAgent）。
    const filtered = q
      ? all.filter((t) => {
          const name = (t.threadName ?? t.sessionId).toLowerCase()
          const acct = accountLabel(t.boundAccountId, t.accountEmail).toLowerCase()
          return name.includes(q) || acct.includes(q) || t.sessionId.toLowerCase().includes(q)
        })
      : base.slice()
    filtered.sort((a, b) => {
      if (threadSort === 'phase') {
        const d = phaseSeverity(b.phase) - phaseSeverity(a.phase)
        if (d !== 0) return d
        return a.lastSeenMs - b.lastSeenMs
      }
      if (threadSort === 'recent') return a.lastSeenMs - b.lastSeenMs
      // account
      if (a.boundAccountId !== b.boundAccountId) return a.boundAccountId - b.boundAccountId
      return a.lastSeenMs - b.lastSeenMs
    })
    return filtered
  }, [data?.threads, threadQuery, threadSort, showSubAgents])

  // 当前被隐藏的 SubAgent 数量（给开关旁边显示「(N 个 SubAgent 已隐藏)」）。
  const hiddenSubAgentCount = useMemo(() => {
    const all = data?.threads ?? []
    return all.filter((t) => !t.threadName && !t.pinnedAccountId).length
  }, [data?.threads])

  const stateCounts = useMemo(() => {
    const counts = { healthy: 0, halfOpen: 0, open: 0, disabled: 0 }
    for (const raw of data?.accounts ?? []) {
      const a = normalizeAccount(raw)
      switch (a.state) {
        case 'HEALTHY':
          counts.healthy++
          break
        case 'HALF_OPEN':
          counts.halfOpen++
          break
        case 'OPEN':
          counts.open++
          break
        default:
          counts.disabled++
      }
    }
    return counts
  }, [data?.accounts])

  // 总吞吐 = 各号【实测吞吐 goodputRps】之和（窗口内成功请求/秒，真实流量）。
  // ⚠️ 不能用 currentRateRps——那是限速器【允许速率上限/容量】，不是真发了多少；
  //   把容量当吞吐会让面板在系统空闲时也显示「很忙」(一种假绿)。
  const totalThroughput = useMemo(
    () =>
      (data?.accounts ?? [])
        .filter((a) => !a.disabled && normalizeAccount(a).state !== 'DISABLED')
        .reduce((s, a) => s + normalizeAccount(a).goodputRps, 0),
    [data?.accounts],
  )
  // 容量上限之和（各号限速器当前允许速率）——单独标，给「还能吃多少」参考，不冒充吞吐。
  const totalCapacity = useMemo(
    () =>
      (data?.accounts ?? [])
        .filter((a) => !a.disabled && normalizeAccount(a).state !== 'DISABLED')
        .reduce((s, a) => s + normalizeAccount(a).currentRateRps, 0),
    [data?.accounts],
  )

  return (
    <TooltipProvider delayDuration={200}>
      <div>
        <PageHeader
          isFetching={isFetching}
          onRefresh={() => void refetch()}
          lastUpdated={lastUpdated ?? dataUpdatedAt}
        />

        {error && (
          <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
            加载失败：{extractErrorMessage(error)}
          </div>
        )}

        {!schedulerReady && !isLoading && rawData && (
          <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-amber-700 dark:text-amber-400">
            后端未返回调度器新字段，已降级显示基础观测数据。
          </div>
        )}

        <GlobalHealthBar
          stateCounts={stateCounts}
          activeSessionTotal={data?.activeSessionTotal ?? 0}
          global429={data?.globalUpstream429Rate5m ?? 0}
          totalThroughput={totalThroughput}
          totalCapacity={totalCapacity}
          hasImbalance={hasImbalance}
          isLoading={isLoading}
        />

        <section className="mb-8">
          <h2 className="mb-3 text-sm font-medium text-muted-foreground">账号运行态</h2>
          {isLoading ? (
            <div className="text-sm text-muted-foreground">加载中…</div>
          ) : (data?.accounts.length ?? 0) === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-sm text-muted-foreground">
                暂无凭据账号
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {sortedAccounts.map((acc) => (
                <AccountCard key={acc.id} account={acc} sessionNameMap={sessionNameMap} />
              ))}
            </div>
          )}
        </section>

        <ObservabilityTrendCharts
          history={history}
          accountIds={accountIds}
          stateMarkers={stateMarkers}
        />

        <section>
          <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <h2 className="text-sm font-medium text-muted-foreground">
              Thread 视角 · 绑哪个号 / 当前阶段
            </h2>
            <div className="flex items-center gap-2">
              <label className="flex select-none items-center gap-1.5 text-[12px] text-muted-foreground">
                <input
                  type="checkbox"
                  checked={showSubAgents}
                  onChange={(e) => setShowSubAgents(e.target.checked)}
                  className="h-3.5 w-3.5 accent-primary"
                />
                显示 SubAgent
                {!showSubAgents && hiddenSubAgentCount > 0 ? (
                  <span className="text-muted-foreground/60">（{hiddenSubAgentCount} 个已隐藏）</span>
                ) : null}
              </label>
              <Input
                value={threadQuery}
                onChange={(e) => setThreadQuery(e.target.value)}
                placeholder="搜 Thread 名 / 账号…"
                className="h-8 w-[200px] text-[12px]"
              />
              <Select
                value={threadSort}
                onValueChange={(v) => setThreadSort(v as ThreadSortKey)}
              >
                <SelectTrigger className="h-8 w-[120px] text-[12px]">
                  <SelectValue placeholder="排序" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="phase">按状态严重度</SelectItem>
                  <SelectItem value="recent">按最近活动</SelectItem>
                  <SelectItem value="account">按账号</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          {isLoading ? (
            <Card>
              <CardContent className="py-8 text-center text-sm text-muted-foreground">
                加载中…
              </CardContent>
            </Card>
          ) : (data?.threads ?? []).length === 0 ? (
            // 后端没返回 threads（旧 binary）→ 回退旧「会话→号」表
            <Card>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[760px] text-left">
                    <thead>
                      <tr className="border-b border-border/60 bg-secondary/30 text-[12px] text-muted-foreground">
                        <th className="py-2.5 pl-4 pr-3 font-medium">会话 ID</th>
                        <th className="py-2.5 pr-3 font-medium">当前账号</th>
                        <th className="py-2.5 pr-3 font-medium">优先级</th>
                        <th className="py-2.5 pr-3 font-medium">Pin 到账号</th>
                        <th className="py-2.5 pr-4 font-medium">操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sessionRows.length === 0 ? (
                        <tr>
                          <td
                            colSpan={5}
                            className="py-8 text-center text-sm text-muted-foreground"
                          >
                            暂无活跃会话绑定
                          </td>
                        </tr>
                      ) : (
                        sessionRows.map((sessionId) => (
                          <SessionRow
                            key={sessionId}
                            sessionId={sessionId}
                            accountId={data?.sessionToAccount[sessionId]}
                            pinnedAccountId={data?.pinnedSessions[sessionId]}
                            priority={data?.sessionPriority[sessionId] ?? 0}
                            accounts={(data?.accounts ?? []).map(normalizeAccount)}
                            accountMap={accountMap}
                            migration={sessionMigrations.get(sessionId)}
                          />
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          ) : threadRows.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-sm text-muted-foreground">
                没有匹配「{threadQuery}」的 Thread
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {threadRows.map((t) => (
                <ThreadRow
                  key={t.sessionId}
                  thread={t}
                  priority={data?.sessionPriority[t.sessionId] ?? 0}
                  accounts={(data?.accounts ?? []).map(normalizeAccount)}
                />
              ))}
            </div>
          )}
        </section>
      </div>
    </TooltipProvider>
  )
}

function PageHeader({
  isFetching,
  onRefresh,
  lastUpdated,
}: {
  isFetching: boolean
  onRefresh: () => void
  lastUpdated?: number
}) {
  return (
    <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-[28px] font-semibold tracking-tight leading-tight">
          运行观测
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          自适应调度器运维看板 · 5s 轮询 · 前端累积 15min 趋势
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <span className="text-[11px] text-muted-foreground tabular-nums">
          更新 {formatLastUpdated(lastUpdated)}
        </span>
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={isFetching}
        >
          <RefreshCw className={cn('mr-1.5 h-3.5 w-3.5', isFetching && 'animate-spin')} />
          刷新
        </Button>
      </div>
    </div>
  )
}

function GlobalHealthBar({
  stateCounts,
  activeSessionTotal,
  global429,
  totalThroughput,
  totalCapacity,
  hasImbalance,
  isLoading,
}: {
  stateCounts: { healthy: number; halfOpen: number; open: number; disabled: number }
  activeSessionTotal: number
  global429: number
  totalThroughput: number
  totalCapacity: number
  hasImbalance: boolean
  isLoading: boolean
}) {
  const overBudget = global429 > 0.02
  const nearBudget = global429 > 0.01 && !overBudget

  // #20：全局健康严重度——有失衡号 / 有熔断(OPEN) → 红；有半开恢复中 → 黄；全健康才绿。
  // isLoading 时保持中性（不误报）。
  const severity: 'green' | 'amber' | 'red' = isLoading
    ? 'green'
    : hasImbalance || stateCounts.open > 0
      ? 'red'
      : stateCounts.halfOpen > 0
        ? 'amber'
        : 'green'
  const severityLabel =
    severity === 'red' ? '有号失衡' : severity === 'amber' ? '恢复中' : '全部健康'

  return (
    <Card
      className={cn(
        'mb-6 transition-colors',
        severity === 'red' && 'border-red-500/60 bg-red-500/5 dark:bg-red-500/10',
        severity === 'amber' && 'border-amber-500/60 bg-amber-500/5 dark:bg-amber-500/10',
        severity === 'green' && 'border-border/80',
      )}
    >
      <CardContent className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <HeartPulse
              className={cn(
                'h-5 w-5',
                severity === 'red' && 'text-red-600 dark:text-red-400',
                severity === 'amber' && 'text-amber-600 dark:text-amber-400',
                severity === 'green' && 'text-emerald-600 dark:text-emerald-400',
              )}
            />
            <span className="text-sm font-medium">全局健康</span>
            <Badge
              variant={
                severity === 'red' ? 'destructive' : severity === 'amber' ? 'warning' : 'success'
              }
              className="text-[11px]"
            >
              {isLoading ? '—' : severityLabel}
            </Badge>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span className="flex items-center gap-1.5" title="Healthy">
              <span className={cn('h-2.5 w-2.5 rounded-full', stateDotColor('HEALTHY'))} />
              <span className="font-mono tabular-nums">{isLoading ? '—' : stateCounts.healthy}</span>
            </span>
            <span className="flex items-center gap-1.5" title="Half Open">
              <span className={cn('h-2.5 w-2.5 rounded-full', stateDotColor('HALF_OPEN'))} />
              <span className="font-mono tabular-nums">{isLoading ? '—' : stateCounts.halfOpen}</span>
            </span>
            <span className="flex items-center gap-1.5" title="Open">
              <span className={cn('h-2.5 w-2.5 rounded-full', stateDotColor('OPEN'))} />
              <span className="font-mono tabular-nums">{isLoading ? '—' : stateCounts.open}</span>
            </span>
          </div>
          <div className="text-sm text-muted-foreground">
            活跃会话{' '}
            <span className="font-mono font-medium text-foreground tabular-nums">
              {isLoading ? '—' : activeSessionTotal}
            </span>
          </div>
          <div className="text-sm text-muted-foreground">
            实测吞吐{' '}
            <span className="font-mono font-medium text-foreground tabular-nums">
              {isLoading ? '—' : `${totalThroughput.toFixed(2)} rps`}
            </span>
            <span className="ml-1 text-xs text-muted-foreground/70">
              {isLoading ? '' : `(容量上限 ${totalCapacity.toFixed(2)} rps)`}
            </span>
          </div>
        </div>
        <div className="text-right">
          <div className="text-[11px] text-muted-foreground">近 5min 上游 429</div>
          <div
            className={cn(
              'text-2xl font-semibold font-mono tabular-nums',
              overBudget && 'text-red-600 dark:text-red-400',
              nearBudget && 'text-amber-600 dark:text-amber-400',
              !overBudget && !nearBudget && 'text-emerald-600 dark:text-emerald-400',
            )}
          >
            {isLoading ? '—' : formatRatePercent(global429)}
          </div>
          <div className="text-[10px] text-muted-foreground">预算 1% / 2%</div>
        </div>
      </CardContent>
    </Card>
  )
}

function AccountCard({
  account,
  sessionNameMap,
}: {
  account: NormalizedAccountObservability
  sessionNameMap: Map<string, string>
}) {
  const isOpen = account.state === 'OPEN'
  const isHalfOpen = account.state === 'HALF_OPEN'
  const isHealthy = account.state === 'HEALTHY'
  const cooled = account.cooldownRemainingMs > 0
  const reopenMs = useLiveCountdown(account.reopenInMs)
  // #20：失衡/过载（429率高 或 inflight 满）。即便状态仍是 Healthy 也要醒目标红喊出来。
  const imbalanced = isAccountImbalanced(account)
  const safeRpsRange =
    account.learnedSafeRpsLo > 0 || account.learnedSafeRpsHi > 0
      ? `${account.learnedSafeRpsLo.toFixed(2)}–${account.learnedSafeRpsHi.toFixed(2)} rps`
      : '—'
  const high429 = account.upstream429Rate5m > 0.02

  return (
    <Card
      className={cn(
        'transition-colors',
        isOpen && 'border-red-500/50 bg-red-500/5 dark:bg-red-500/10',
        isHalfOpen && 'border-amber-500/50 bg-amber-500/5 dark:bg-amber-500/10',
        isHealthy && !cooled && 'border-emerald-500/20',
        !isOpen && !isHalfOpen && cooled && 'border-amber-500/40 bg-amber-500/5',
        // 失衡红圈盖在最上层：ring 不与 border 冲突，Healthy 卡也能被一眼揪出来。
        imbalanced && 'border-red-500/70 bg-red-500/5 ring-2 ring-red-500/70 dark:bg-red-500/10',
      )}
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-start gap-2">
            <StateIcon state={account.state} />
            <div>
              <CardTitle className="text-sm font-medium leading-snug">
                {accountLabel(account.id, account.email)}
              </CardTitle>
              {isOpen && reopenMs > 0 && (
                <div className="mt-1 flex items-center gap-1 text-[12px] font-medium text-red-600 dark:text-red-400">
                  <Timer className="h-3.5 w-3.5" />
                  静养中，剩 {formatCooldown(reopenMs)}
                </div>
              )}
            </div>
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1">
            <Badge variant={stateBadgeVariant(account.state)}>
              {stateLabel(account.state)}
            </Badge>
            {imbalanced && (
              <Badge variant="destructive" className="gap-1 text-[10px]">
                <ShieldAlert className="h-3 w-3" />
                失衡/过载
              </Badge>
            )}
          </div>
        </div>
        {account.stateReason && (
          <p className="mt-1.5 text-[11px] text-muted-foreground leading-snug">
            {account.stateReason}
          </p>
        )}
      </CardHeader>
      <CardContent className="space-y-3 text-[13px]">
        <div>
          <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
            <span>Inflight</span>
            <span className="font-mono tabular-nums">
              {account.currentInflight} / {account.currentMaxInflight}
            </span>
          </div>
          <Progress value={account.currentInflight} max={Math.max(account.currentMaxInflight, 1)} />
        </div>

        <div className="grid grid-cols-2 gap-x-3 gap-y-2">
          <Metric label="实测吞吐" value={`${account.goodputRps.toFixed(2)} rps`} />
          <Metric label="速率上限" value={`${account.currentRateRps.toFixed(2)} rps`} />
          <Metric label="Safe rps" value={safeRpsRange} />
          <Metric label="RPM (60s)" value={String(account.rpm)} />
          <Metric
            label="429 率 (5m)"
            value={formatRatePercent(account.upstream429Rate5m)}
            danger={high429}
            warn={account.upstream429Rate5m > 0.01 && !high429}
          />
        </div>

        <div className="flex flex-wrap gap-1.5">
          <LearningTag label="瓶颈" value={bottleneckLabel(account.bottleneckDimension)} />
          {account.learnedOptimalTSecs > 0 && (
            <LearningTag label="最优静养T" value={`${account.learnedOptimalTSecs}s`} />
          )}
          {account.p80HeldMs > 0 && (
            <LearningTag label="p80占槽" value={formatCooldown(account.p80HeldMs)} />
          )}
        </div>

        <div>
          <div className="mb-1 text-[11px] text-muted-foreground">
            绑定会话 (活跃5m {account.activeSessions ?? 0} / 共{account.boundSessions.length})
          </div>
          {account.boundSessions.length === 0 ? (
            <span className="text-[12px] text-muted-foreground">无</span>
          ) : (
            <div className="flex flex-wrap gap-1">
              {account.boundSessions.map((sid) => {
                // #22：能拿到 thread 真名就显真名（非等宽字体），拿不到才回退 shortSessionId（等宽）。
                const realName = sessionNameMap.get(sid)
                return (
                  <Badge
                    key={sid}
                    variant="outline"
                    className={cn('max-w-[180px] truncate text-[10px]', !realName && 'font-mono')}
                    title={realName ? `${realName}（${sid}）` : sid}
                  >
                    {realName ?? shortSessionId(sid)}
                  </Badge>
                )
              })}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

function LearningTag({ label, value }: { label: string; value: string }) {
  return (
    <Badge variant="outline" className="text-[10px] font-normal">
      <span className="text-muted-foreground">{label}:</span>{' '}
      <span className="font-mono">{value}</span>
    </Badge>
  )
}

function Metric({
  label,
  value,
  danger,
  warn,
}: {
  label: string
  value: string
  danger?: boolean
  warn?: boolean
}) {
  return (
    <div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div
        className={cn(
          'font-mono tabular-nums text-[13px]',
          danger && 'font-medium text-red-600 dark:text-red-400',
          warn && !danger && 'font-medium text-amber-600 dark:text-amber-400',
        )}
      >
        {value}
      </div>
    </div>
  )
}

// ── Thread 视角卡片：收起=灯+真名+账号；展开=详情 + Pin/优先级 ──────────
function ThreadRow({
  thread,
  priority,
  accounts,
}: {
  thread: import('@/types/api').ThreadObservation
  priority: number
  accounts: NormalizedAccountObservability[]
}) {
  const [expanded, setExpanded] = useState(false)
  const pinSession = usePinSession()
  const unpinSession = useUnpinSession()
  const setPriority = useSetSessionPriority()
  const [draftPriority, setDraftPriority] = useState(String(priority))
  // 单一数据源：pin 状态只读 thread.pinnedAccountId（后端原生字段），不再走侧 join，避免 badge/下拉/按钮分叉。
  const pinnedAccountId = thread.pinnedAccountId ?? undefined
  const isPinned = pinnedAccountId != null

  useEffect(() => {
    setDraftPriority(String(priority))
  }, [priority])

  const handlePriorityCommit = async () => {
    const n = Number.parseInt(draftPriority, 10)
    if (Number.isNaN(n)) {
      toast.error('优先级须为整数')
      setDraftPriority(String(priority))
      return
    }
    if (n === priority) return
    try {
      const res = await setPriority.mutateAsync({ sessionId: thread.sessionId, priority: n })
      toast.success(res.message)
    } catch (e) {
      toast.error(extractErrorMessage(e))
      setDraftPriority(String(priority))
    }
  }

  const handlePin = async (credId: string) => {
    const id = Number.parseInt(credId, 10)
    if (Number.isNaN(id)) return
    try {
      const res = await pinSession.mutateAsync({ sessionId: thread.sessionId, credentialId: id })
      toast.success(res.message)
    } catch (e) {
      toast.error(extractErrorMessage(e))
    }
  }

  const handleUnpin = async () => {
    try {
      const res = await unpinSession.mutateAsync(thread.sessionId)
      toast.success(res.message)
    } catch (e) {
      toast.error(extractErrorMessage(e))
    }
  }

  const displayName = thread.threadName ?? shortSessionId(thread.sessionId)

  return (
    <Card
      className={cn(
        'transition-colors',
        thread.phase === 'errored' && 'border-red-500/40',
        thread.phase === 'rateLimited' && 'border-amber-500/40',
      )}
    >
      <CardContent className="p-0">
        {/* 折叠行：toggle 按钮 + 解绑按钮作为兄弟节点（避免按钮嵌套），孤儿 Pin 不展开也能一键清。 */}
        <div className="flex w-full items-center gap-2 pr-3">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="flex min-w-0 flex-1 items-center gap-3 px-4 py-3 text-left hover:bg-secondary/30"
          >
            <span
              className={cn('h-2.5 w-2.5 shrink-0 rounded-full', phaseDotColor(thread.phase))}
              aria-label={phaseLabel(thread.phase)}
            />
            <span className="min-w-0 flex-1 truncate text-[13px] font-medium" title={displayName}>
              {displayName}
            </span>
            <span className="hidden shrink-0 text-[12px] text-muted-foreground sm:inline">
              {accountLabel(thread.boundAccountId, thread.accountEmail)}
            </span>
            <Badge variant={phaseBadgeVariant(thread.phase)} className="shrink-0 text-[11px]">
              {phaseLabel(thread.phase)}
            </Badge>
            {thread.pinnedAccountId != null && (
              <Badge variant="secondary" className="shrink-0 gap-1 text-[11px]">
                <Pin className="h-3 w-3" />
                已 Pin #{thread.pinnedAccountId}
              </Badge>
            )}
            <span className="hidden shrink-0 text-[11px] text-muted-foreground tabular-nums md:inline">
              {formatSince(thread.lastSeenMs)}
            </span>
          </button>
          {isPinned && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 shrink-0 px-2 text-[11px] text-muted-foreground hover:text-foreground"
              onClick={() => void handleUnpin()}
              disabled={unpinSession.isPending}
              title="解除该会话的 Pin 绑定"
            >
              <PinOff className="mr-1 h-3.5 w-3.5" />
              解绑
            </Button>
          )}
        </div>

        {expanded && (
          <div className="border-t border-border/50 px-4 py-3 text-[12px]">
            <div className="mb-3 grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3">
              <DetailField label="Thread ID" value={shortSessionId(thread.sessionId)} mono />
              <DetailField
                label="绑定账号"
                value={accountLabel(thread.boundAccountId, thread.accountEmail)}
              />
              <DetailField label="绑定于" value={formatBoundAt(thread.boundAt)} />
              <DetailField label="距上次活动" value={formatSince(thread.lastSeenMs)} />
              <DetailField
                label="最近 429 次数"
                value={String(thread.recentThrottleCount)}
                mono
              />
              <DetailField label="最近一次结果" value={thread.lastFinalStatus ?? '—'} />
            </div>
            <div className="flex flex-wrap items-end gap-3 border-t border-border/40 pt-3">
              <div>
                <div className="mb-1 text-[11px] text-muted-foreground">优先级</div>
                <Input
                  type="number"
                  className="h-8 w-20 font-mono text-[13px]"
                  value={draftPriority}
                  onChange={(e) => setDraftPriority(e.target.value)}
                  onBlur={() => void handlePriorityCommit()}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') e.currentTarget.blur()
                  }}
                  disabled={setPriority.isPending}
                />
              </div>
              <div>
                <div className="mb-1 text-[11px] text-muted-foreground">Pin 到账号</div>
                <Select
                  value={pinnedAccountId != null ? String(pinnedAccountId) : undefined}
                  onValueChange={(v) => void handlePin(v)}
                  disabled={pinSession.isPending || accounts.length === 0}
                >
                  <SelectTrigger className="h-8 w-[160px] text-[12px]">
                    <SelectValue placeholder="选择账号 Pin" />
                  </SelectTrigger>
                  <SelectContent>
                    {accounts.map((a) => (
                      <SelectItem
                        key={a.id}
                        value={String(a.id)}
                        disabled={a.state === 'OPEN' || a.state === 'HALF_OPEN' || a.disabled}
                        title={
                          a.state === 'OPEN' || a.state === 'HALF_OPEN'
                            ? '该号正限流/熔断，不能 Pin'
                            : a.disabled
                              ? '该号已禁用，不能 Pin'
                              : undefined
                        }
                      >
                        {accountLabel(a.id, a.email)}
                        {(a.state === 'OPEN' || a.state === 'HALF_OPEN') && '（限流中）'}
                        {a.disabled && '（已禁用）'}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {isPinned && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 text-[12px]"
                  onClick={() => void handleUnpin()}
                  disabled={unpinSession.isPending}
                >
                  <PinOff className="mr-1 h-3.5 w-3.5" />
                  解除 Pin
                </Button>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function DetailField({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className={cn('truncate', mono && 'font-mono')} title={value}>
        {value}
      </div>
    </div>
  )
}

function formatBoundAt(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function SessionRow({
  sessionId,
  accountId,
  pinnedAccountId,
  priority,
  accounts,
  accountMap,
  migration,
}: {
  sessionId: string
  accountId: number | undefined
  pinnedAccountId: number | undefined
  priority: number
  accounts: NormalizedAccountObservability[]
  accountMap: Map<number, NormalizedAccountObservability>
  migration?: { fromAccountId: number; toAccountId: number; reason: string }
}) {
  const pinSession = usePinSession()
  const unpinSession = useUnpinSession()
  const setPriority = useSetSessionPriority()
  const [draftPriority, setDraftPriority] = useState(String(priority))
  const isPinned = pinnedAccountId != null

  useEffect(() => {
    setDraftPriority(String(priority))
  }, [priority])

  const handlePriorityCommit = async () => {
    const n = Number.parseInt(draftPriority, 10)
    if (Number.isNaN(n)) {
      toast.error('优先级须为整数')
      setDraftPriority(String(priority))
      return
    }
    if (n === priority) return
    try {
      const res = await setPriority.mutateAsync({ sessionId, priority: n })
      toast.success(res.message)
    } catch (e) {
      toast.error(extractErrorMessage(e))
      setDraftPriority(String(priority))
    }
  }

  const handlePin = async (credId: string) => {
    const id = Number.parseInt(credId, 10)
    if (Number.isNaN(id)) return
    try {
      const res = await pinSession.mutateAsync({ sessionId, credentialId: id })
      toast.success(res.message)
    } catch (e) {
      toast.error(extractErrorMessage(e))
    }
  }

  const handleUnpin = async () => {
    try {
      const res = await unpinSession.mutateAsync(sessionId)
      toast.success(res.message)
    } catch (e) {
      toast.error(extractErrorMessage(e))
    }
  }

  const currentAcc = accountId != null ? accountMap.get(accountId) : undefined

  return (
    <tr
      className={cn(
        'border-b border-border/40 text-[13px]',
        isPinned && 'bg-primary/5 dark:bg-primary/10',
        migration && 'bg-amber-500/5 dark:bg-amber-500/10',
      )}
    >
      <td className="py-2.5 pl-4 pr-3">
        <div className="flex items-center gap-1.5">
          {isPinned && (
            <Pin className="h-3.5 w-3.5 shrink-0 text-primary" aria-label="已 Pin" />
          )}
          {migration && (
            <Tooltip>
              <TooltipTrigger asChild>
                <ArrowRightLeft
                  className="h-3.5 w-3.5 shrink-0 text-amber-600 dark:text-amber-400"
                  aria-label="forced switch"
                />
              </TooltipTrigger>
              <TooltipContent>
                原号 #{migration.fromAccountId} 静养中，已迁至 #{migration.toAccountId}
              </TooltipContent>
            </Tooltip>
          )}
          <span className="font-mono text-[12px]" title={sessionId}>
            {shortSessionId(sessionId)}
          </span>
        </div>
      </td>
      <td className="py-2.5 pr-3">
        {accountId != null ? (
          <div className="flex items-center gap-1.5">
            {currentAcc && (
              <span
                className={cn('h-2 w-2 shrink-0 rounded-full', stateDotColor(currentAcc.state))}
              />
            )}
            <span>{accountLabel(accountId, currentAcc?.email ?? null)}</span>
          </div>
        ) : (
          <span className="text-muted-foreground">未绑定</span>
        )}
      </td>
      <td className="py-2.5 pr-3">
        <Input
          type="number"
          className="h-8 w-20 font-mono text-[13px]"
          value={draftPriority}
          onChange={(e) => setDraftPriority(e.target.value)}
          onBlur={() => void handlePriorityCommit()}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.currentTarget.blur()
            }
          }}
          disabled={setPriority.isPending}
        />
      </td>
      <td className="py-2.5 pr-3">
        <Select
          value={pinnedAccountId != null ? String(pinnedAccountId) : undefined}
          onValueChange={(v) => void handlePin(v)}
          disabled={pinSession.isPending || accounts.length === 0}
        >
          <SelectTrigger className="h-8 w-[160px] text-[12px]">
            <SelectValue placeholder="选择账号 Pin" />
          </SelectTrigger>
          <SelectContent>
            {accounts.map((a) => (
              <SelectItem key={a.id} value={String(a.id)}>
                {accountLabel(a.id, a.email)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </td>
      <td className="py-2.5 pr-4">
        {isPinned ? (
          <Button
            variant="ghost"
            size="sm"
            className="h-8 text-[12px]"
            onClick={() => void handleUnpin()}
            disabled={unpinSession.isPending}
          >
            <PinOff className="mr-1 h-3.5 w-3.5" />
            解除 Pin
          </Button>
        ) : (
          <span className="text-[12px] text-muted-foreground">—</span>
        )}
      </td>
    </tr>
  )
}

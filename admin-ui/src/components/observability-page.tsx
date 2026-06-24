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

  const threadRows = useMemo(() => {
    const all = data?.threads ?? []
    const q = threadQuery.trim().toLowerCase()
    const filtered = q
      ? all.filter((t) => {
          const name = (t.threadName ?? t.sessionId).toLowerCase()
          const acct = accountLabel(t.boundAccountId, t.accountEmail).toLowerCase()
          return name.includes(q) || acct.includes(q) || t.sessionId.toLowerCase().includes(q)
        })
      : all.slice()
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
  }, [data?.threads, threadQuery, threadSort])

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

  const totalThroughput = useMemo(
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
              {data!.accounts.map((acc) => (
                <AccountCard key={acc.id} account={normalizeAccount(acc)} />
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
  isLoading,
}: {
  stateCounts: { healthy: number; halfOpen: number; open: number; disabled: number }
  activeSessionTotal: number
  global429: number
  totalThroughput: number
  isLoading: boolean
}) {
  const overBudget = global429 > 0.02
  const nearBudget = global429 > 0.01 && !overBudget

  return (
    <Card className="mb-6 border-border/80">
      <CardContent className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <HeartPulse className="h-5 w-5 text-muted-foreground" />
            <span className="text-sm font-medium">全局健康</span>
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
            总吞吐{' '}
            <span className="font-mono font-medium text-foreground tabular-nums">
              {isLoading ? '—' : `${totalThroughput.toFixed(2)} rps`}
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

function AccountCard({ account }: { account: NormalizedAccountObservability }) {
  const isOpen = account.state === 'OPEN'
  const isHalfOpen = account.state === 'HALF_OPEN'
  const isHealthy = account.state === 'HEALTHY'
  const cooled = account.cooldownRemainingMs > 0
  const reopenMs = useLiveCountdown(account.reopenInMs)
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
          <Badge variant={stateBadgeVariant(account.state)}>
            {stateLabel(account.state)}
          </Badge>
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
          <Metric label="当前 rps" value={`${account.currentRateRps.toFixed(2)} rps`} />
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
              {account.boundSessions.map((sid) => (
                <Badge key={sid} variant="outline" className="font-mono text-[10px]">
                  {shortSessionId(sid)}
                </Badge>
              ))}
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
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-secondary/30"
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

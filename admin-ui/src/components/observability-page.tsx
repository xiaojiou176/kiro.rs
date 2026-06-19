import { useMemo, useState, useEffect } from 'react'
import { toast } from 'sonner'
import {
  Gauge,
  RefreshCw,
  Pin,
  PinOff,
  Users,
  Clock,
  Zap,
  AlertTriangle,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  useObservability,
  usePinSession,
  useUnpinSession,
  useSetSessionPriority,
} from '@/hooks/use-observability'
import { cn, extractErrorMessage } from '@/lib/utils'
import type { AccountObservability } from '@/types/api'

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

function accountLabel(id: number, email: string | null | undefined): string {
  if (email) return `#${id} · ${email}`
  return `#${id}`
}

export function ObservabilityPage() {
  const { data, isLoading, isFetching, refetch, error } = useObservability()

  const accountMap = useMemo(() => {
    const m = new Map<number, AccountObservability>()
    for (const a of data?.accounts ?? []) m.set(a.id, a)
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

  return (
    <div>
      <PageHeader
        isFetching={isFetching}
        onRefresh={() => void refetch()}
      />

      {error && (
        <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          加载失败：{extractErrorMessage(error)}
        </div>
      )}

      <SummaryCards
        multiAccountEnabled={data?.multiAccountEnabled ?? false}
        activeSessionTotal={data?.activeSessionTotal ?? 0}
        activeWindowSecs={data?.activeWindowSecs ?? 0}
        accountCount={data?.accounts.length ?? 0}
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
              <AccountCard key={acc.id} account={acc} />
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground">
          会话 (Thread) → 号
        </h2>
        <Card>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left">
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
                  {isLoading ? (
                    <tr>
                      <td
                        colSpan={5}
                        className="py-8 text-center text-sm text-muted-foreground"
                      >
                        加载中…
                      </td>
                    </tr>
                  ) : sessionRows.length === 0 ? (
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
                        accounts={data?.accounts ?? []}
                        accountMap={accountMap}
                      />
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  )
}

function PageHeader({
  isFetching,
  onRefresh,
}: {
  isFetching: boolean
  onRefresh: () => void
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-[28px] font-semibold tracking-tight leading-tight">
          运行观测
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          多号 affinity 实时状态：账号负载、会话绑定、Pin 与优先级
        </p>
      </div>
      <Button
        variant="outline"
        size="sm"
        onClick={onRefresh}
        disabled={isFetching}
        className="shrink-0"
      >
        <RefreshCw className={cn('mr-1.5 h-3.5 w-3.5', isFetching && 'animate-spin')} />
        刷新
      </Button>
    </div>
  )
}

function SummaryCards({
  multiAccountEnabled,
  activeSessionTotal,
  activeWindowSecs,
  accountCount,
  isLoading,
}: {
  multiAccountEnabled: boolean
  activeSessionTotal: number
  activeWindowSecs: number
  accountCount: number
  isLoading: boolean
}) {
  const cards = [
    {
      icon: <Gauge className="h-4 w-4" />,
      label: '多号模式',
      value: isLoading ? '—' : multiAccountEnabled ? '已开启' : '未开启',
      badge: multiAccountEnabled ? (
        <Badge variant="success">ON</Badge>
      ) : (
        <Badge variant="secondary">OFF</Badge>
      ),
    },
    {
      icon: <Users className="h-4 w-4" />,
      label: '活跃会话',
      value: isLoading ? '—' : String(activeSessionTotal),
      meta: `活跃窗口 ${activeWindowSecs}s`,
    },
    {
      icon: <Clock className="h-4 w-4" />,
      label: '活跃窗口',
      value: isLoading ? '—' : `${activeWindowSecs}s`,
      meta: '再平衡判定窗口',
    },
    {
      icon: <Zap className="h-4 w-4" />,
      label: '账号数',
      value: isLoading ? '—' : String(accountCount),
      meta: '全部凭据',
    },
  ]

  return (
    <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
      {cards.map((c) => (
        <Card key={c.label}>
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-muted-foreground">
              {c.icon}
              <span className="text-[12px]">{c.label}</span>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="text-xl font-semibold tabular-nums">{c.value}</span>
              {c.badge}
            </div>
            {c.meta && (
              <p className="mt-1 text-[11px] text-muted-foreground">{c.meta}</p>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function AccountCard({ account }: { account: AccountObservability }) {
  const cooled = account.cooldownRemainingMs > 0

  return (
    <Card
      className={cn(
        cooled && 'border-amber-500/40 bg-amber-500/5 dark:bg-amber-500/10',
      )}
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-sm font-medium leading-snug">
            {accountLabel(account.id, account.email)}
          </CardTitle>
          <div className="flex shrink-0 flex-wrap justify-end gap-1">
            {account.disabled && (
              <Badge variant="destructive">已禁用</Badge>
            )}
            {cooled && (
              <Badge variant="warning">
                <AlertTriangle className="mr-1 h-3 w-3" />
                冷却中
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 text-[13px]">
        <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
          <Metric label="RPM" value={String(account.rpm)} />
          <Metric label="活跃会话" value={String(account.activeSessions)} />
          <Metric
            label="限速 (rps)"
            value={
              account.limiterRateRps != null
                ? account.limiterRateRps.toFixed(2)
                : '—'
            }
          />
          <Metric
            label="冷却剩余"
            value={formatCooldown(account.cooldownRemainingMs)}
            highlight={cooled}
          />
        </div>
        <div>
          <div className="mb-1 text-[11px] text-muted-foreground">
            绑定会话 ({account.boundSessions.length})
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

function Metric({
  label,
  value,
  highlight,
}: {
  label: string
  value: string
  highlight?: boolean
}) {
  return (
    <div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div
        className={cn(
          'font-mono tabular-nums',
          highlight && 'font-medium text-amber-600 dark:text-amber-400',
        )}
      >
        {value}
      </div>
    </div>
  )
}

function SessionRow({
  sessionId,
  accountId,
  pinnedAccountId,
  priority,
  accounts,
  accountMap,
}: {
  sessionId: string
  accountId: number | undefined
  pinnedAccountId: number | undefined
  priority: number
  accounts: AccountObservability[]
  accountMap: Map<number, AccountObservability>
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
      )}
    >
      <td className="py-2.5 pl-4 pr-3">
        <div className="flex items-center gap-1.5">
          {isPinned && (
            <Pin className="h-3.5 w-3.5 shrink-0 text-primary" aria-label="已 Pin" />
          )}
          <span className="font-mono text-[12px]" title={sessionId}>
            {shortSessionId(sessionId)}
          </span>
        </div>
      </td>
      <td className="py-2.5 pr-3">
        {accountId != null ? (
          <span>{accountLabel(accountId, currentAcc?.email ?? null)}</span>
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

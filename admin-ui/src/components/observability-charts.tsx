import { useMemo, useState } from 'react'
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  tooltipContentStyle,
  tooltipCursorStyle,
  tooltipItemStyle,
  tooltipLabelStyle,
} from '@/components/charts/tooltip-style'
import type {
  ObservabilityHistoryPoint,
  StateTransitionMarker,
} from '@/hooks/use-observability-history'

const PROBE_BUDGET_LOW = 0.01
const PROBE_BUDGET_HIGH = 0.02

const ACCOUNT_COLORS = [
  '#3b82f6',
  '#10b981',
  '#f59e0b',
  '#ef4444',
  '#8b5cf6',
  '#06b6d4',
  '#ec4899',
  '#64748b',
]

function accountColor(id: number, ids: number[]): string {
  const idx = ids.indexOf(id)
  return ACCOUNT_COLORS[idx >= 0 ? idx % ACCOUNT_COLORS.length : 0]
}

function pickXInterval(len: number): number | 'preserveStartEnd' {
  if (len <= 8) return 0
  if (len <= 24) return 2
  return Math.ceil(len / 12)
}

function formatPct(v: number): string {
  return `${(v * 100).toFixed(2)}%`
}

interface ChartRow {
  label: string
  ts: number
  global429: number
  [key: string]: string | number
}

function buildRows(
  history: ObservabilityHistoryPoint[],
  accountIds: number[],
): ChartRow[] {
  return history.map((p) => {
    const row: ChartRow = {
      label: p.label,
      ts: p.ts,
      global429: p.global429,
    }
    for (const id of accountIds) {
      const a = p.accounts[id]
      row[`rate_${id}`] = a?.rateRps ?? 0
      row[`safeLo_${id}`] = a?.safeLo ?? 0
      row[`safeHi_${id}`] = a?.safeHi ?? 0
      row[`inflight_${id}`] = a?.inflight ?? 0
      row[`maxInflight_${id}`] = a?.maxInflight ?? 0
    }
    return row
  })
}

function StateMarkers({
  markers,
  axis = 'left',
}: {
  markers: StateTransitionMarker[]
  axis?: 'left' | 'right'
}) {
  return (
    <>
      {markers.map((m, i) => (
        <ReferenceLine
          key={`${m.ts}-${m.accountId}-${i}`}
          yAxisId={axis}
          x={m.label}
          stroke={
            m.to === 'OPEN'
              ? '#ef4444'
              : m.to === 'HALF_OPEN'
                ? '#f59e0b'
                : '#10b981'
          }
          strokeDasharray="4 4"
          strokeWidth={1.5}
          label={{
            value: `#${m.accountId}→${m.to.slice(0, 4)}`,
            position: 'insideTopRight',
            fontSize: 9,
            fill: '#94a3b8',
          }}
        />
      ))}
    </>
  )
}

export function ObservabilityTrendCharts({
  history,
  accountIds,
  stateMarkers,
}: {
  history: ObservabilityHistoryPoint[]
  accountIds: number[]
  stateMarkers: StateTransitionMarker[]
}) {
  const [focusId, setFocusId] = useState<string>(
    accountIds[0] != null ? String(accountIds[0]) : '',
  )

  const rows = useMemo(
    () => buildRows(history, accountIds),
    [history, accountIds],
  )
  const interval = pickXInterval(rows.length)
  const focusNum = Number(focusId)
  const hasData = rows.length >= 2

  if (!hasData) {
    return (
      <section className="mb-8 space-y-4">
        <h2 className="text-sm font-medium text-muted-foreground">时序趋势</h2>
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            趋势图需要至少 2 次轮询采样（约 10s）… 请稍候
          </CardContent>
        </Card>
      </section>
    )
  }

  return (
    <section className="mb-8 space-y-4">
      <h2 className="text-sm font-medium text-muted-foreground">
        时序趋势（前端累积{' '}
        {history.length >= 2
          ? Math.round((history[history.length - 1].ts - history[0].ts) / 1000)
          : 0}
        s）
      </h2>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="text-sm font-medium">
                发送速率 rps + Safe 区间
              </CardTitle>
              {accountIds.length > 1 && (
                <Select value={focusId} onValueChange={setFocusId}>
                  <SelectTrigger className="h-7 w-[100px] text-[11px]">
                    <SelectValue placeholder="账号" />
                  </SelectTrigger>
                  <SelectContent>
                    {accountIds.map((id) => (
                      <SelectItem key={id} value={String(id)}>
                        #{id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          </CardHeader>
          <CardContent>
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={rows} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/50" />
                  <XAxis
                    dataKey="label"
                    tick={{ fontSize: 10 }}
                    className="fill-muted-foreground"
                    interval={interval}
                  />
                  <YAxis
                    yAxisId="left"
                    tick={{ fontSize: 10 }}
                    className="fill-muted-foreground"
                    width={36}
                    domain={[0, 'auto']}
                  />
                  <Tooltip
                    cursor={tooltipCursorStyle}
                    contentStyle={tooltipContentStyle}
                    labelStyle={tooltipLabelStyle}
                    itemStyle={tooltipItemStyle}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  {focusNum > 0 && (
                    <>
                      <Area
                        yAxisId="left"
                        type="monotone"
                        dataKey={`safeHi_${focusNum}`}
                        stroke="none"
                        fill="#10b981"
                        fillOpacity={0.12}
                        name={`#${focusNum} safeHi`}
                        legendType="none"
                        isAnimationActive={false}
                      />
                      <Area
                        yAxisId="left"
                        type="monotone"
                        dataKey={`safeLo_${focusNum}`}
                        stroke="none"
                        fill="var(--background)"
                        fillOpacity={1}
                        name={`#${focusNum} safeLo`}
                        legendType="none"
                        isAnimationActive={false}
                      />
                    </>
                  )}
                  {accountIds.map((id) => (
                    <Line
                      key={id}
                      yAxisId="left"
                      type="monotone"
                      dataKey={`rate_${id}`}
                      stroke={accountColor(id, accountIds)}
                      name={`#${id} rps`}
                      dot={false}
                      strokeWidth={id === focusNum ? 2.5 : 1.5}
                      strokeOpacity={accountIds.length <= 3 || id === focusNum ? 1 : 0.45}
                      isAnimationActive={false}
                    />
                  ))}
                  <StateMarkers markers={stateMarkers} />
                </ComposedChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">
              上游 429 率（全局）
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={rows} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/50" />
                  <XAxis
                    dataKey="label"
                    tick={{ fontSize: 10 }}
                    className="fill-muted-foreground"
                    interval={interval}
                  />
                  <YAxis
                    tick={{ fontSize: 10 }}
                    className="fill-muted-foreground"
                    width={44}
                    tickFormatter={(v: number) => formatPct(v)}
                    domain={[0, 'auto']}
                  />
                  <Tooltip
                    cursor={tooltipCursorStyle}
                    contentStyle={tooltipContentStyle}
                    labelStyle={tooltipLabelStyle}
                    itemStyle={tooltipItemStyle}
                    formatter={(v: number) => formatPct(v)}
                  />
                  <ReferenceLine
                    y={PROBE_BUDGET_LOW}
                    stroke="#10b981"
                    strokeDasharray="6 4"
                    label={{ value: '1%', position: 'insideTopLeft', fontSize: 10, fill: '#10b981' }}
                  />
                  <ReferenceLine
                    y={PROBE_BUDGET_HIGH}
                    stroke="#ef4444"
                    strokeDasharray="6 4"
                    label={{ value: '2%', position: 'insideTopLeft', fontSize: 10, fill: '#ef4444' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="global429"
                    stroke="#ef4444"
                    name="全局 429"
                    dot={false}
                    strokeWidth={2}
                    isAnimationActive={false}
                  />
                  <StateMarkers markers={stateMarkers} axis="left" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="xl:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">
              Inflight 占用（current / max）
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={rows} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border/50" />
                  <XAxis
                    dataKey="label"
                    tick={{ fontSize: 10 }}
                    className="fill-muted-foreground"
                    interval={interval}
                  />
                  <YAxis
                    yAxisId="left"
                    tick={{ fontSize: 10 }}
                    className="fill-muted-foreground"
                    width={32}
                    allowDecimals={false}
                    domain={[0, 'auto']}
                  />
                  <Tooltip
                    cursor={tooltipCursorStyle}
                    contentStyle={tooltipContentStyle}
                    labelStyle={tooltipLabelStyle}
                    itemStyle={tooltipItemStyle}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  {accountIds.map((id) => (
                    <Area
                      key={`inf-${id}`}
                      yAxisId="left"
                      type="monotone"
                      dataKey={`inflight_${id}`}
                      stroke={accountColor(id, accountIds)}
                      fill={accountColor(id, accountIds)}
                      fillOpacity={0.15}
                      name={`#${id} inflight`}
                      isAnimationActive={false}
                    />
                  ))}
                  {accountIds.map((id) => (
                    <Line
                      key={`max-${id}`}
                      yAxisId="left"
                      type="monotone"
                      dataKey={`maxInflight_${id}`}
                      stroke={accountColor(id, accountIds)}
                      name={`#${id} max`}
                      dot={false}
                      strokeWidth={1}
                      strokeDasharray="4 3"
                      isAnimationActive={false}
                    />
                  ))}
                </ComposedChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  )
}

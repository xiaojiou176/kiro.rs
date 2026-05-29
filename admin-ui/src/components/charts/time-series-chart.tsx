import { memo, useMemo } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import type { TimeSeriesPoint, StatsRange } from '@/types/api'
import { tooltipCursorStyle } from './tooltip-style'
import { formatCredits, formatNumber } from '@/lib/utils'

interface Props {
  data: TimeSeriesPoint[]
  range: StatsRange
}

const COLORS = {
  input: '#3b82f6',
  output: '#10b981',
  cacheCreation: '#f59e0b',
  cacheRead: '#06b6d4',
  cacheHitRate: '#a855f7',
  credits: '#ec4899',
} as const

const SERIES = [
  { key: 'inputTokens', name: 'Input', color: COLORS.input, axis: 'left' as const, kind: 'tokens' as const },
  { key: 'outputTokens', name: 'Output', color: COLORS.output, axis: 'left' as const, kind: 'tokens' as const },
  { key: 'cacheCreationTokens', name: 'Cache Creation', color: COLORS.cacheCreation, axis: 'left' as const, kind: 'tokens' as const },
  { key: 'cacheReadTokens', name: 'Cache Read', color: COLORS.cacheRead, axis: 'left' as const, kind: 'tokens' as const },
  { key: 'cacheHitRate', name: 'Cache Hit Rate', color: COLORS.cacheHitRate, axis: 'right' as const, kind: 'percent' as const },
]

interface ChartPoint extends TimeSeriesPoint {
  label: string
  cacheHitRate: number
}

function formatTs(ts: string, range: StatsRange): string {
  const d = new Date(ts)
  const md = `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
  if (range === '30d') return `${d.getFullYear()}-${md}`
  return `${d.getFullYear()}-${md} ${String(d.getHours()).padStart(2, '0')}:00`
}

/** 命中率 = cacheRead / (input + cacheRead)，无缓存读取时为 0 */
function calcHitRate(p: TimeSeriesPoint): number {
  const denom = p.inputTokens + p.cacheReadTokens
  if (denom <= 0) return 0
  return (p.cacheReadTokens / denom) * 100
}

function pickXAxisInterval(len: number): number | 'preserveStartEnd' {
  if (len <= 12) return 0
  if (len <= 48) return Math.ceil(len / 12)
  return Math.ceil(len / 16)
}

function ChartTooltip({ active, payload, label }: {
  active?: boolean
  payload?: ReadonlyArray<{
    dataKey?: string | number
    value?: number
    color?: string
    payload?: ChartPoint
  }>
  label?: string
}) {
  if (!active || !payload?.length) return null
  // 按 SERIES 顺序展示，保证视觉稳定（recharts 默认顺序按 Line 注册顺序）
  const map = new Map<string, number>()
  payload.forEach((p) => {
    if (typeof p.dataKey === 'string' && typeof p.value === 'number') {
      map.set(p.dataKey, p.value)
    }
  })
  // credits 不画线，从原始数据点里直接取
  const credits = payload[0]?.payload?.credits ?? 0
  return (
    <div
      style={{
        background: 'rgba(20,20,20,0.94)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 10,
        padding: '10px 14px',
        boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
        fontSize: 12,
        color: '#fff',
        minWidth: 180,
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 6, color: 'rgba(255,255,255,0.92)' }}>{label}</div>
      {SERIES.map((s) => {
        const v = map.get(s.key)
        if (v == null) return null
        const valueStr = s.kind === 'percent' ? `${v.toFixed(1)}%` : formatNumber(v)
        return (
          <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '2px 0' }}>
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: 2,
                background: s.color,
                display: 'inline-block',
              }}
            />
            <span style={{ flex: 1 }}>{s.name}:</span>
            <span style={{ fontVariantNumeric: 'tabular-nums' }}>{valueStr}</span>
          </div>
        )
      })}
      {credits > 0 && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '4px 0 0',
            marginTop: 4,
            borderTop: '1px solid rgba(255,255,255,0.08)',
          }}
        >
          <span
            style={{
              width: 10,
              height: 10,
              borderRadius: 2,
              background: COLORS.credits,
              display: 'inline-block',
            }}
          />
          <span style={{ flex: 1 }}>Credit:</span>
          <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatCredits(credits)}</span>
        </div>
      )}
    </div>
  )
}

function TimeSeriesChartImpl({ data, range }: Props) {
  const formatted = useMemo<ChartPoint[]>(
    () =>
      data.map((p) => ({
        ...p,
        label: formatTs(p.ts, range),
        cacheHitRate: calcHitRate(p),
      })),
    [data, range],
  )
  const interval = useMemo(() => pickXAxisInterval(formatted.length), [formatted.length])
  // 全零时强制让左轴显示 0 刻度，避免空白
  const leftAllZero = useMemo(
    () =>
      formatted.every(
        (p) =>
          p.inputTokens === 0 &&
          p.outputTokens === 0 &&
          p.cacheCreationTokens === 0 &&
          p.cacheReadTokens === 0,
      ),
    [formatted],
  )

  return (
    <ResponsiveContainer width="100%" height={320}>
      <LineChart data={formatted} margin={{ top: 16, right: 16, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" className="stroke-border/50" />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 11 }}
          className="fill-muted-foreground"
          interval={interval}
        />
        <YAxis
          yAxisId="left"
          tick={{ fontSize: 11 }}
          className="fill-muted-foreground"
          tickFormatter={(v: number) => formatNumber(v)}
          width={56}
          domain={leftAllZero ? [0, 1] : [0, 'auto']}
          ticks={leftAllZero ? [0] : undefined}
          allowDecimals={false}
        />
        <YAxis
          yAxisId="right"
          orientation="right"
          tick={{ fontSize: 11, fill: COLORS.cacheHitRate }}
          domain={[0, 100]}
          ticks={[0, 20, 40, 60, 80, 100]}
          tickFormatter={(v: number) => `${v}%`}
          width={44}
        />
        <Tooltip content={<ChartTooltip />} cursor={tooltipCursorStyle} />
        <Legend
          verticalAlign="top"
          align="center"
          iconType="circle"
          wrapperStyle={{ fontSize: 12, paddingBottom: 8 }}
        />
        {SERIES.map((s) => (
          <Line
            key={s.key}
            yAxisId={s.axis}
            type="monotone"
            dataKey={s.key}
            stroke={s.color}
            name={s.name}
            dot={false}
            strokeWidth={s.kind === 'percent' ? 1.8 : 2}
            strokeDasharray={s.kind === 'percent' ? '4 4' : undefined}
            isAnimationActive={false}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}

export const TimeSeriesChart = memo(TimeSeriesChartImpl)

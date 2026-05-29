import { memo, useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import type { CredentialDistribution } from '@/types/api'
import { tooltipContentStyle, tooltipCursorStyle, tooltipItemStyle, tooltipLabelStyle } from './tooltip-style'
import { formatNumber } from '@/lib/utils'

interface Props {
  data: CredentialDistribution[]
}

function CredentialBarChartImpl({ data }: Props) {
  const formatted = useMemo(
    () =>
      data.slice(0, 12).map((d) => ({
        label: d.email ? truncateEmail(d.email) : `#${d.credentialId}`,
        fullLabel: d.email ?? `#${d.credentialId}`,
        inputTokens: d.inputTokens,
        outputTokens: d.outputTokens,
        calls: d.calls,
        errors: d.errors,
      })),
    [data],
  )

  if (data.length === 0) {
    return (
      <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
        暂无数据
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={340}>
      <BarChart data={formatted} margin={{ top: 8, right: 16, left: 0, bottom: 64 }}>
        <CartesianGrid strokeDasharray="3 3" className="stroke-border/50" />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 10 }}
          angle={-30}
          textAnchor="end"
          interval={0}
          height={72}
        />
        <YAxis
          tick={{ fontSize: 11 }}
          tickFormatter={(v: number) => formatNumber(v)}
          width={48}
        />
        <Tooltip
          contentStyle={tooltipContentStyle}
          labelStyle={tooltipLabelStyle}
          itemStyle={tooltipItemStyle}
          cursor={tooltipCursorStyle}
          formatter={(value: number) => formatNumber(value)}
          labelFormatter={(_label: string, payload) => {
            const item = payload?.[0]?.payload as { fullLabel?: string } | undefined
            return item?.fullLabel ?? _label
          }}
        />
        <Legend
          verticalAlign="top"
          align="right"
          height={28}
          wrapperStyle={{ fontSize: 12 }}
        />
        <Bar dataKey="inputTokens" name="输入" stackId="a" fill="#3b82f6" isAnimationActive={false} />
        <Bar dataKey="outputTokens" name="输出" stackId="a" fill="#10b981" isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export const CredentialBarChart = memo(CredentialBarChartImpl)

/** 仅用于 X 轴展示：保留 @ 后域名前 1-2 段，整体最长 22 字符 */
function truncateEmail(email: string): string {
  if (email.length <= 22) return email
  const at = email.indexOf('@')
  if (at < 0) return email.slice(0, 20) + '…'
  const name = email.slice(0, at)
  const domain = email.slice(at + 1)
  const shortName = name.length > 12 ? name.slice(0, 11) + '…' : name
  return `${shortName}@${domain}`
}

import { memo, useMemo } from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import type { ModelDistribution } from '@/types/api'
import { tooltipContentStyle, tooltipItemStyle, tooltipLabelStyle } from './tooltip-style'
import { formatNumber } from '@/lib/utils'

interface Props {
  data: ModelDistribution[]
}

const PALETTE = [
  '#3b82f6', '#10b981', '#a855f7', '#f59e0b', '#ec4899',
  '#06b6d4', '#84cc16', '#f97316', '#6366f1', '#14b8a6',
]

function ModelPieChartImpl({ data }: Props) {
  const { chartData, total } = useMemo(() => {
    const total = data.reduce((s, d) => s + d.calls, 0) || 1
    const chartData = data.map((d) => ({
      name: d.model,
      value: d.calls,
      inputTokens: d.inputTokens,
      outputTokens: d.outputTokens,
    }))
    return { chartData, total }
  }, [data])

  if (data.length === 0) {
    return (
      <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
        暂无数据
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie
          data={chartData}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          outerRadius={90}
          innerRadius={48}
          paddingAngle={2}
          isAnimationActive={false}
        >
          {chartData.map((_, i) => (
            <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={tooltipContentStyle}
          labelStyle={tooltipLabelStyle}
          itemStyle={tooltipItemStyle}
          cursor={false}
          formatter={(value: number, _name, item) => {
            const pct = ((value / total) * 100).toFixed(1)
            const payload = (item?.payload ?? {}) as { inputTokens?: number; outputTokens?: number }
            return [
              `${formatNumber(value)} 次（${pct}%）  in ${formatNumber(payload.inputTokens ?? 0)} / out ${formatNumber(payload.outputTokens ?? 0)}`,
              item?.payload?.name as string,
            ]
          }}
        />
        <Legend wrapperStyle={{ fontSize: 11 }} iconSize={8} />
      </PieChart>
    </ResponsiveContainer>
  )
}

export const ModelPieChart = memo(ModelPieChartImpl)

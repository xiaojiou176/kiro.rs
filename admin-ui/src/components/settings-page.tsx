import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { Gauge, RefreshCw, Save, ArrowRightLeft, Lock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { useRateLimitConfig, useSetRateLimitConfig } from '@/hooks/use-settings'
import type { RateLimitConfigPatch } from '@/types/api'
import { extractErrorMessage } from '@/lib/utils'

/** 一个数值参数的编辑行：标签 + 说明 + number 输入框 */
function NumberField({
  label,
  hint,
  value,
  step,
  min,
  max,
  onChange,
}: {
  label: string
  hint: string
  value: number
  step?: number
  min?: number
  max?: number
  onChange: (v: number) => void
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{label}</div>
        <div className="text-xs text-muted-foreground">{hint}</div>
      </div>
      <Input
        type="number"
        className="w-32 shrink-0"
        value={Number.isFinite(value) ? value : ''}
        step={step ?? 'any'}
        min={min}
        max={max}
        onChange={(e) => {
          const v = parseFloat(e.target.value)
          if (!Number.isNaN(v)) onChange(v)
        }}
      />
    </div>
  )
}

export function SettingsPage() {
  const { data, isLoading, isError, error, refetch, isFetching } = useRateLimitConfig()
  const save = useSetRateLimitConfig()

  // 本地草稿：从服务端值初始化，保存前都在本地改
  const [draft, setDraft] = useState<RateLimitConfigPatch>({})

  // 服务端值到了/变了，重置草稿为空（草稿空=显示服务端值）
  useEffect(() => {
    setDraft({})
  }, [data])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> 加载限速配置…
      </div>
    )
  }
  if (isError || !data) {
    return (
      <div className="py-20 text-center">
        <div className="text-sm text-destructive">
          加载失败：{extractErrorMessage(error)}
        </div>
        <Button variant="outline" className="mt-3" onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> 重试
        </Button>
      </div>
    )
  }

  // 当前显示值 = 草稿覆盖服务端值
  const cur = { ...data, ...draft }
  const ov = { ...data.overflowOnBusy, ...(draft.overflowOnBusy ?? {}) }
  const dirty = Object.keys(draft).length > 0

  const setField = (patch: Partial<RateLimitConfigPatch>) =>
    setDraft((d) => ({ ...d, ...patch }))
  const setOv = (patch: Partial<RateLimitConfigPatch['overflowOnBusy']>) =>
    setDraft((d) => ({ ...d, overflowOnBusy: { ...(d.overflowOnBusy ?? {}), ...patch } }))

  const onSave = () => {
    if (!dirty) {
      toast.info('没有改动')
      return
    }
    save.mutate(draft, {
      onSuccess: (res) => {
        toast.success(
          res.persisted
            ? '已保存并落盘，立即对所有账号生效（无需重启）'
            : '已热改生效，但未落盘 config.json（重启会丢）',
        )
      },
      onError: (err) => toast.error('保存失败：' + extractErrorMessage(err)),
    })
  }

  return (
    <div className="mx-auto max-w-2xl space-y-4 py-2">
      {/* 吞吐爬升参数 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="flex items-center gap-2 text-base">
            <Gauge className="h-4 w-4" /> 吞吐爬升参数
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
          </Button>
        </CardHeader>
        <CardContent className="divide-y">
          <NumberField
            label="加速步长 (additiveStepRps)"
            hint="每次往上加多少请求/秒。调大=爬升更快。"
            value={cur.additiveStepRps}
            step={0.05}
            min={0}
            onChange={(v) => setField({ additiveStepRps: v })}
          />
          <NumberField
            label="加速间隔 (increaseIntervalSecs)"
            hint="隔多少秒才允许加一次。调小=爬升更频繁。"
            value={cur.increaseIntervalSecs}
            step={1}
            min={0}
            onChange={(v) => setField({ increaseIntervalSecs: Math.round(v) })}
          />
          <NumberField
            label="加速成功阈值 (successesPerIncrease)"
            hint="连续成功几次才肯加速。调小=更激进。"
            value={cur.successesPerIncrease}
            step={1}
            min={1}
            onChange={(v) => setField({ successesPerIncrease: Math.round(v) })}
          />
          <NumberField
            label="最高速率 (maxRateRps)"
            hint="日常爬升天花板（请求/秒）。"
            value={cur.maxRateRps}
            step={0.5}
            min={0}
            onChange={(v) => setField({ maxRateRps: v })}
          />
          <NumberField
            label="429 硬上限 (goodputHardCeiling)"
            hint="窗口 429 率超此值就强制降速（0~1）。"
            value={cur.goodputHardCeiling}
            step={0.01}
            min={0}
            max={1}
            onChange={(v) => setField({ goodputHardCeiling: v })}
          />
          <NumberField
            label="失控保险丝 (goodputSanityMaxRps)"
            hint="rate 绝对上限，防爬山失控（请求/秒）。"
            value={cur.goodputSanityMaxRps}
            step={0.5}
            min={0}
            onChange={(v) => setField({ goodputSanityMaxRps: v })}
          />
          <div className="flex items-start justify-between gap-4 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5 text-sm font-medium text-muted-foreground">
                <Lock className="h-3.5 w-3.5" /> 最大并发 (hardMaxInflight)
              </div>
              <div className="text-xs text-muted-foreground">
                信号量容量，构造时定死，改它需重启——这里只读展示。
              </div>
            </div>
            <div className="w-32 shrink-0 text-right text-sm tabular-nums text-muted-foreground">
              {data.hardMaxInflight}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Overflow-on-busy 撞墙迁移 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowRightLeft className="h-4 w-4" /> Overflow 撞墙迁移
          </CardTitle>
        </CardHeader>
        <CardContent className="divide-y">
          <div className="flex items-center justify-between gap-4 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium">启用 (enabled)</div>
              <div className="text-xs text-muted-foreground">
                绑定号撞 429 且吞吐低时，把整个会话迁到健康号。
              </div>
            </div>
            <Switch
              checked={ov.enabled}
              onCheckedChange={(checked) => setOv({ enabled: checked })}
            />
          </div>
          <NumberField
            label="429 率门槛 (upstream429RateThreshold)"
            hint="绑定号 5 分钟 429 率超此值才算撞墙（0~1）。"
            value={ov.upstream429RateThreshold}
            step={0.05}
            min={0}
            max={1}
            onChange={(v) => setOv({ upstream429RateThreshold: v })}
          />
          <NumberField
            label="吞吐比门槛 (goodputRatioThreshold)"
            hint="吞吐低于健康上界的此比例才迁（0~1）。"
            value={ov.goodputRatioThreshold}
            step={0.05}
            min={0}
            max={1}
            onChange={(v) => setOv({ goodputRatioThreshold: v })}
          />
          <NumberField
            label="迁移防抖 (migrateDebounceSecs)"
            hint="迁移后多少秒内不再迁，防来回横跳。"
            value={ov.migrateDebounceSecs}
            step={1}
            min={0}
            onChange={(v) => setOv({ migrateDebounceSecs: Math.round(v) })}
          />
        </CardContent>
      </Card>

      {/* 保存条 */}
      <div className="flex items-center justify-end gap-3">
        {dirty && (
          <span className="text-xs text-amber-500">有未保存改动</span>
        )}
        <Button onClick={onSave} disabled={!dirty || save.isPending}>
          {save.isPending ? (
            <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Save className="mr-2 h-4 w-4" />
          )}
          保存并热生效
        </Button>
      </div>
    </div>
  )
}

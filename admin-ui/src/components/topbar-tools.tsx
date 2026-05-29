import { useState } from 'react'
import {
  Activity, RefreshCw, UploadCloud, Settings, Key, Wand2, Eye, EyeOff, Copy,
} from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { storage } from '@/lib/storage'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from '@/components/ui/dialog'
import {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuContent,
  DropdownMenuItem, DropdownMenuLabel,
} from '@/components/ui/dropdown-menu'
import { useLoadBalancingMode, useSetLoadBalancingMode } from '@/hooks/use-credentials'
import { useUpdateCheck } from '@/hooks/use-update-check'
import { updateAdminKey, updateApiKey } from '@/api/credentials'
import { extractErrorMessage, generateApiKey } from '@/lib/utils'
import { ImageUpdateDialog } from '@/components/image-update-dialog'

/**
 * 顶栏右侧通用工具栏：负载均衡切换、刷新、在线更新、设置（Key 管理）。
 *
 * 与原 Dashboard 中的工具按钮等价，但全局 Tab 都可访问。刷新按钮会失效
 * 凭据/客户端 Key/统计三类查询，覆盖三个 Tab 的主要数据源。
 */
export function TopbarTools() {
  const queryClient = useQueryClient()
  const { data: loadBalancingData, isLoading: isLoadingMode } = useLoadBalancingMode()
  const { mutate: setLoadBalancingMode, isPending: isSettingMode } = useSetLoadBalancingMode()
  const { data: updateCheck } = useUpdateCheck()

  const [imageUpdateOpen, setImageUpdateOpen] = useState(false)

  const [keyDialogOpen, setKeyDialogOpen] = useState(false)
  const [keyEditMode, setKeyEditMode] = useState<'admin' | 'api'>('admin')
  const [newKey, setNewKey] = useState('')
  const [showPlain, setShowPlain] = useState(false)
  const [updating, setUpdating] = useState(false)

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['credentials'] })
    queryClient.invalidateQueries({ queryKey: ['client-keys'] })
    queryClient.invalidateQueries({ queryKey: ['stats'] })
    toast.success('已刷新')
  }

  const handleToggleLoadBalancing = () => {
    const cur = loadBalancingData?.mode || 'priority'
    const next = cur === 'priority' ? 'balanced' : 'priority'
    setLoadBalancingMode(next, {
      onSuccess: () => toast.success(`已切换到${next === 'priority' ? '优先级模式' : '均衡负载模式'}`),
      onError: (err) => toast.error(`切换失败: ${extractErrorMessage(err)}`),
    })
  }

  const openKeyDialog = (mode: 'admin' | 'api') => {
    setKeyEditMode(mode)
    setNewKey('')
    setShowPlain(false)
    setKeyDialogOpen(true)
  }

  const handleUpdateKey = async (e: React.FormEvent) => {
    e.preventDefault()
    const key = newKey.trim()
    if (!key) {
      toast.error(keyEditMode === 'admin' ? '新 Admin Key 不能为空' : '新 API Key 不能为空')
      return
    }
    setUpdating(true)
    try {
      if (keyEditMode === 'admin') {
        await updateAdminKey({ newKey: key })
        storage.setApiKey(key)
        toast.success('Admin API Key 已更新，已自动切换到新 Key')
      } else {
        await updateApiKey({ newKey: key })
        toast.success('业务 API Key 已更新，所有使用 /v1 接口的客户端都需要切换')
      }
      setKeyDialogOpen(false)
      setNewKey('')
    } catch (err) {
      toast.error(`更新失败: ${extractErrorMessage(err)}`)
    } finally {
      setUpdating(false)
    }
  }

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        onClick={handleToggleLoadBalancing}
        disabled={isLoadingMode || isSettingMode}
        title="切换负载均衡模式"
      >
        <Activity className="h-3.5 w-3.5" />
        <span className="hidden md:inline">
          {isLoadingMode ? '加载中…' : (loadBalancingData?.mode === 'priority' ? '优先级' : '均衡负载')}
        </span>
      </Button>
      <Button variant="ghost" size="icon" onClick={handleRefresh} title="刷新">
        <RefreshCw className="h-4 w-4" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setImageUpdateOpen(true)}
        title={
          updateCheck?.hasUpdate
            ? `发现新版本 v${updateCheck.latestVersion}（当前 v${updateCheck.currentVersion}）`
            : '镜像在线更新'
        }
        className="relative"
      >
        <UploadCloud className="h-4 w-4" />
        {updateCheck?.hasUpdate && (
          <span className="absolute right-1 top-1 inline-flex h-2 w-2 items-center justify-center">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500" />
          </span>
        )}
      </Button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" title="设置">
            <Settings className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>密钥管理</DropdownMenuLabel>
          <DropdownMenuItem onSelect={() => openKeyDialog('admin')}>
            <Key />修改 Admin API Key（管理面板登录）
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => openKeyDialog('api')}>
            <Key />修改业务 API Key（客户端 /v1 调用）
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <ImageUpdateDialog open={imageUpdateOpen} onOpenChange={setImageUpdateOpen} />

      <Dialog
        open={keyDialogOpen}
        onOpenChange={(open) => { if (!updating) setKeyDialogOpen(open) }}
      >
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Key className="h-4 w-4" />
              {keyEditMode === 'admin' ? '修改 Admin API Key' : '修改业务 API Key'}
            </DialogTitle>
            <DialogDescription>
              {keyEditMode === 'admin'
                ? '用于登录此管理面板。修改后将自动更新本地存储的 Key，无需重新登录。'
                : '客户端调用 /v1/* 接口时携带的密钥。修改后所有第三方客户端（Cline、Cursor、SDK 等）都需要更新为新值。'}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleUpdateKey} className="space-y-4 py-2">
            <div className="relative">
              <Input
                type={showPlain ? 'text' : 'password'}
                placeholder="输入或生成新的 Key"
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
                disabled={updating}
                autoFocus
                className="pr-20 font-mono text-[13px]"
              />
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-1.5">
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="pointer-events-auto h-7 w-7"
                  onClick={() => setShowPlain((v) => !v)}
                  disabled={updating}
                  title={showPlain ? '隐藏' : '显示'}
                >
                  {showPlain ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="pointer-events-auto h-7 w-7"
                  onClick={async () => {
                    if (!newKey.trim()) {
                      toast.error('请先输入或生成 Key 再复制')
                      return
                    }
                    try {
                      await navigator.clipboard.writeText(newKey)
                      toast.success('已复制到剪贴板')
                    } catch {
                      toast.error('复制失败，请手动选择文本')
                    }
                  }}
                  disabled={updating}
                  title="复制"
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
            <div className="flex items-center justify-between gap-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => {
                  const key = generateApiKey(
                    keyEditMode === 'admin' ? 'sk-admin-' : 'sk-kiro-',
                  )
                  setNewKey(key)
                  setShowPlain(true)
                }}
                disabled={updating}
              >
                <Wand2 className="h-3.5 w-3.5" />生成随机 Key
              </Button>
              <p className="text-[11px] text-muted-foreground">
                建议生成后立即复制保存，确认更新后即生效。
              </p>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setKeyDialogOpen(false)} disabled={updating}>
                取消
              </Button>
              <Button type="submit" disabled={updating || !newKey.trim()}>
                {updating ? '更新中…' : '确认更新'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { useCredentialModels } from '@/hooks/use-credentials'
import { parseError, formatNumber } from '@/lib/utils'

interface AvailableModelsDialogProps {
  credentialId: number | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AvailableModelsDialog({
  credentialId,
  open,
  onOpenChange,
}: AvailableModelsDialogProps) {
  const { data, isLoading, error } = useCredentialModels(
    open ? credentialId : null,
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>凭据 #{credentialId} 可用模型</DialogTitle>
        </DialogHeader>

        {isLoading && (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        )}

        {error &&
          (() => {
            const parsed = parseError(error)
            return (
              <div className="py-6 space-y-3">
                <div className="flex items-center justify-center gap-2 text-red-500">
                  <svg className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path
                      fillRule="evenodd"
                      d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                      clipRule="evenodd"
                    />
                  </svg>
                  <span className="font-medium">{parsed.title}</span>
                </div>
                {parsed.detail && (
                  <div className="text-sm text-muted-foreground text-center px-4">
                    {parsed.detail}
                  </div>
                )}
              </div>
            )
          })()}

        {data && data.models.length === 0 && (
          <div className="py-8 text-center text-sm text-muted-foreground">
            该凭据当前没有可用模型
          </div>
        )}

        {data && data.models.length > 0 && (
          <div className="space-y-2 max-h-[60vh] overflow-auto pr-1">
            {data.models.map((m) => (
              <div
                key={m.modelId}
                className="rounded-lg border border-border/60 bg-secondary/40 px-3 py-2.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-sm truncate">
                    {m.modelName || m.modelId}
                  </span>
                  {m.maxInputTokens != null && (
                    <Badge variant="secondary" className="shrink-0 tabular-nums">
                      {formatNumber(m.maxInputTokens)} tokens
                    </Badge>
                  )}
                </div>
                {m.modelName && m.modelName !== m.modelId && (
                  <div className="mt-0.5 font-mono text-[11px] text-muted-foreground truncate">
                    {m.modelId}
                  </div>
                )}
                {m.description && (
                  <div className="mt-1 text-xs text-muted-foreground">
                    {m.description}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

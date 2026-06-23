import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getRateLimitConfig, setRateLimitConfig } from '@/api/settings'
import type { RateLimitConfigPatch } from '@/types/api'

/** 限速器运行时配置：进页面拉一次，不轮询（改动靠 mutation 后失效刷新） */
export function useRateLimitConfig() {
  return useQuery({
    queryKey: ['rate-limit-config'],
    queryFn: getRateLimitConfig,
    staleTime: 10_000,
    refetchOnWindowFocus: false,
  })
}

/** 热改限速器参数 */
export function useSetRateLimitConfig() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (patch: RateLimitConfigPatch) => setRateLimitConfig(patch),
    onSuccess: (data) => {
      // 用返回的全量值直接回填缓存，避免再发一次 GET
      queryClient.setQueryData(['rate-limit-config'], data)
    },
  })
}

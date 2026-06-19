import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getObservability,
  pinSession,
  unpinSession,
  setSessionPriority,
} from '@/api/observability'

/** 运行观测快照：5s 轮询，用于实时面板 */
export function useObservability() {
  return useQuery({
    queryKey: ['observability'],
    queryFn: getObservability,
    refetchInterval: 5_000,
    staleTime: 2_000,
    refetchOnWindowFocus: false,
  })
}

export function usePinSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      sessionId,
      credentialId,
    }: {
      sessionId: string
      credentialId: number
    }) => pinSession(sessionId, credentialId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['observability'] })
    },
  })
}

export function useUnpinSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (sessionId: string) => unpinSession(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['observability'] })
    },
  })
}

export function useSetSessionPriority() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      sessionId,
      priority,
    }: {
      sessionId: string
      priority: number
    }) => setSessionPriority(sessionId, priority),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['observability'] })
    },
  })
}

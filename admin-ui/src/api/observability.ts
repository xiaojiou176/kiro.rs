import axios from 'axios'
import { storage } from '@/lib/storage'
import type { ObservabilitySnapshot, SuccessResponse } from '@/types/api'

const api = axios.create({
  baseURL: '/api/admin',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const apiKey = storage.getApiKey()
  if (apiKey) config.headers['x-api-key'] = apiKey
  return config
})

export async function getObservability(): Promise<ObservabilitySnapshot> {
  const { data } = await api.get<ObservabilitySnapshot>('/observability')
  return data
}

export async function pinSession(
  sessionId: string,
  credentialId: number,
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>('/sessions/pin', {
    sessionId,
    credentialId,
  })
  return data
}

export async function unpinSession(sessionId: string): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>('/sessions/unpin', { sessionId })
  return data
}

export async function setSessionPriority(
  sessionId: string,
  priority: number,
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>('/sessions/priority', {
    sessionId,
    priority,
  })
  return data
}

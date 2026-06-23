import axios from 'axios'
import { storage } from '@/lib/storage'
import type { RateLimitConfigResponse, RateLimitConfigPatch } from '@/types/api'

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

/** 读当前限速器运行时配置（热替换后的 live 值） */
export async function getRateLimitConfig(): Promise<RateLimitConfigResponse> {
  const { data } = await api.get<RateLimitConfigResponse>('/config/rate-limit')
  return data
}

/** 热改限速器参数（只传要改的字段）；返回更新后的全量值 */
export async function setRateLimitConfig(
  patch: RateLimitConfigPatch,
): Promise<RateLimitConfigResponse> {
  const { data } = await api.put<RateLimitConfigResponse>('/config/rate-limit', patch)
  return data
}

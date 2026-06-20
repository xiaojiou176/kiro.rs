//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求
//! 支持多凭据故障转移和重试
//! 支持按凭据级 endpoint 切换不同 Kiro API 端点

use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::admin::trace_db::{TraceAttempt, TraceSink, outcome, truncate_snippet};
use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::rate_limiter::{
    AcquireOutcome, LimiterRegistry, ThrottleScope, classify_throttle_reason,
};
use crate::kiro::token_manager::MultiTokenManager;
use crate::model::config::TlsBackend;
use crate::observability;
use parking_lot::Mutex;

/// 每个凭据的最大重试次数
const MAX_RETRIES_PER_CREDENTIAL: usize = 3;

/// 总重试次数硬上限（避免无限重试）
///
/// 注：上游 429 多为账号级速率配额（SERVICE_REQUEST_RATE_EXCEEDED），高峰期
/// 多账号同时触顶时，过多重试会在账号间连环撞墙、放大限流。故上限取较小值，
/// 配合 429 专用长退避（见 retry_delay_throttle），被限时尽早返回而非耗尽配额。
const MAX_TOTAL_RETRIES: usize = 4;

/// 本地 limiter 排队耗尽时的最后状态（用于映射 429 而非 502）。
#[derive(Debug, Clone, Copy)]
struct LocalThrottleMarker {
    reason: &'static str,
    est_wait_ms: u64,
    current_rps: f64,
}

/// 单次 retry attempt 结束时：若仍持有 permit 且未 on_success/on_throttle，清 HALF_OPEN canary。
struct LimiterAttemptGuard<'a> {
    provider: &'a KiroProvider,
    cred_id: u64,
    permit: Option<crate::kiro::rate_limiter::LimiterPermit>,
    outcome_recorded: bool,
}

impl Drop for LimiterAttemptGuard<'_> {
    fn drop(&mut self) {
        if self.permit.take().is_some()
            && !self.outcome_recorded
            && self.provider.limiters.enabled()
        {
            self.provider
                .limiters
                .for_scope(&ThrottleScope::UserCredential(self.cred_id))
                .on_acquire_aborted();
        }
    }
}

impl<'a> LimiterAttemptGuard<'a> {
    fn new(provider: &'a KiroProvider, cred_id: u64) -> Self {
        Self {
            provider,
            cred_id,
            permit: None,
            outcome_recorded: false,
        }
    }

    fn set_permit(&mut self, permit: crate::kiro::rate_limiter::LimiterPermit) {
        self.permit = Some(permit);
    }

    fn mark_outcome(&mut self) {
        self.outcome_recorded = true;
    }

    fn take_permit_on_success(&mut self) -> Option<crate::kiro::rate_limiter::LimiterPermit> {
        self.outcome_recorded = true;
        self.permit.take()
    }
}

/// HTTP Client 缓存容量上限（不含常驻的全局代理 client）。
/// 代理池条目较多时，避免每个不同代理都常驻一个 reqwest::Client 导致内存无界增长。
const CLIENT_CACHE_CAP: usize = 64;

/// 带容量上限的 HTTP Client 缓存。
///
/// - key 为 effective proxy 配置（None = 直连/全局回退）
/// - 受保护 key（全局代理对应的 effective 配置）永不被淘汰
/// - 超出容量时按插入顺序淘汰最旧的「非受保护」条目
struct ClientCache {
    map: HashMap<Option<ProxyConfig>, Client>,
    /// 插入顺序（仅记录可淘汰的非受保护 key）
    order: std::collections::VecDeque<Option<ProxyConfig>>,
    /// 受保护、不参与淘汰的 key（全局代理）
    protected: Option<ProxyConfig>,
    cap: usize,
}

impl ClientCache {
    fn new(protected: Option<ProxyConfig>, initial: Client, cap: usize) -> Self {
        let mut map = HashMap::new();
        map.insert(protected.clone(), initial);
        Self {
            map,
            order: std::collections::VecDeque::new(),
            protected,
            cap,
        }
    }

    fn get(&self, key: &Option<ProxyConfig>) -> Option<Client> {
        self.map.get(key).cloned()
    }

    /// 插入新条目，必要时淘汰最旧的非受保护条目
    fn insert(&mut self, key: Option<ProxyConfig>, client: Client) {
        if key == self.protected || self.map.contains_key(&key) {
            self.map.insert(key, client);
            return;
        }
        while self.order.len() >= self.cap {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, client);
    }
}

/// API 调用结果，附带本次实际命中的上游凭据 ID（用于用量统计）
pub struct KiroCallResult {
    pub response: reqwest::Response,
    pub credential_id: u64,
    /// 限速器在飞许可（maxInflight 槽位）。
    ///
    /// - **非流式**：handler 取出 `response` 后读完 body，`KiroCallResult`（含本字段）在 handler
    ///   返回前 drop → maxInflight 在 body 消费完毕后才释放。
    /// - **流式**：handler 用 `.take()` 取出本 permit，move 进 `PermitHoldingStream` 包住 SSE 流
    ///   （见 anthropic/handlers.rs）→ permit 随流活到**流真正结束**(完整消费或客户端断连)才 drop，
    ///   maxInflight 槽位才释放。修掉了「流式 permit 在 handler 返回即 drop、长流在飞欠计数」。
    ///   `None` 表示未启用限速或 shadow 模式。
    pub(crate) limiter_permit: Option<crate::kiro::rate_limiter::LimiterPermit>,
}

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
/// 支持多凭据故障转移和重试机制
/// 按凭据 `endpoint` 字段选择 [`KiroEndpoint`] 实现
pub struct KiroProvider {
    token_manager: Arc<MultiTokenManager>,
    /// 全局代理配置（用于凭据无自定义代理时的回退）
    global_proxy: Option<ProxyConfig>,
    /// Client 缓存：key = effective proxy config, value = reqwest::Client
    /// 不同代理配置的凭据使用不同的 Client，共享相同代理的凭据复用 Client。
    /// 带容量上限淘汰（全局代理 client 常驻），避免代理数量增长导致内存无界增长。
    client_cache: Mutex<ClientCache>,
    /// TLS 后端配置
    tls_backend: TlsBackend,
    /// 端点实现注册表（key: endpoint 名称）
    endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
    /// 默认端点名称（凭据未指定 endpoint 时使用）
    default_endpoint: String,
    /// 已尝试过 profileArn 解析的凭据 ID（进程内）。
    ///
    /// 避免对「无 Enterprise profile」的账号（如纯 BuilderID）在每次请求都重复调用
    /// `ListAvailableProfiles`。命中真实 ARN 的账号会把 ARN 持久化进凭据，之后
    /// 通过 `streaming_profile_arn()` 直接命中，不再进入解析路径。
    profile_resolution_attempted: Mutex<HashSet<u64>>,
    /// 自适应限速器容器（按 scope 多 limiter）。解决 AWS 429：
    /// 发送前令牌桶闸门 + AIMD 调速 + 全局冷却 + Fail Aloud。
    /// `enabled=false` 时完全不介入（行为等同改造前）。
    limiters: Arc<LimiterRegistry>,
    /// 灰度作用域："retry_only"（只拦 retry）/ "all"（初始+retry 全拦）。
    limiter_enforce_scope: String,
}

impl KiroProvider {
    /// 创建带代理配置和端点注册表的 KiroProvider 实例
    ///
    /// # Arguments
    /// * `token_manager` - 多凭据 Token 管理器
    /// * `proxy` - 全局代理配置
    /// * `endpoints` - 端点名 → 实现的注册表（至少包含 `default_endpoint` 对应条目）
    /// * `default_endpoint` - 凭据未显式指定 endpoint 时使用的名称
    pub fn with_proxy(
        token_manager: Arc<MultiTokenManager>,
        proxy: Option<ProxyConfig>,
        endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
        default_endpoint: String,
    ) -> Self {
        assert!(
            endpoints.contains_key(&default_endpoint),
            "默认端点 {} 未在 endpoints 注册表中",
            default_endpoint
        );
        let tls_backend = token_manager.config().tls_backend;
        // 预热：构建全局代理对应的 Client（作为受保护的常驻条目）
        let initial_client =
            build_client(proxy.as_ref(), 720, tls_backend).expect("创建 HTTP 客户端失败");
        let client_cache = ClientCache::new(proxy.clone(), initial_client, CLIENT_CACHE_CAP);

        // 自适应限速器：复用 token_manager 内的同一实例，确保 selection 查询到的「剩余冷却」
        // 与此处发送前闸门是同一份状态（多号 session affinity 的切号判定依赖这一点）。
        let limiter_enforce_scope = token_manager
            .config()
            .adaptive_limit
            .enforce_scope
            .clone();
        let limiters = token_manager.limiters();

        Self {
            token_manager,
            global_proxy: proxy,
            client_cache: Mutex::new(client_cache),
            tls_backend,
            endpoints,
            default_endpoint,
            profile_resolution_attempted: Mutex::new(HashSet::new()),
            limiters,
            limiter_enforce_scope,
        }
    }

    /// 根据凭据的代理配置获取（或创建并缓存）对应的 reqwest::Client
    fn client_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let mut cache = self.client_cache.lock();
        if let Some(client) = cache.get(&effective) {
            return Ok(client);
        }
        let client = build_client(effective.as_ref(), 720, self.tls_backend)?;
        cache.insert(effective, client.clone());
        Ok(client)
    }

    /// 根据凭据选择 endpoint 实现
    fn endpoint_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Arc<dyn KiroEndpoint>> {
        let name = credentials
            .endpoint
            .as_deref()
            .unwrap_or(&self.default_endpoint);
        self.endpoints
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未知端点: {}", name))
    }

    /// 在发起请求前，确保 Enterprise / IdC 账号的真实 profileArn 已解析并写入 `ctx`。
    ///
    /// 流式端点强制要求 profileArn；Enterprise / IdC 账号必须先把 BuilderID
    /// 占位符解析为真实 ARN，纯 BuilderID 账号则回退占位符。
    /// 仅对「OAuth 凭据 + profileArn 缺失或为占位符」的账号触发一次上游
    /// `ListAvailableProfiles` 查询（进程内去重）：
    /// - 命中真实 ARN → 写回 `ctx.credentials.profile_arn` 并由 token_manager 持久化；
    ///   之后该凭据的 `streaming_profile_arn()` 直接命中，不再进入此路径。
    /// - 无 Enterprise profile（纯 BuilderID 等）→ 保持占位符回退逻辑，并标记已尝试，
    ///   避免每次请求重复查询。
    async fn ensure_profile_arn(&self, ctx: &mut crate::kiro::token_manager::CallContext) {
        use crate::kiro::model::credentials::is_placeholder_profile_arn;

        if ctx.credentials.is_api_key_credential() {
            return;
        }
        let needs = match ctx.credentials.profile_arn.as_deref() {
            None => true,
            Some(arn) => is_placeholder_profile_arn(arn),
        };
        if !needs {
            return;
        }
        // 进程内去重：仅在「拿到上游确定结果」后才标记已尝试，避免一次网络抖动
        // 把账号永久卡在占位符上（重启前不再重试）。
        if self.profile_resolution_attempted.lock().contains(&ctx.id) {
            return;
        }
        match self
            .token_manager
            .resolve_profile_arn_for(ctx.id, &ctx.token)
            .await
        {
            Ok(Some(arn)) => {
                ctx.credentials.profile_arn = Some(arn);
                self.profile_resolution_attempted.lock().insert(ctx.id);
            }
            Ok(None) => {
                // 上游确认该账号无 Enterprise profile（纯 BuilderID 等）：标记已尝试，
                // 后续请求回退到占位符逻辑，不再重复查询。
                self.profile_resolution_attempted.lock().insert(ctx.id);
            }
            Err(e) => {
                // 网络/瞬态错误：不标记，下次请求再试；本次按原 profileArn 继续
                tracing::warn!("凭据 #{} 解析真实 profileArn 失败（按原 profileArn 继续）: {}", ctx.id, e);
            }
        }
    }

    /// 发送非流式 API 请求
    ///
    /// 支持多凭据故障转移（见 [`Self::call_api_with_retry`]）。
    /// `sink` 可选，用于逐跳上报链路追踪。
    pub async fn call_api(
        &self,
        request_body: &str,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
        session_key: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        self.call_api_with_retry(request_body, false, sink, group, session_key)
            .await
    }

    /// 发送流式 API 请求
    pub async fn call_api_stream(
        &self,
        request_body: &str,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
        session_key: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        self.call_api_with_retry(request_body, true, sink, group, session_key)
            .await
    }

    /// 发送 MCP API 请求（WebSearch 等工具调用）。
    /// `session_key`：会话亲和锚点——让同一会话的 MCP 搜索与其对话轮黏在同一个号上。
    pub async fn call_mcp(
        &self,
        request_body: &str,
        session_key: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        self.call_mcp_with_retry(request_body, session_key).await
    }

    /// 内部方法：带重试逻辑的 MCP API 调用
    async fn call_mcp_with_retry(
        &self,
        request_body: &str,
        session_key: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut last_local_throttle: Option<LocalThrottleMarker> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();

        for attempt in 0..max_retries {
            // MCP 调用（WebSearch 等工具）不涉及模型选择
            // 但带上 session_key 做会话亲和：同一会话的搜索黏在它的对话号上，避免跨号。
            let ctx = match self.token_manager.acquire_context(None, None, session_key).await {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    // endpoint 解析失败：记为失败，换下一张凭据
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.mcp_url(&rctx);
            let body = endpoint.transform_mcp_body(request_body, &rctx);

            let traceparent = observability::current_traceparent();
            let base = self
                .client_for(&ctx.credentials)?
                .post(&url)
                .body(body.clone())
                .header("content-type", endpoint.content_type())
                .header("Connection", "close");
            let base = if !traceparent.is_empty() {
                base.header("traceparent", traceparent)
            } else {
                base
            };
            let request = endpoint.decorate_mcp(base, &rctx);

            // KIRO_RS_CAPTURE=1 时也抓 MCP/WebSearch 出站包
            if observability::capture_enabled() {
                if let Ok(built) = request.try_clone().map(|r| r.build()).transpose() {
                    if let Some(req) = built {
                        let captured_headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(k, v)| {
                                (
                                    k.as_str().to_string(),
                                    v.to_str().unwrap_or("<binary>").to_string(),
                                )
                            })
                            .collect();
                        observability::capture_outbound(
                            "POST",
                            req.url().as_str(),
                            &captured_headers,
                            &body,
                            "outbound-kiro-mcp",
                        );
                    }
                }
            }

            // ===== 自适应限速发送前闸门（MCP / WebSearch 路径，与 call_api_with_retry 对齐）=====
            let mut limiter_guard = LimiterAttemptGuard::new(self, ctx.id);
            if self.limiters.enabled() {
                let scope = ThrottleScope::UserCredential(ctx.id);
                let limiter = self.limiters.for_scope(&scope);
                let retry_only = self.limiter_enforce_scope == "retry_only";
                let outcome = if retry_only && attempt == 0 {
                    limiter.acquire_shadow()
                } else {
                    limiter.acquire().await
                };
                match outcome {
                    AcquireOutcome::Proceed(permit) => {
                        tracing::info!(
                            event = "kiro_limiter_decision",
                            credential_id = ctx.id,
                            scope = "user",
                            action = "acquire_proceed",
                            current_rate_rps = limiter.current_rate_rps(),
                            attempt = attempt,
                            "limiter 放行 (MCP)"
                        );
                        limiter_guard.set_permit(permit);
                    }
                    AcquireOutcome::ShadowProceed {
                        would_wait_ms,
                        would_rps,
                    } => {
                        tracing::info!(
                            event = "kiro_limiter_decision",
                            credential_id = ctx.id,
                            scope = "user",
                            action = "shadow",
                            would_wait_ms = would_wait_ms,
                            would_rate_rps = would_rps,
                            attempt = attempt,
                            "limiter shadow（MCP，未拦截，仅记录）"
                        );
                    }
                    AcquireOutcome::LocalThrottled {
                        est_wait_ms,
                        current_rps,
                        reason,
                    } => {
                        if reason == "account_open" {
                            tracing::warn!(
                                event = "kiro_limiter_decision",
                                credential_id = ctx.id,
                                scope = "user",
                                action = "account_open_skip",
                                est_wait_ms = est_wait_ms,
                                current_rate_rps = current_rps,
                                reason = reason,
                                attempt = attempt,
                                "account 处于 open 状态，跳过并换号重试 (MCP)"
                            );
                            continue;
                        }
                        Self::handle_local_throttled_absorb(
                            est_wait_ms,
                            current_rps,
                            reason,
                            ctx.id,
                            attempt,
                            "mcp",
                            &mut last_local_throttle,
                        )
                        .await;
                        last_error = None;
                        continue;
                    }
                }
            }

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "MCP 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();

            // 429 响应头采样（读 body 前抓取，与主路径一致）
            if status.as_u16() == 429 {
                let hdrs = response.headers();
                let retry_after = hdrs
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let amz_retry_after = hdrs
                    .get("x-amz-retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let throttle_headers: Vec<String> = hdrs
                    .iter()
                    .filter(|(k, _)| {
                        let k = k.as_str().to_ascii_lowercase();
                        k.contains("retry") || k.contains("ratelimit") || k.starts_with("x-amz")
                    })
                    .map(|(k, v)| format!("{}={}", k.as_str(), v.to_str().unwrap_or("<bin>")))
                    .collect();
                tracing::warn!(
                    cred_id = ctx.id,
                    retry_after = ?retry_after,
                    x_amz_retry_after = ?amz_retry_after,
                    throttle_headers = ?throttle_headers,
                    "AWS 429 响应头采样（MCP，用于确认上游是否返回 Retry-After / 限流头）"
                );
            }

            // 成功响应：读完 body 后 drop permit（MCP 非流式，caller 需要完整 body）
            if status.is_success() {
                self.token_manager.report_success(ctx.id);
                if self.limiters.enabled() {
                    let scope = ThrottleScope::UserCredential(ctx.id);
                    self.limiters
                        .for_scope(&scope)
                        .on_success(self.token_manager.account_rpm(ctx.id))
                        .await;
                    limiter_guard.mark_outcome();
                }
                let headers = response.headers().clone();
                let body = response.text().await.unwrap_or_default();
                let mut builder = http::Response::builder().status(status);
                for (name, value) in headers.iter() {
                    if let Ok(v) = value.to_str() {
                        builder = builder.header(name.as_str(), v);
                    }
                }
                let response = reqwest::Response::from(
                    builder
                        .body(body)
                        .expect("valid MCP response body"),
                );
                return Ok(response);
            }

            // 失败响应
            let body = response.text().await.unwrap_or_default();

            // 限速器 429 回写
            if status.as_u16() == 429 && self.limiters.enabled() {
                let reason = classify_throttle_reason(&body);
                let scope = ThrottleScope::UserCredential(ctx.id);
                self.limiters
                    .for_scope(&scope)
                    .on_throttle(reason, None, self.token_manager.account_rpm(ctx.id))
                    .await;
                limiter_guard.mark_outcome();
                tracing::info!(
                    event = "kiro_limiter_decision",
                    credential_id = ctx.id,
                    scope = "user",
                    action = "on_throttle",
                    throttle_reason = ?reason,
                    upstream_status = 429u16,
                    "limiter 减速回写 (MCP)"
                );
            }

            // 402 额度用尽
            if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 400 Bad Request
            if status.as_u16() == 400 {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 401/403 凭据问题
            if matches!(status.as_u16(), 401 | 403) {
                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if self
                        .token_manager
                        .force_refresh_token_for(ctx.id)
                        .await
                        .is_ok()
                    {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 瞬态错误
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                tracing::warn!(
                    "MCP 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                if attempt + 1 < max_retries {
                    // 429 限流用更长退避；408/5xx 仍用通用快速退避
                    let delay = if status.as_u16() == 429 {
                        Self::retry_delay_throttle(attempt)
                    } else {
                        Self::retry_delay(attempt)
                    };
                    sleep(delay).await;
                }
                continue;
            }

            // 其他 4xx
            if status.is_client_error() {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 兜底
            last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        Err(Self::final_request_error(
            "MCP",
            last_error,
            last_local_throttle,
            max_retries,
        ))
    }

    /// 内部方法：带重试逻辑的 API 调用
    ///
    /// 重试策略：
    /// - 每个凭据最多重试 MAX_RETRIES_PER_CREDENTIAL 次
    /// - 总重试次数 = min(凭据数量 × 每凭据重试次数, MAX_TOTAL_RETRIES)
    /// - 硬上限 9 次，避免无限重试
    async fn call_api_with_retry(
        &self,
        request_body: &str,
        is_stream: bool,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
        session_key: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        // 重试预算按当前请求所属分组的账号数计算，避免小分组按全局账号数获得过多无效重试
        let total_credentials = self.token_manager.total_count_in_group(group).max(1);
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut last_local_throttle: Option<LocalThrottleMarker> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 尝试从请求体中提取模型信息
        let model = Self::extract_model_from_request(request_body);

        for attempt in 0..max_retries {
            let attempt_start = Instant::now();
            // 获取调用上下文（绑定 index、credentials、token）
            let mut ctx = match self
                .token_manager
                .acquire_context(model.as_deref(), group, session_key)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    Self::emit_attempt(
                        sink,
                        attempt,
                        0,
                        "",
                        None,
                        outcome::UNKNOWN,
                        Some(&e.to_string()),
                        attempt_start,
                    );
                    last_error = Some(e);
                    continue;
                }
            };

            // 确保 Enterprise / IdC 账号的真实 profileArn 已解析（流式端点强制要求）
            self.ensure_profile_arn(&mut ctx).await;

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    Self::emit_attempt(
                        sink,
                        attempt,
                        ctx.id,
                        "",
                        None,
                        outcome::UNKNOWN,
                        Some(&e.to_string()),
                        attempt_start,
                    );
                    last_error = Some(e);
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };
            let endpoint_name = endpoint.name();

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.api_url(&rctx);
            let body = endpoint.transform_api_body(request_body, &rctx);

            tracing::debug!("使用端点 [{}] POST {}", endpoint.name(), url);
            tracing::debug!("实际发送请求体: {}", body);

            let traceparent = observability::current_traceparent();
            let base = self
                .client_for(&ctx.credentials)?
                .post(&url)
                .body(body.clone())
                .header("content-type", endpoint.content_type())
                .header("Connection", "close");
            let base = if !traceparent.is_empty() {
                base.header("traceparent", traceparent)
            } else {
                base
            };
            let request = endpoint.decorate_api(base, &rctx);

            // 打印实际发送的请求头（RUST_LOG=debug 时输出，便于排查问题）
            let request = request
                .build()
                .map_err(|e| anyhow::anyhow!("构建请求失败: {}", e))?;
            if tracing::enabled!(tracing::Level::DEBUG) {
                for (k, v) in request.headers() {
                    tracing::debug!("  header {}: {}", k, v.to_str().unwrap_or("<binary>"));
                }
            }

            // KIRO_RS_CAPTURE=1 时把真发包落盘 — 不挂 mitm 也能验证 output_config.effort=max 之类
            if observability::capture_enabled() {
                let captured_headers: Vec<(String, String)> = request
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_string(),
                            v.to_str().unwrap_or("<binary>").to_string(),
                        )
                    })
                    .collect();
                observability::capture_outbound(
                    "POST",
                    request.url().as_str(),
                    &captured_headers,
                    &body,
                    "outbound-kiro-api",
                );
            }

            // ===== 自适应限速发送前闸门（解决 429）=====
            // 每个 attempt（含 retry）发送前都过闸门。灰度：
            //   - enabled=false：完全跳过（行为等同改造前）。
            //   - enforce_scope=retry_only：attempt 0 走 shadow（只记录），attempt>0 真拦。
            //   - enforce_scope=all：所有 attempt 真拦。
            // Proceed 持 permit 到响应结束（随 KiroCallResult drop，见 struct 字段注释）；
            // LocalThrottled 本地失败不发请求。
            let mut limiter_guard = LimiterAttemptGuard::new(self, ctx.id);
            if self.limiters.enabled() {
                let scope = ThrottleScope::UserCredential(ctx.id);
                let limiter = self.limiters.for_scope(&scope);
                let retry_only = self.limiter_enforce_scope == "retry_only";
                let outcome = if retry_only && attempt == 0 {
                    // Phase B：初始请求只观测、不拦截。
                    limiter.acquire_shadow()
                } else {
                    limiter.acquire().await
                };
                match outcome {
                    AcquireOutcome::Proceed(permit) => {
                        tracing::info!(
                            event = "kiro_limiter_decision",
                            credential_id = ctx.id,
                            scope = "user",
                            action = "acquire_proceed",
                            current_rate_rps = limiter.current_rate_rps(),
                            attempt = attempt,
                            "limiter 放行"
                        );
                        limiter_guard.set_permit(permit);
                    }
                    AcquireOutcome::ShadowProceed {
                        would_wait_ms,
                        would_rps,
                    } => {
                        tracing::info!(
                            event = "kiro_limiter_decision",
                            credential_id = ctx.id,
                            scope = "user",
                            action = "shadow",
                            would_wait_ms = would_wait_ms,
                            would_rate_rps = would_rps,
                            attempt = attempt,
                            "limiter shadow（未拦截，仅记录）"
                        );
                    }
                    AcquireOutcome::LocalThrottled {
                        est_wait_ms,
                        current_rps,
                        reason,
                    } => {
                        if reason == "account_open" {
                            tracing::warn!(
                                event = "kiro_limiter_decision",
                                credential_id = ctx.id,
                                scope = "user",
                                action = "account_open_skip",
                                est_wait_ms = est_wait_ms,
                                current_rate_rps = current_rps,
                                reason = reason,
                                attempt = attempt,
                                "account 处于 open 状态，跳过并换号重试"
                            );
                            continue;
                        }
                        Self::handle_local_throttled_absorb(
                            est_wait_ms,
                            current_rps,
                            reason,
                            ctx.id,
                            attempt,
                            "messages",
                            &mut last_local_throttle,
                        )
                        .await;
                        last_error = None;
                        continue;
                    }
                }
            }

            let response = match self.client_for(&ctx.credentials)?.execute(request).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "API 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    Self::emit_attempt(
                        sink,
                        attempt,
                        ctx.id,
                        endpoint_name,
                        None,
                        outcome::NETWORK_ERROR,
                        Some(&e.to_string()),
                        attempt_start,
                    );
                    // 网络错误通常是上游/链路瞬态问题，不应导致"禁用凭据"或"切换凭据"
                    // （否则一段时间网络抖动会把所有凭据都误禁用，需要重启才能恢复）
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();

            // 成功响应
            if status.is_success() {
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::SUCCESS,
                    None,
                    attempt_start,
                );
                self.token_manager.report_success(ctx.id);
                // 限速器成功回写：慢加性增速。
                if self.limiters.enabled() {
                    let scope = ThrottleScope::UserCredential(ctx.id);
                    self.limiters
                        .for_scope(&scope)
                        .on_success(self.token_manager.account_rpm(ctx.id))
                        .await;
                    limiter_guard.mark_outcome();
                }
                // limiter_permit 随 KiroCallResult 交给 handler；非流式在 body 读完后 drop，
                // 流式在 handler 返回时 drop（见 KiroCallResult::limiter_permit 注释）。
                return Ok(KiroCallResult {
                    response,
                    credential_id: ctx.id,
                    limiter_permit: limiter_guard.take_permit_on_success(),
                });
            }

            // 失败响应：读取 body 用于日志/错误信息
            // 采样上游限流响应头（仅 429）：response.text() 会消费 response，
            // headers 之后不可访问，故必须在读 body 之前抓取。
            // 目的：确认 AWS 上游 429 是否返回 Retry-After / x-amz-retry-after / x-ratelimit-*，
            // 为后续自适应限速的「优先信任上游退避时长」决策提供 runtime 证据。零额外请求、零配额。
            if status.as_u16() == 429 {
                let hdrs = response.headers();
                let retry_after = hdrs
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let amz_retry_after = hdrs
                    .get("x-amz-retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let throttle_headers: Vec<String> = hdrs
                    .iter()
                    .filter(|(k, _)| {
                        let k = k.as_str().to_ascii_lowercase();
                        k.contains("retry") || k.contains("ratelimit") || k.starts_with("x-amz")
                    })
                    .map(|(k, v)| format!("{}={}", k.as_str(), v.to_str().unwrap_or("<bin>")))
                    .collect();
                tracing::warn!(
                    cred_id = ctx.id,
                    retry_after = ?retry_after,
                    x_amz_retry_after = ?amz_retry_after,
                    throttle_headers = ?throttle_headers,
                    "AWS 429 响应头采样（用于确认上游是否返回 Retry-After / 限流头）"
                );
            }
            let body = response.text().await.unwrap_or_default();

            // 限速器 429 回写：乘性减速 + 冷却（AWS 实证不返回 Retry-After，故传 None）。
            if status.as_u16() == 429 && self.limiters.enabled() {
                let reason = classify_throttle_reason(&body);
                let scope = ThrottleScope::UserCredential(ctx.id);
                self.limiters
                    .for_scope(&scope)
                    .on_throttle(reason, None, self.token_manager.account_rpm(ctx.id))
                    .await;
                limiter_guard.mark_outcome();
                tracing::info!(
                    event = "kiro_limiter_decision",
                    credential_id = ctx.id,
                    scope = "user",
                    action = "on_throttle",
                    throttle_reason = ?reason,
                    upstream_status = 429u16,
                    "limiter 减速回写"
                );
            }

            // 402 Payment Required 且额度用尽：禁用凭据并故障转移
            if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                tracing::warn!(
                    "API 请求失败（额度已用尽，禁用凭据并切换，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::QUOTA_EXHAUSTED,
                    Some(&body),
                    attempt_start,
                );

                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有凭据已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 400 Bad Request - 请求问题，重试/切换凭据无意义
            if status.as_u16() == 400 {
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(400),
                    outcome::BAD_REQUEST,
                    Some(&body),
                    attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 401/403 - 更可能是凭据/权限问题：计入失败并允许故障转移
            if matches!(status.as_u16(), 401 | 403) {
                tracing::warn!(
                    "API 请求失败（可能为凭据错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::AUTH_FAILED,
                    Some(&body),
                    attempt_start,
                );

                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if self
                        .token_manager
                        .force_refresh_token_for(ctx.id)
                        .await
                        .is_ok()
                    {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有凭据已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 429 + suspicious activity = 账号级临时风控
            // 仅当前凭据被针对，故障转移到其它凭据可立即恢复（受配置开关控制）。
            if status.as_u16() == 429
                && self.token_manager.get_account_throttle_failover()
                && endpoint.is_account_throttled(&body)
            {
                let cooldown_secs = self
                    .token_manager
                    .get_account_throttle_cooldown_secs()
                    .max(1);
                let cooldown = std::time::Duration::from_secs(cooldown_secs);
                tracing::warn!(
                    "API 请求失败（账号级风控，凭据 #{} 冷却 {}s 并切换，尝试 {}/{}）: {}",
                    ctx.id,
                    cooldown_secs,
                    attempt + 1,
                    max_retries,
                    body
                );

                let remaining = self
                    .token_manager
                    .report_account_throttled(ctx.id, cooldown);
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(429),
                    outcome::ACCOUNT_THROTTLED,
                    Some(&body),
                    attempt_start,
                );
                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败（账号级风控，凭据 #{} 已冷却 {} 分钟）: {} {}",
                    api_type,
                    ctx.id,
                    cooldown_secs / 60,
                    status,
                    body
                ));

                if remaining == 0 {
                    anyhow::bail!(
                        "{} API 请求失败：所有凭据都处于账号风控冷却或已禁用状态。\
                         上游对凭据 #{} 的账号触发了 \"suspicious activity\" 临时限速，\
                         建议：(1) 增加更多不同 AWS 账号的凭据；\
                         (2) 在管理面板降低冷却时长或手动解除冷却以重试；\
                         (3) 提交 AWS Support 申诉解封该账号。原始响应: {} {}",
                        api_type,
                        ctx.id,
                        status,
                        body
                    );
                }
                continue;
            }

            // 客户端请求格式错误（messages 数组违反协议）：根因在调用方，重试无意义
            // 上游常以 5xx 返回，必须在下方"瞬态错误重试"分支之前拦截，否则会被当作
            // 上游故障重试 max_retries 次，把一个坏请求放大成多次 503（503 风暴）。
            // 直接终止：不重试、不切换凭据、不计入凭据失败。
            if endpoint.is_client_validation_error(&body) {
                tracing::warn!(
                    "API 请求失败（客户端请求格式错误，不重试）: {} {}",
                    status,
                    body
                );
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::BAD_REQUEST,
                    Some(&body),
                    attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 524 / gateway timeout：上游边缘层超时，继续在本次请求内重试通常只会
            // 放大客户端等待时间和 Claude 端 Retrying 轮数；快速返回，让客户端下一次调用
            // 重新建连。
            if status.as_u16() == 524 || endpoint.is_gateway_timeout(&body) {
                tracing::warn!("API 请求失败（上游网关超时，不重试）: {} {}", status, body);
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::TRANSIENT,
                    Some(&body),
                    attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 429/408/5xx - 瞬态上游错误：重试但不禁用或切换凭据
            // （避免 429 high traffic / 502 high load 等瞬态错误把所有凭据锁死）
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                tracing::warn!(
                    "API 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::TRANSIENT,
                    Some(&body),
                    attempt_start,
                );
                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                if attempt + 1 < max_retries {
                    // 429 限流用更长退避给账号配额恢复时间；408/5xx 仍用通用快速退避
                    let delay = if status.as_u16() == 429 {
                        Self::retry_delay_throttle(attempt)
                    } else {
                        Self::retry_delay(attempt)
                    };
                    sleep(delay).await;
                }
                continue;
            }

            // 其他 4xx - 通常为请求/配置问题：直接返回，不计入凭据失败
            if status.is_client_error() {
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::BAD_REQUEST,
                    Some(&body),
                    attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 兜底：当作可重试的瞬态错误处理（不切换凭据）
            tracing::warn!(
                "API 请求失败（未知错误，尝试 {}/{}）: {} {}",
                attempt + 1,
                max_retries,
                status,
                body
            );
            Self::emit_attempt(
                sink,
                attempt,
                ctx.id,
                endpoint_name,
                Some(status.as_u16()),
                outcome::UNKNOWN,
                Some(&body),
                attempt_start,
            );
            last_error = Some(anyhow::anyhow!(
                "{} API 请求失败: {} {}",
                api_type,
                status,
                body
            ));
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        // 所有重试都失败
        Err(Self::final_request_error(
            api_type,
            last_error,
            last_local_throttle,
            max_retries,
        ))
    }

    /// 向 trace sink 上报一跳结果（sink 为 None 时无开销）
    #[allow(clippy::too_many_arguments)]
    fn emit_attempt(
        sink: Option<&dyn TraceSink>,
        attempt: usize,
        credential_id: u64,
        endpoint: &str,
        http_status: Option<u16>,
        outcome: &str,
        error_body: Option<&str>,
        started: Instant,
    ) {
        let Some(sink) = sink else { return };
        sink.on_attempt(TraceAttempt {
            attempt: attempt as u32,
            credential_id,
            endpoint: endpoint.to_string(),
            http_status,
            outcome: outcome.to_string(),
            error_snippet: error_body.and_then(truncate_snippet),
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    /// 从请求体中提取模型信息
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.currentMessage.userInputMessage.modelId
    fn extract_model_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        json.get("conversationState")?
            .get("currentMessage")?
            .get("userInputMessage")?
            .get("modelId")?
            .as_str()
            .map(|s| s.to_string())
    }

    fn retry_delay(attempt: usize) -> Duration {
        // 指数退避 + 少量抖动，避免上游抖动时放大故障
        const BASE_MS: u64 = 200;
        const MAX_MS: u64 = 2_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }

    /// Absorb-First：本地 limiter 排队在 provider 内消化；limiter 已等到 absorb_timeout 时不再叠睡。
    async fn handle_local_throttled_absorb(
        est_wait_ms: u64,
        current_rps: f64,
        reason: &str,
        credential_id: u64,
        attempt: usize,
        path: &str,
        marker: &mut Option<LocalThrottleMarker>,
    ) {
        *marker = Some(LocalThrottleMarker {
            reason: match reason {
                "upstream_throttle_storm" => "upstream_throttle_storm",
                "absorb_timeout" => "absorb_timeout",
                _ => "local_queue_timeout",
            },
            est_wait_ms,
            current_rps,
        });
        if reason == "absorb_timeout" || reason == "upstream_throttle_storm" {
            tracing::info!(
                event = "kiro_limiter_decision",
                credential_id = credential_id,
                scope = "user",
                action = "absorb_exhaust_retry",
                est_wait_ms = est_wait_ms,
                current_rate_rps = current_rps,
                reason = reason,
                attempt = attempt,
                path = path,
                "limiter 已吸满 max_absorb_wait，换 attempt 重试（不叠睡）"
            );
            return;
        }
        Self::absorb_local_throttle_wait(
            est_wait_ms,
            current_rps,
            reason,
            credential_id,
            attempt,
            path,
        )
        .await;
    }

    fn local_throttle_exhaust_error(
        api_type: &str,
        marker: Option<LocalThrottleMarker>,
        max_retries: usize,
    ) -> anyhow::Error {
        if let Some(lt) = marker {
            anyhow::anyhow!(
                "{} 本地限流（吸收超时）: kiro_local_throttled reason={} est_wait_ms={} rate_rps={:.3}",
                api_type,
                lt.reason,
                lt.est_wait_ms,
                lt.current_rps
            )
        } else {
            anyhow::anyhow!(
                "{} API 请求失败：已达到最大重试次数（{}次）",
                api_type,
                max_retries
            )
        }
    }

    fn final_request_error(
        api_type: &str,
        last_error: Option<anyhow::Error>,
        last_local_throttle: Option<LocalThrottleMarker>,
        max_retries: usize,
    ) -> anyhow::Error {
        if let Some(marker) = last_local_throttle {
            return Self::local_throttle_exhaust_error(api_type, Some(marker), max_retries);
        }
        last_error.unwrap_or_else(|| {
            Self::local_throttle_exhaust_error(api_type, None, max_retries)
        })
    }

    async fn absorb_local_throttle_wait(
        est_wait_ms: u64,
        current_rps: f64,
        reason: &str,
        credential_id: u64,
        attempt: usize,
        path: &str,
    ) {
        let wait = Duration::from_millis(est_wait_ms.clamp(50, 15_000));
        tracing::info!(
            event = "kiro_limiter_decision",
            credential_id = credential_id,
            scope = "user",
            action = "absorb_wait",
            est_wait_ms = est_wait_ms,
            current_rate_rps = current_rps,
            reason = reason,
            attempt = attempt,
            path = path,
            "limiter 本地排队吸收（不向 CPA/Codex 吐 429）"
        );
        sleep(wait).await;
    }

    fn retry_delay_throttle(attempt: usize) -> Duration {
        const BASE_MS: u64 = 1_000;
        const MAX_MS: u64 = 8_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }
}

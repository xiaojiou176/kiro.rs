//! Anthropic API 中间件

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use parking_lot::RwLock;
use tracing::Instrument;
use uuid::Uuid;

use crate::admin::client_keys::SharedClientKeyManager;
use crate::admin::usage_stats::{SharedAggregator, SharedRecorder};
use crate::admin::trace_db::SharedTraceStore;
use crate::common::auth;
use crate::kiro::provider::KiroProvider;
use crate::observability;

use super::prompt_cache::SharedPromptCache;
use super::types::ErrorResponse;

/// 命中的鉴权上下文（注入到请求扩展，供 handler 记录用量）
#[derive(Clone, Copy, Debug)]
pub struct KeyContext {
    /// 命中的客户端 Key id；0 表示用 master apiKey 调用
    pub key_id: u64,
}

/// 应用共享状态
#[derive(Clone)]
pub struct AppState {
    /// API 密钥（运行时可修改，与 Admin 持久化共享）
    pub api_key: Arc<RwLock<String>>,
    /// Kiro Provider（可选，用于实际 API 调用）
    /// 内部使用 MultiTokenManager，已支持线程安全的多凭据管理
    pub kiro_provider: Option<Arc<KiroProvider>>,
    /// 是否开启非流式响应的 thinking 块提取
    pub extract_thinking: bool,
    /// 客户端 Key 管理器（可选，未启用 Admin 时为 None）
    pub client_keys: Option<SharedClientKeyManager>,
    /// 用量日志记录器
    pub usage_recorder: Option<SharedRecorder>,
    /// 用量聚合器
    pub usage_aggregator: Option<SharedAggregator>,
    /// 中转层 prompt cache（基于 cache_control 断点的内存缓存）
    pub prompt_cache: Option<SharedPromptCache>,
    /// 请求链路追踪存储（SQLite，可选）
    pub trace_store: Option<SharedTraceStore>,
}

impl AppState {
    /// 创建新的应用状态
    ///
    /// 默认入口通过 `with_provider` 注入 `KiroProvider`；这个简化构造函数留给
    /// 下游 lib 用户使用（e.g. 测试、嵌入到其他服务时）。
    #[allow(dead_code)]
    pub fn new(api_key: impl Into<String>, extract_thinking: bool) -> Self {
        Self {
            api_key: Arc::new(RwLock::new(api_key.into())),
            kiro_provider: None,
            extract_thinking,
            client_keys: None,
            usage_recorder: None,
            usage_aggregator: None,
            prompt_cache: None,
            trace_store: None,
        }
    }

    /// 使用现有 Arc 共享 api_key（用于与 Admin 模块共享同一份内存）
    pub fn with_shared_api_key(api_key: Arc<RwLock<String>>, extract_thinking: bool) -> Self {
        Self {
            api_key,
            kiro_provider: None,
            extract_thinking,
            client_keys: None,
            usage_recorder: None,
            usage_aggregator: None,
            prompt_cache: None,
            trace_store: None,
        }
    }

    /// 设置 KiroProvider
    pub fn with_kiro_provider(mut self, provider: KiroProvider) -> Self {
        self.kiro_provider = Some(Arc::new(provider));
        self
    }

    /// 注入用量记录组件
    pub fn with_usage(
        mut self,
        client_keys: Option<SharedClientKeyManager>,
        recorder: Option<SharedRecorder>,
        aggregator: Option<SharedAggregator>,
    ) -> Self {
        self.client_keys = client_keys;
        self.usage_recorder = recorder;
        self.usage_aggregator = aggregator;
        self
    }

    /// 注入 PromptCache
    pub fn with_prompt_cache(mut self, cache: Option<SharedPromptCache>) -> Self {
        self.prompt_cache = cache;
        self
    }

    /// 注入链路追踪存储
    pub fn with_trace_store(mut self, store: Option<SharedTraceStore>) -> Self {
        self.trace_store = store;
        self
    }
}

/// API Key 认证中间件
///
/// 鉴权顺序：master apiKey → 客户端 Key（`csk_*`）。命中后向请求扩展注入
/// [`KeyContext`]，供 handler 记录用量时使用。
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let presented = match auth::extract_api_key(&request) {
        Some(k) => k,
        None => {
            let error = ErrorResponse::authentication_error();
            return (StatusCode::UNAUTHORIZED, Json(error)).into_response();
        }
    };

    // 1) master apiKey
    let master = state.api_key.read().clone();
    if auth::constant_time_eq(&presented, &master) {
        request.extensions_mut().insert(KeyContext { key_id: 0 });
        return next.run(request).await;
    }

    // 2) 客户端 Key
    if let Some(mgr) = &state.client_keys {
        if let Some(id) = mgr.verify_and_touch(&presented) {
            request.extensions_mut().insert(KeyContext { key_id: id });
            return next.run(request).await;
        }
    }

    let error = ErrorResponse::authentication_error();
    (StatusCode::UNAUTHORIZED, Json(error)).into_response()
}

/// Per-request observability middleware.
///
/// For every inbound HTTP request:
/// 1. Reads `x-request-id` from the client; if absent, mints a fresh UUIDv4.
/// 2. Reads `traceparent` (W3C trace-context); if absent or malformed, mints a
///    new 32-hex `trace_id`. Either way, generates a fresh per-hop `span_id`.
/// 3. Stuffs both into the tokio task-local scope so any downstream `async fn`
///    can call `observability::current_request_id()` / `current_traceparent()`
///    without threading them through every signature.
/// 4. Wraps the rest of the request in a `tracing::info_span!` carrying
///    `request_id` and `trace_id`, so every structured-JSON log line under
///    this span auto-includes them — no manual `request_id=%rid` per log call.
/// 5. Echoes `x-request-id` and `traceparent` back to the client so callers
///    (or upstream proxies like CPA / Codex) can correlate.
pub async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let incoming_traceparent = request
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let inherited_trace_id = incoming_traceparent
        .as_deref()
        .and_then(observability::extract_trace_id);
    let traceparent =
        observability::generate_traceparent(inherited_trace_id.as_deref());
    let trace_id = observability::extract_trace_id(&traceparent).unwrap_or_default();

    // Inject the upstream-facing traceparent into the request so downstream
    // code (provider, http_client) can read it via header-stripping if needed.
    if let Ok(tp_val) = HeaderValue::from_str(&traceparent) {
        request.headers_mut().insert("traceparent", tp_val);
    }
    if let Ok(rid_val) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert("x-request-id", rid_val);
    }

    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        trace_id = %trace_id,
        method = %method,
        path = %path,
    );

    let response_request_id = request_id.clone();
    let response_traceparent = traceparent.clone();

    let mut response = observability::REQUEST_ID
        .scope(request_id, async move {
            observability::TRACE_PARENT
                .scope(traceparent, async move { next.run(request).await })
                .await
        })
        .instrument(span)
        .await;

    if let Ok(v) = HeaderValue::from_str(&response_request_id) {
        response.headers_mut().insert("x-request-id", v);
    }
    if let Ok(v) = HeaderValue::from_str(&response_traceparent) {
        response.headers_mut().insert("traceparent", v);
    }
    response
}

/// CORS 中间件层
///
/// **安全说明**：当前配置允许所有来源（Any），这是为了支持公开 API 服务。
/// 如果需要更严格的安全控制，请根据实际需求配置具体的允许来源、方法和头信息。
///
/// # 配置说明
/// - `allow_origin(Any)`: 允许任何来源的请求
/// - `allow_methods(Any)`: 允许任何 HTTP 方法
/// - `allow_headers(Any)`: 允许任何请求头
pub fn cors_layer() -> tower_http::cors::CorsLayer {
    use tower_http::cors::{Any, CorsLayer};

    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}

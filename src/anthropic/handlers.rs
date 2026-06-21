//! Anthropic API Handler 函数

use std::convert::Infallible;
use std::time::Instant;

use crate::admin::client_keys::SharedClientKeyManager;
use crate::admin::usage_stats::{SharedAggregator, SharedRecorder, UsageRecord};
use crate::admin::trace_db::{
    SharedTraceStore, TraceAttempt, TraceKeySource, TraceRecord, TraceSink, outcome,
};
use crate::kiro::model::events::Event;
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::token;
use anyhow::Error;
use axum::{
    Json as JsonExtractor,
    body::Body,
    extract::{Extension, State},
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use chrono::Utc;
use futures::{Stream, StreamExt, stream};
use serde_json::json;
use std::time::Duration;
use tokio::time::interval;
use uuid::Uuid;

use super::converter::{ConversionError, convert_request};
use super::middleware::{AppState, KeyContext};
use super::stream::{BufferedStreamContext, SseEvent, StreamContext};
use super::types::{
    CountTokensRequest, CountTokensResponse, ErrorResponse, MessagesRequest, Model, ModelsResponse,
    OutputConfig, Thinking,
};
use super::websearch;

/// 请求结束时记录用量的钩子
///
/// 在 handler 入口构造，调用 [`Self::record`] 时把当次请求的 input/output token、
/// 命中的上游凭据 ID、状态写入：
/// - `usage_log.YYYY-MM-DD.jsonl`（持久化历史）
/// - 内存聚合器（仪表盘趋势）
/// - 客户端 Key 计数（按 Key 累计）
#[derive(Clone)]
pub(crate) struct UsageRecordHook {
    pub recorder: Option<SharedRecorder>,
    pub aggregator: Option<SharedAggregator>,
    pub client_keys: Option<SharedClientKeyManager>,
    pub key_id: u64,
    pub model: String,
    pub started_at: Instant,
}

impl UsageRecordHook {
    pub fn from_state(state: &AppState, key_id: u64, model: String) -> Self {
        Self {
            recorder: state.usage_recorder.clone(),
            aggregator: state.usage_aggregator.clone(),
            client_keys: state.client_keys.clone(),
            key_id,
            model,
            started_at: Instant::now(),
        }
    }

    pub fn record(
        &self,
        credential_id: u64,
        input_tokens: i32,
        output_tokens: i32,
        cache_creation_tokens: i32,
        cache_read_tokens: i32,
        credits: f64,
        status: &str,
    ) {
        let rec = UsageRecord {
            ts: Utc::now().to_rfc3339(),
            key_id: self.key_id,
            credential_id,
            model: self.model.clone(),
            input_tokens: input_tokens.max(0) as u64,
            output_tokens: output_tokens.max(0) as u64,
            cache_creation_tokens: cache_creation_tokens.max(0) as u64,
            cache_read_tokens: cache_read_tokens.max(0) as u64,
            credits: if credits.is_finite() && credits > 0.0 {
                credits
            } else {
                0.0
            },
            duration_ms: self.started_at.elapsed().as_millis() as u64,
            status: status.to_string(),
        };
        if let Some(r) = &self.recorder {
            r.record(&rec);
        }
        if let Some(a) = &self.aggregator {
            a.ingest(&rec);
        }
        if status == "success" && self.key_id != 0 {
            if let Some(m) = &self.client_keys {
                m.record_usage(
                    self.key_id,
                    rec.input_tokens,
                    rec.output_tokens,
                    rec.cache_creation_tokens,
                    rec.cache_read_tokens,
                    rec.credits,
                );
            }
        }
    }
}

/// 单次请求的链路追踪器
///
/// 在 handler 入口构造，作为 [`TraceSink`] 传入 provider；provider 在重试循环里
/// 每跳调用 [`on_attempt`](TraceSink::on_attempt) 累积一条 [`TraceAttempt`]。
/// 请求结束时调用 [`Self::finalize`] 组装 [`TraceRecord`] 并写入 SQLite。
///
/// `store` 为 None（未启用 Admin / trace）时所有方法都是空操作，零开销。
pub(crate) struct RequestTracer {
    store: Option<SharedTraceStore>,
    trace_id: String,
    ts: String,
    key_id: u64,
    key_source: TraceKeySource,
    model: String,
    is_stream: bool,
    conversation_id: Option<String>,
    /// 客户端请求的 effort 档位（映射前原值，可空）
    effort_requested: Option<String>,
    /// 实际发往上游的 effort 档位（映射后值，可空）
    effort_sent: Option<String>,
    started_at: Instant,
    /// 首个上游 chunk 到达时刻（仅流式标记；取第一次）
    first_token_at: parking_lot::Mutex<Option<Instant>>,
    attempts: parking_lot::Mutex<Vec<TraceAttempt>>,
}

/// 本次请求的用量快照（落入 trace 行，与 usage_log 同源）
#[derive(Clone, Default)]
pub(crate) struct TraceUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_tokens: u64,
    pub cache_read_tokens: u64,
    pub credits: f64,
    /// 思考 token（单独计数，不从 output_tokens 扣除）
    pub reasoning_tokens: u64,
}

impl TraceUsage {
    /// 错误早退等无用量场景
    pub fn zero() -> Self {
        Self::default()
    }
}

struct RequestTraceOptions {
    key_ctx: KeyContext,
    model: String,
    is_stream: bool,
    conversation_id: Option<String>,
    effort_requested: Option<String>,
    effort_sent: Option<String>,
}

impl RequestTracer {
    fn new(state: &AppState, options: RequestTraceOptions) -> Self {
        Self {
            store: state.trace_store.clone(),
            trace_id: Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            key_id: options.key_ctx.key_id,
            key_source: options.key_ctx.key_source,
            model: options.model,
            is_stream: options.is_stream,
            conversation_id: options.conversation_id,
            effort_requested: options.effort_requested,
            effort_sent: options.effort_sent,
            started_at: Instant::now(),
            first_token_at: parking_lot::Mutex::new(None),
            attempts: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// web_search agentic-loop 专用构造：该路径绕过普通 chat 的 tracer 装配，
    /// 这里用与普通路径同口径的 effort 快照 + conversation_id（Codex thread id），
    /// 保证 web_search 请求也落 traces.db（修复 2026-06-21：此前该路径完全不写 trace，
    /// 导致带 web_search 的请求在 traces.db 查无记录）。
    pub(crate) fn for_web_search(
        state: &AppState,
        key_ctx: &KeyContext,
        payload: &MessagesRequest,
    ) -> Self {
        let (effort_requested, effort_sent) = trace_efforts(payload, &payload.model);
        let conversation_id = super::converter::extract_affinity_session_id(payload);
        Self::new(
            state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: payload.stream,
                conversation_id,
                effort_requested,
                effort_sent,
            },
        )
    }

    /// 标记首个上游 chunk 到达（幂等，仅记录第一次）
    pub fn mark_first_token(&self) {
        let mut slot = self.first_token_at.lock();
        if slot.is_none() {
            *slot = Some(Instant::now());
        }
    }

    /// 组装并落库一条完整链路。store 为 None 时不做任何事。
    pub fn finalize(
        &self,
        final_status: &str,
        error_type: Option<&str>,
        error_message: Option<&str>,
        interrupted_after_bytes: Option<u64>,
        usage: TraceUsage,
    ) {
        let Some(store) = &self.store else { return };
        let attempts = std::mem::take(&mut *self.attempts.lock());
        // 最终凭据：最后一跳的命中凭据（成功跳即命中凭据，失败跳即最后尝试的凭据）
        let final_credential_id = attempts.last().map(|a| a.credential_id).unwrap_or(0);
        let first_token_ms = self
            .first_token_at
            .lock()
            .map(|t| t.duration_since(self.started_at).as_millis() as u64);
        let rec = TraceRecord {
            trace_id: self.trace_id.clone(),
            ts: self.ts.clone(),
            key_id: self.key_id,
            key_source: self.key_source,
            model: self.model.clone(),
            is_stream: self.is_stream,
            final_status: final_status.to_string(),
            final_credential_id,
            error_type: error_type.map(|s| s.to_string()),
            error_message: error_message.map(|s| s.to_string()),
            total_attempts: attempts.len() as u32,
            duration_ms: self.started_at.elapsed().as_millis() as u64,
            interrupted_after_bytes,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            credits: usage.credits,
            reasoning_tokens: usage.reasoning_tokens,
            effort_requested: self.effort_requested.clone(),
            effort_sent: self.effort_sent.clone(),
            first_token_ms,
            conversation_id: self.conversation_id.clone(),
            attempts,
        };
        store.insert(&rec);
    }
}

impl TraceSink for RequestTracer {
    fn on_attempt(&self, attempt: TraceAttempt) {
        self.attempts.lock().push(attempt);
    }
}

/// 把客户端请求的 effort 档位映射为实际发往上游的值（trace 记录用）。
///
/// 与 converter 的请求→上游映射保持一致：顶档 `xhigh` → Kiro 线值 `max`，
/// trace 侧"实际发往上游的 effort 档位"——直接复用 converter 的单一真相源
/// `map_effort_to_wire`，保证 trace 记录值与真实出站值永不漂移（修复 2026-06-20：
/// 旧本地副本漏了 low/medium→high clamp，导致出站已 clamp 成 high、trace 却虚记 low/medium，
/// 污染降智埋点）。
fn trace_effort_sent(effort: &str) -> String {
    crate::anthropic::converter::map_effort_to_wire(effort)
}

/// 从客户端请求里取出 trace 用的 (effort_requested, effort_sent)。
///
/// `effort_requested` = 客户端 `output_config.effort`（去空白后非空才记，否则 None）。
/// `effort_sent` = 我们**实际会发往上游的** effort 档位。只有当上游真的会收到
/// `output_config.effort`（即 converter 的发送门控放行该模型）时，才记映射后的值；
/// 否则（output_config 被 converter skip 掉，上游根本收不到 effort 覆盖）记 None，
/// 绝不虚标一个并未下发的 `max`，以免 downgrade 检测被假信号污染。
///
/// trace 侧「effort 实际是否发往上游」的判定，直接复用 converter 的**单一真相源**
/// `should_emit_output_config`，避免 trace 副本与真实发送逻辑漂移（Task 2 根治：
/// effort 门改为「上游真实存在即放行」的动态判定后，旧的硬编码 4.6/4.8 副本会误判，
/// 例如 opus-4.7 实际会发 effort 但旧副本记 None、污染降智检测）。
///
/// `model_id` 必须是 **已映射** 的上游模型 ID（与 converter 门控同口径）：调用方先用
/// `converter::map_model` 把客户端别名（如 `claude-opus-4-8` / `…-thinking`）归一到
/// `claude-opus-4.8` 再传入，否则会与 converter 的点号形态错配、误判主模型。
fn trace_effort_sent_emitted(payload: &MessagesRequest, mapped_model_id: &str) -> bool {
    crate::anthropic::converter::should_emit_output_config(payload, mapped_model_id)
}

fn trace_efforts(payload: &MessagesRequest, model_id: &str) -> (Option<String>, Option<String>) {
    let requested = payload
        .output_config
        .as_ref()
        .map(|c| c.effort.trim())
        .filter(|e| !e.is_empty())
        .map(|e| e.to_string());
    // 与 converter 同口径：先把客户端模型别名映射成上游模型 ID 再做门控判断。
    // 映射失败（未知模型）时按"不发 output_config"处理，sent 记 None。
    let mapped = super::converter::map_model(model_id);
    let emitted = mapped
        .as_deref()
        .is_some_and(|m| trace_effort_sent_emitted(payload, m));
    // effort_sent 只在上游真会收到 output_config 时才有值，且为映射后的线值。
    let sent = if emitted {
        requested.as_deref().map(trace_effort_sent)
    } else {
        None
    };
    (requested, sent)
}

/// 取追踪器里最后一跳的 outcome（用于把 provider 的失败分类提升到 record.error_type）。
/// 返回 'static str（outcome 常量），无 attempt 时返回 None。
fn last_attempt_outcome(tracer: &RequestTracer) -> Option<&'static str> {
    let last = tracer.attempts.lock().last()?.outcome.clone();
    Some(match last.as_str() {
        outcome::QUOTA_EXHAUSTED => outcome::QUOTA_EXHAUSTED,
        outcome::ACCOUNT_THROTTLED => outcome::ACCOUNT_THROTTLED,
        outcome::AUTH_FAILED => outcome::AUTH_FAILED,
        outcome::TRANSIENT => outcome::TRANSIENT,
        outcome::NETWORK_ERROR => outcome::NETWORK_ERROR,
        outcome::BAD_REQUEST => outcome::BAD_REQUEST,
        _ => outcome::UNKNOWN,
    })
}

/// Image-budget warning threshold (in raw base64 chars, not decoded bytes).
/// Emits a warning when the total base64 char count of all image content in one request exceeds this threshold.
/// The threshold does not reject the request (the upstream makes the final call); it only gives operators more precise diagnostics.
const IMAGE_BUDGET_WARN_BYTES: usize = 800 * 1024;

/// Budget statistics for the image content in one inbound request.
struct ImageBudget {
    count: usize,
    total_b64_bytes: usize,
    largest_b64_bytes: usize,
}

/// Counts the total number of images in the payload and their base64 byte size.
/// Looks only at inline base64 (image source.type == "base64"), skipping url-mode images (which do not
/// go directly into a Bedrock single message body). This is a lightweight O(N) scan that does not decode base64.
fn count_image_budget(payload: &super::types::MessagesRequest) -> ImageBudget {
    let mut count = 0usize;
    let mut total = 0usize;
    let mut largest = 0usize;
    for msg in &payload.messages {
        if let serde_json::Value::Array(arr) = &msg.content {
            for item in arr {
                if item.get("type").and_then(|v| v.as_str()) != Some("image") {
                    continue;
                }
                let Some(src) = item.get("source") else { continue };
                if src.get("type").and_then(|v| v.as_str()) != Some("base64") {
                    continue;
                }
                let n = src.get("data").and_then(|v| v.as_str()).map(|s| s.len()).unwrap_or(0);
                count += 1;
                total += n;
                if n > largest {
                    largest = n;
                }
            }
        }
    }
    ImageBudget {
        count,
        total_b64_bytes: total,
        largest_b64_bytes: largest,
    }
}

/// 将 KiroProvider 错误映射为 HTTP 响应
pub(super) fn map_provider_error(err: Error) -> Response {
    let err_str = err.to_string();

    // 上下文窗口满了（对话历史累积超出模型上下文窗口限制）
    if err_str.contains("CONTENT_LENGTH_EXCEEDS_THRESHOLD") {
        tracing::warn!(error = %err, "上游拒绝请求：上下文窗口已满（不应重试）");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Context window is full. Reduce conversation history, system prompt, or tools.",
            )),
        )
            .into_response();
    }

    // 单次输入太长（请求体本身超出上游限制）
    if err_str.contains("Input is too long") {
        tracing::warn!(error = %err, "上游拒绝请求：输入过长（不应重试）");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Input is too long. Reduce the size of your messages.",
            )),
        )
            .into_response();
    }

    // Bedrock client-side validation errors (tool_use <-> tool_result mismatch, invalid message sequence, etc.)
    // The root cause is the client's own messages array, not an upstream failure, so it must not map to 5xx
    // otherwise it triggers an upstream cooldown that amplifies one client error into a 30+ burst of 503s.
    // Detection is centralized in the endpoint layer (single source of truth for the markers); the provider
    // already bails out without retry on these, and this mapping is the client-facing safety net.
    if crate::kiro::endpoint::default_is_client_validation_error(&err_str) {
        tracing::warn!(
            error = %err,
            "client messages array violates the protocol (Bedrock validation; mapped to 400 to avoid a false cooldown)"
        );
        // Return a stable, client-facing message and avoid echoing the raw upstream
        // error string (which can carry request IDs or internal validation details).
        // The full error is already logged above for diagnostics.
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Invalid message sequence: tool_use and tool_result blocks must be correctly paired and ordered.".to_string(),
            )),
        )
            .into_response();
    }

    // Fail Aloud（历史）：本地 adaptive limiter 主动拒绝。
    // Absorb-First 后 provider 不再 bail kiro_local_throttled；此分支仅兜底上游路径残留。
    // 形如：kiro_local_throttled reason=absorb_timeout est_wait_ms=95000 rate_rps=0.100
    if err_str.contains("kiro_local_throttled") {
        let parse_kv = |key: &str| -> Option<String> {
            err_str
                .split_whitespace()
                .find_map(|tok| tok.strip_prefix(key).map(|v| v.to_string()))
        };
        let reason = parse_kv("reason=").unwrap_or_else(|| "local_queue_timeout".to_string());
        let est_wait_ms: u64 = parse_kv("est_wait_ms=")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let rate_rps = parse_kv("rate_rps=").unwrap_or_else(|| "0".to_string());
        let retry_after_secs = est_wait_ms.div_ceil(1000).max(1);
        tracing::warn!(
            error = %err,
            "Fail Aloud：本地限流，返回 429（不是上游故障）"
        );
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse::new(
                "rate_limit_error",
                "Locally throttled by adaptive rate limiter; reduce concurrency and retry."
                    .to_string(),
            )),
        )
            .into_response();
        let h = resp.headers_mut();
        if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
            h.insert(axum::http::header::RETRY_AFTER, v);
        }
        h.insert(
            "x-local-throttled",
            axum::http::HeaderValue::from_static("true"),
        );
        if let Ok(v) = axum::http::HeaderValue::from_str(&rate_rps) {
            h.insert("x-kiro-limiter-rate", v);
        }
        if let Ok(v) = axum::http::HeaderValue::from_str(&reason) {
            h.insert("x-kiro-limiter-reason", v);
        }
        return resp;
    }

    // Pure upstream rate limiting (ThrottlingException / SERVICE_REQUEST_RATE_EXCEEDED):
    // the request was simply too fast; the account quota is NOT exhausted and a short
    // backoff will succeed. If this falls through to the 502 bottom default, CPA treats
    // it as an upstream service failure and cools the claude credential down for 60s;
    // with a single active credential that turns one rate-limit into a 60s burst of 503
    // (auth_unavailable). Mapping it to 429 makes CPA take the quota-backoff path (base
    // 1s, far below 60s) and is semantically honest (it really is rate limiting, not a
    // client-side 400). A Retry-After hint lets CPA size the backoff precisely.
    if crate::kiro::endpoint::default_is_rate_limited(&err_str) {
        tracing::warn!(
            error = %err,
            "upstream rate limited (throttling; mapped to 429 to avoid a 60s false cooldown)"
        );
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse::new(
                "rate_limit_error",
                "Upstream is rate limiting requests; retry after a short delay.".to_string(),
            )),
        )
            .into_response();
        // Conservative retry hint; CPA reads Retry-After to size its backoff.
        if let Ok(value) = axum::http::HeaderValue::from_str("1") {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        return resp;
    }

    tracing::error!("Kiro API 调用失败: {}", err);
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse::new(
            "api_error",
            format!("上游 API 调用失败: {}", err),
        )),
    )
        .into_response()
}

/// 计算 Anthropic usage 口径的 input_tokens
fn resolve_usage_input_tokens(
    fallback_total_input_tokens: i32,
    context_total_input_tokens: Option<i32>,
) -> i32 {
    context_total_input_tokens.unwrap_or(fallback_total_input_tokens)
}

/// 裸模型目录（id / display / created / max_tokens）。
///
/// Task 4 根治：只列 **裸模型**，零 `*-thinking` 虚标变体——上游 AWS 没有任何 `-thinking`
/// 模型 ID，thinking 深度由 `output_config.effort` 驱动、服务端自动决定。
///
/// 每条带一个 `upstream_id`（点号形态，对齐 `map_model` 输出 + 上游 `ListAvailableModels`），
/// 用于与上游真实清单做交集过滤。
struct BareModelDef {
    /// 对外暴露的模型 ID（dash 形态，Codex/客户端可见）
    exposed_id: &'static str,
    /// 与上游对齐的归一化 ID（dot 形态 = `map_model` 输出 / 上游 model_id）
    upstream_id: &'static str,
    display_name: &'static str,
    created: i64,
}

/// 裸模型目录。冷启动（上游缓存未热）时直接用它；热启动时与上游真实清单取交集。
/// 顺序即对外列表顺序（高端在前）。
const BARE_MODEL_CATALOG: &[BareModelDef] = &[
    BareModelDef {
        exposed_id: "claude-opus-4-8",
        upstream_id: "claude-opus-4.8",
        display_name: "Claude Opus 4.8",
        created: 1779897600, // May 28, 2026
    },
    BareModelDef {
        exposed_id: "claude-opus-4-7",
        upstream_id: "claude-opus-4.7",
        display_name: "Claude Opus 4.7",
        created: 1776276000, // Apr 16, 2026
    },
    BareModelDef {
        exposed_id: "claude-opus-4-6",
        upstream_id: "claude-opus-4.6",
        display_name: "Claude Opus 4.6",
        created: 1770163200, // Feb 4, 2026
    },
    BareModelDef {
        exposed_id: "claude-sonnet-4-6",
        upstream_id: "claude-sonnet-4.6",
        display_name: "Claude Sonnet 4.6",
        created: 1771286400, // Feb 17, 2026
    },
    BareModelDef {
        exposed_id: "claude-opus-4-5-20251101",
        upstream_id: "claude-opus-4.5",
        display_name: "Claude Opus 4.5",
        created: 1763942400, // Nov 24, 2025
    },
    BareModelDef {
        exposed_id: "claude-sonnet-4-5-20250929",
        upstream_id: "claude-sonnet-4.5",
        display_name: "Claude Sonnet 4.5",
        created: 1759104000, // Sep 29, 2025
    },
    BareModelDef {
        exposed_id: "claude-haiku-4-5-20251001",
        upstream_id: "claude-haiku-4.5",
        display_name: "Claude Haiku 4.5",
        created: 1760486400, // Oct 15, 2025
    },
];

fn bare_def_to_model(def: &BareModelDef) -> Model {
    Model {
        id: def.exposed_id.to_string(),
        object: "model".to_string(),
        created: def.created,
        owned_by: "anthropic".to_string(),
        display_name: def.display_name.to_string(),
        model_type: "chat".to_string(),
        max_tokens: 64000,
    }
}

/// 裸模型目录的上游归一化 ID（点号形态）。供启动期 bootstrap 种子用——这些都是有
/// 抓包/清单证据的真实上游模型，在 refresher 拉到真实清单前作为 effort 门/模型列表的默认。
pub fn bare_catalog_upstream_ids() -> Vec<&'static str> {
    BARE_MODEL_CATALOG.iter().map(|d| d.upstream_id).collect()
}

/// 对外可用模型列表（Task 4 动态化）。
///
/// - 上游模型缓存**已热**：返回「裸目录 ∩ 上游真实清单」——只暴露上游真实存在的模型，
///   未来上游加/减模型自动跟随，零虚标。
/// - 上游缓存**未热**（启动初期或拉取失败）：回退到裸目录全集（仍零 `*-thinking`），
///   保证服务可用、且任何状态下都不暴露虚标变体。
fn available_models() -> Vec<Model> {
    match crate::kiro::upstream_models::cached() {
        Some(_) => BARE_MODEL_CATALOG
            .iter()
            .filter(|def| {
                crate::kiro::upstream_models::contains_normalized(def.upstream_id)
            })
            .map(bare_def_to_model)
            .collect(),
        None => BARE_MODEL_CATALOG.iter().map(bare_def_to_model).collect(),
    }
}

/// GET /v1/models
///
/// 返回可用的模型列表
pub async fn get_models() -> impl IntoResponse {
    tracing::info!("Received GET /v1/models request");

    let models = available_models();

    Json(ModelsResponse {
        object: "list".to_string(),
        data: models,
    })
}

/// POST /v1/messages
///
/// 创建消息（对话）
pub async fn post_messages(
    State(state): State<AppState>,
    Extension(key_ctx): Extension<KeyContext>,
    JsonExtractor(mut payload): JsonExtractor<MessagesRequest>,
) -> Response {
    // Count the image budget on inbound to provide precise diagnostics for later context-window-full errors
    let img_stats = count_image_budget(&payload);
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        image_count = %img_stats.count,
        image_total_b64_kb = %(img_stats.total_b64_bytes / 1024),
        image_largest_b64_kb = %(img_stats.largest_b64_bytes / 1024),
        "Received POST /v1/messages request"
    );
    if img_stats.total_b64_bytes > IMAGE_BUDGET_WARN_BYTES {
        tracing::warn!(
            image_count = %img_stats.count,
            image_total_b64_kb = %(img_stats.total_b64_bytes / 1024),
            "incoming image payload is large; if upstream rejects with CONTENT_LENGTH_EXCEEDS_THRESHOLD, reduce image count or use lower-resolution screenshots"
        );
    }
    let hook = UsageRecordHook::from_state(&state, key_ctx.key_id, payload.model.clone());
    // 检查 KiroProvider 是否可用
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload);
    // 裸高阶 opus（无 -thinking 后缀、客户端又没给 effort）兜底默认 xhigh→max（见函数注释，
    // 根因 2026-06-20：删 CPA -thinking 后全部走裸模型，无此兜底会让 Opus 丢掉 effort 降智）。
    apply_default_effort_floor(&mut payload);

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;

        let resp = websearch::handle_websearch_request(provider, &payload, input_tokens).await;
        // WebSearch 路径走 MCP 端点，没有 credential_id 上下文，统一记 0
        let status = if resp.status().is_success() { "success" } else { "error" };
        hook.record(0, input_tokens, 0, 0, 0, 0.0, status);
        return resp;
    }

    let payload_stream = payload.stream;
    // Mixed-tools (web_search + exec...) case: web_search coexists with other tools and falls onto the normal chat path,
    // where the upstream may return a tool_use with name=web_search. Take the internal agentic loop: search internally and feed the results back.
    if websearch::has_web_search_among_tools(&payload) {
        tracing::info!("detected mixed tools containing web_search, entering the web_search agentic loop");
        let tracer = std::sync::Arc::new(RequestTracer::for_web_search(&state, &key_ctx, &payload));
        return super::websearch_loop::run_web_search_loop(
            provider,
            payload,
            hook,
            payload_stream,
            key_ctx.group.clone(),
            tracer,
        )
        .await;
    }

    // 转换请求
    let conversion_result = match convert_request(&payload) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("模型不支持: {}", model))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
                }
            };
            tracing::warn!("请求转换失败: {}", e);
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    // Codex thread id（从 metadata.user_id 提取的 conversationId）用于 trace 关联
    let conversation_id_for_trace = conversion_result.conversation_state.conversation_id.clone();

    // Build the Kiro request. profile_arn is injected by the provider layer from the actual
    // credentials; additional_model_request_fields is already filtered by converter model support.
    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
        additional_model_request_fields: conversion_result.additional_model_request_fields,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!("Kiro request body: {}", request_body);

    // 估算输入 tokens
    let total_input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system.clone(),
        payload.messages.clone(),
        payload.tools.clone(),
    ) as i32;

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    let tool_name_map = conversion_result.tool_name_map;
    let known_tool_names = conversion_result.known_tool_names;

    // CacheMeter：根据 cache_control 断点查 / 写中转层提示词缓存。
    // 返回 estimate 口径的覆盖量；真实 input/cache 互斥分摊在拿到 total 真值时进行。
    let cache_usage = state
        .cache_meter
        .as_ref()
        .map(|cache| super::cache_metering::compute_cache_usage(cache, &payload, key_ctx.key_id))
        .unwrap_or_default();

    // trace 侧的 effort 快照：客户端请求档位 + 实际发往上游档位（映射后）。
    let (effort_requested, effort_sent) = trace_efforts(&payload, &payload.model);

    if payload.stream {
        // 流式响应
        let tracer = std::sync::Arc::new(RequestTracer::new(
            &state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: true,
                conversation_id: Some(conversation_id_for_trace.clone()),
                effort_requested: effort_requested.clone(),
                effort_sent: effort_sent.clone(),
            },
        ));
        handle_stream_request(
            provider,
            &request_body,
            &payload.model,
            total_input_tokens,
            thinking_enabled,
            tool_name_map,
            known_tool_names,
            hook,
            cache_usage,
            tracer,
            key_ctx.group.clone(),
            conversion_result.affinity_session_id.clone(),
        )
        .await
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking && thinking_enabled;
        let tracer = std::sync::Arc::new(RequestTracer::new(
            &state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: false,
                conversation_id: Some(conversation_id_for_trace.clone()),
                effort_requested,
                effort_sent,
            },
        ));
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            total_input_tokens,
            extract_thinking,
            tool_name_map,
            known_tool_names,
            hook,
            cache_usage,
            tracer,
            key_ctx.group.clone(),
            conversion_result.affinity_session_id.clone(),
        )
        .await
    }
}

/// 处理流式请求
async fn handle_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    known_tool_names: std::collections::HashSet<String>,
    hook: UsageRecordHook,
    cache_usage: super::cache_metering::CacheUsage,
    tracer: std::sync::Arc<RequestTracer>,
    group: Option<String>,
    session_key: Option<String>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let mut call_result = match provider
        .call_api_stream(
            request_body,
            Some(tracer.as_ref()),
            group.as_deref(),
            session_key.as_deref(),
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            hook.record(0, input_tokens, 0, 0, 0, 0.0, "error");
            // 重试链路全部失败、未开始返回内容：error_type 取最后一跳分类
            tracer.finalize("error", last_attempt_outcome(&tracer), Some(&e.to_string()), None, TraceUsage::zero());
            return map_provider_error(e);
        }
    };
    let limiter_permit = call_result.limiter_permit.take();
    let response = call_result.response;
    let credential_id = call_result.credential_id;

    // 创建流处理上下文
    let mut ctx = StreamContext::new_with_thinking(model, input_tokens, thinking_enabled, tool_name_map, known_tool_names);
    ctx.cache_usage = cache_usage;

    // 生成初始事件
    let initial_events = ctx.generate_initial_events();

    // 创建 SSE 流
    let stream = create_sse_stream(response, ctx, initial_events, hook, credential_id, tracer);
    // M1：permit 随 SSE 流活到流结束才 drop（而非 handler 返回即 drop）。
    let stream = PermitHoldingStream::new(stream, limiter_permit);

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Ping 事件间隔（25秒）
const PING_INTERVAL_SECS: u64 = 25;

/// M1：把限速器在飞许可(LimiterPermit)的生命周期绑定到 SSE 流本身。
///
/// 包住任意 SSE 字节流 + 持有 permit；只有当这个 wrapper 被 drop(流被完整消费完，
/// 或客户端断连导致 axum 丢弃响应体)时，permit 才 drop → maxInflight 槽位才释放。
/// 这修掉了「流式请求 permit 在 handler 返回(构建完 Body)时就 drop、而非流真正结束」
/// 导致的长流在飞欠计数(实际并发可超 maxInflight、放大 429)。
struct PermitHoldingStream {
    inner: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, Infallible>> + Send>>,
    // 持有到 drop；非流式/shadow 模式为 None。下划线：仅靠 Drop 释放，不主动读。
    _permit: Option<crate::kiro::rate_limiter::LimiterPermit>,
}

impl PermitHoldingStream {
    fn new(
        inner: impl Stream<Item = Result<Bytes, Infallible>> + Send + 'static,
        permit: Option<crate::kiro::rate_limiter::LimiterPermit>,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            _permit: permit,
        }
    }
}

impl Stream for PermitHoldingStream {
    type Item = Result<Bytes, Infallible>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// 创建 ping 事件的 SSE 字符串
fn create_ping_sse() -> Bytes {
    Bytes::from("event: ping\ndata: {\"type\": \"ping\"}\n\n")
}

/// 创建 SSE 事件流
fn create_sse_stream(
    response: reqwest::Response,
    ctx: StreamContext,
    initial_events: Vec<SseEvent>,
    hook: UsageRecordHook,
    credential_id: u64,
    tracer: std::sync::Arc<RequestTracer>,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    // 先发送初始事件
    let initial_stream = stream::iter(
        initial_events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    );

    // 然后处理 Kiro 响应流，同时每25秒发送 ping 保活
    let body_stream = response.bytes_stream();

    let processing_stream = stream::unfold(
        (body_stream, ctx, EventStreamDecoder::new(), false, interval(Duration::from_secs(PING_INTERVAL_SECS)), hook, credential_id, tracer, 0u64),
        |(mut body_stream, mut ctx, mut decoder, finished, mut ping_interval, hook, credential_id, tracer, mut sent_bytes)| async move {
            if finished {
                return None;
            }

            // 使用 select! 同时等待数据和 ping 定时器
            tokio::select! {
                // 处理数据流
                chunk_result = body_stream.next() => {
                    match chunk_result {
                        Some(Ok(chunk)) => {
                            tracer.mark_first_token();
                            sent_bytes += chunk.len() as u64;
                            // 解码事件
                            if let Err(e) = decoder.feed(&chunk) {
                                tracing::warn!("缓冲区溢出: {}", e);
                            }

                            let mut events = Vec::new();
                            for result in decoder.decode_iter() {
                                match result {
                                    Ok(frame) => {
                                        if let Ok(event) = Event::from_frame(frame) {
                                            let sse_events = ctx.process_kiro_event(&event);
                                            events.extend(sse_events);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("解码事件失败: {}", e);
                                    }
                                }
                            }

                            // 转换为 SSE 字节流
                            let bytes: Vec<Result<Bytes, Infallible>> = events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();

                            Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, hook, credential_id, tracer, sent_bytes)))
                        }
                        Some(Err(e)) => {
                            tracing::error!("读取响应流失败: {}", e);
                            // 发送最终事件并结束（记为 error）
                            let final_events = ctx.generate_final_events();
                            record_stream_usage(&hook, &ctx, credential_id, "error");
                            // 已开始返回内容后上游断流：标记为 interrupted，带已发送字节数
                            tracer.finalize(
                                "interrupted",
                                Some(outcome::STREAM_INTERRUPTED),
                                Some(&e.to_string()),
                                Some(sent_bytes),
                                stream_trace_usage(&ctx),
                            );
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, hook, credential_id, tracer, sent_bytes)))
                        }
                        None => {
                            // 流结束，发送最终事件
                            let final_events = ctx.generate_final_events();
                            record_stream_usage(&hook, &ctx, credential_id, "success");
                            tracer.finalize("success", None, None, None, stream_trace_usage(&ctx));
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, hook, credential_id, tracer, sent_bytes)))
                        }
                    }
                }
                // 发送 ping 保活
                _ = ping_interval.tick() => {
                    tracing::trace!("发送 ping 保活事件");
                    let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                    Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, hook, credential_id, tracer, sent_bytes)))
                }
            }
        },
    )
    .flatten();

    initial_stream.chain(processing_stream)
}

/// 从 StreamContext 提取最终用量并写入 hook
fn record_stream_usage(
    hook: &UsageRecordHook,
    ctx: &StreamContext,
    credential_id: u64,
    status: &str,
) {
    // 互斥分摊后的 (input, cache_creation, cache_read)，与 trace 上报口径一致。
    let (input, cache_creation, cache_read) = ctx.resolved_usage();
    hook.record(
        credential_id,
        input,
        ctx.output_tokens,
        cache_creation,
        cache_read,
        ctx.credits,
        status,
    );
}

/// 从 StreamContext 提取用量，转成 trace 行用量（与 record_stream_usage 同源）
fn stream_trace_usage(ctx: &StreamContext) -> TraceUsage {
    let (input, cache_creation, cache_read) = ctx.resolved_usage();
    TraceUsage {
        input_tokens: input.max(0) as u64,
        output_tokens: ctx.output_tokens.max(0) as u64,
        cache_creation_tokens: cache_creation.max(0) as u64,
        cache_read_tokens: cache_read.max(0) as u64,
        credits: if ctx.credits.is_finite() && ctx.credits > 0.0 { ctx.credits } else { 0.0 },
        reasoning_tokens: ctx.reasoning_tokens.max(0) as u64,
    }
}

use super::converter::get_context_window_size;

/// 处理非流式请求
async fn handle_non_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    // 非流式路径直接处理结构化 Event::ToolUse，不经过 <invoke> 文本嗅探，
    // 因此这里不需要工具表校验；保留参数以对齐调用方签名。
    _known_tool_names: std::collections::HashSet<String>,
    hook: UsageRecordHook,
    cache_usage: super::cache_metering::CacheUsage,
    tracer: std::sync::Arc<RequestTracer>,
    group: Option<String>,
    session_key: Option<String>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let call_result = match provider
        .call_api(
            request_body,
            Some(tracer.as_ref()),
            group.as_deref(),
            session_key.as_deref(),
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            hook.record(0, input_tokens, 0, 0, 0, 0.0, "error");
            tracer.finalize("error", last_attempt_outcome(&tracer), Some(&e.to_string()), None, TraceUsage::zero());
            return map_provider_error(e);
        }
    };
    let response = call_result.response;
    let credential_id = call_result.credential_id;

    // 读取响应体
    let body_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("读取响应体失败: {}", e);
            hook.record(credential_id, input_tokens, 0, 0, 0, 0.0, "error");
            tracer.finalize(
                "interrupted",
                Some(outcome::STREAM_INTERRUPTED),
                Some(&e.to_string()),
                None,
                TraceUsage::zero(),
            );
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    format!("读取响应失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    // 解析事件流
    let mut decoder = EventStreamDecoder::new();
    if let Err(e) = decoder.feed(&body_bytes) {
        tracing::warn!("缓冲区溢出: {}", e);
    }

    let mut text_content = String::new();
    let mut native_thinking = String::new();
    let mut native_thinking_signature: Option<String> = None;
    let mut native_redacted_thinking: Vec<String> = Vec::new();
    let mut tool_uses: Vec<serde_json::Value> = Vec::new();
    let mut has_tool_use = false;
    let mut stop_reason = "end_turn".to_string();
    // 从 contextUsageEvent 计算的实际输入 tokens
    let mut context_input_tokens: Option<i32> = None;
    // meteringEvent 上报的 credit 计费量（上游真实下发）；
    // input/cache_* 的互斥分摊在拿到 total 真值后由 cache_usage 完成。
    let mut credits: f64 = 0.0;

    // 收集工具调用的增量 JSON
    let mut tool_json_buffers: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for result in decoder.decode_iter() {
        match result {
            Ok(frame) => {
                if let Ok(event) = Event::from_frame(frame) {
                    match event {
                        Event::AssistantResponse(resp) => {
                            text_content.push_str(&resp.content);
                        }
                        Event::ReasoningContent(reasoning) => {
                            if let Some(text) = reasoning.text
                                && !text.is_empty()
                            {
                                native_thinking.push_str(&text);
                            }
                            if let Some(signature) = reasoning.signature
                                && !signature.is_empty()
                            {
                                native_thinking_signature = Some(signature);
                            }
                            if let Some(redacted) = reasoning.redacted_content
                                && !redacted.is_empty()
                            {
                                native_redacted_thinking.push(redacted);
                            }
                        }
                        Event::ToolUse(tool_use) => {
                            has_tool_use = true;

                            // 累积工具的 JSON 输入
                            let buffer = tool_json_buffers
                                .entry(tool_use.tool_use_id.clone())
                                .or_insert_with(String::new);
                            buffer.push_str(&tool_use.input);

                            // 如果是完整的工具调用，添加到列表
                            if tool_use.stop {
                                let input: serde_json::Value = if buffer.is_empty() {
                                    serde_json::json!({})
                                } else {
                                    serde_json::from_str(buffer).unwrap_or_else(|e| {
                                        tracing::warn!(
                                            "工具输入 JSON 解析失败: {}, tool_use_id: {}",
                                            e,
                                            tool_use.tool_use_id
                                        );
                                        serde_json::json!({})
                                    })
                                };

                                let original_name = tool_name_map
                                    .get(&tool_use.name)
                                    .cloned()
                                    .unwrap_or_else(|| tool_use.name.clone());

                                tool_uses.push(json!({
                                    "type": "tool_use",
                                    "id": tool_use.tool_use_id,
                                    "name": original_name,
                                    "input": input
                                }));
                            }
                        }
                        Event::ContextUsage(context_usage) => {
                            // 从上下文使用百分比计算实际的 input_tokens
                            let window_size = get_context_window_size(model);
                            let actual_input_tokens =
                                (context_usage.context_usage_percentage * (window_size as f64)
                                    / 100.0) as i32;
                            context_input_tokens = Some(actual_input_tokens);
                            // 上下文使用量达到 100% 时，设置 stop_reason 为 model_context_window_exceeded
                            if context_usage.context_usage_percentage >= 100.0 {
                                stop_reason = "model_context_window_exceeded".to_string();
                            }
                            tracing::debug!(
                                "收到 contextUsageEvent: {}%, 计算 input_tokens: {}",
                                context_usage.context_usage_percentage,
                                actual_input_tokens
                            );
                        }
                        Event::Metering(metering) => {
                            // 上游只下发 credit；token / cache 字段不存在
                            credits += metering.usage;
                            tracing::debug!("metering credits +{:.6}", metering.usage);
                        }
                        Event::Exception { exception_type, .. } => {
                            if exception_type == "ContentLengthExceededException" {
                                stop_reason = "max_tokens".to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                tracing::warn!("解码事件失败: {}", e);
            }
        }
    }

    // 确定 stop_reason
    if has_tool_use && stop_reason == "end_turn" {
        stop_reason = "tool_use".to_string();
    }

    // 构建响应内容
    let mut content = build_non_stream_content(
        thinking_enabled,
        text_content,
        native_thinking,
        native_thinking_signature,
        native_redacted_thinking,
    );
    content.extend(tool_uses);

    // 估算输出 tokens（上游不下发 token，全部走估算）
    let output_tokens = token::estimate_output_tokens(&content);

    // 思考 token 单独计数（与 stream 路径口径一致：thinking 文本走 estimate_tokens，
    // 加密 redacted 块固定 +8）。output_tokens 已包含 thinking，这里是额外的独立计数，
    // 不从 output_tokens 中扣减。
    let reasoning_tokens: i32 = content
        .iter()
        .map(|block| match block.get("type").and_then(|t| t.as_str()) {
            Some("thinking") => block
                .get("thinking")
                .and_then(|t| t.as_str())
                .map(super::stream::estimate_tokens)
                .unwrap_or(0),
            Some("redacted_thinking") => 8,
            _ => 0,
        })
        .sum();

    // 输入 tokens：contextUsage 真实值优先，否则用客户端估算
    let total_input_tokens = resolve_usage_input_tokens(input_tokens, context_input_tokens);
    // 互斥分摊：input + cache_creation + cache_read == total
    let (final_input_tokens, cache_creation_tokens, cache_read_tokens) =
        cache_usage.split_against_total(total_input_tokens);

    // 构建 Anthropic 响应
    let response_body = json!({
        "id": format!("msg_{}", Uuid::new_v4().to_string().replace('-', "")),
        "type": "message",
        "role": "assistant",
        "content": content,
        "model": model,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": final_input_tokens,
            "output_tokens": output_tokens,
            "cache_creation_input_tokens": cache_creation_tokens,
            "cache_read_input_tokens": cache_read_tokens
        }
    });

    hook.record(
        credential_id,
        final_input_tokens,
        output_tokens,
        cache_creation_tokens,
        cache_read_tokens,
        credits,
        "success",
    );
    tracer.finalize(
        "success",
        None,
        None,
        None,
        TraceUsage {
            input_tokens: final_input_tokens.max(0) as u64,
            output_tokens: output_tokens.max(0) as u64,
            cache_creation_tokens: cache_creation_tokens.max(0) as u64,
            cache_read_tokens: cache_read_tokens.max(0) as u64,
            credits: if credits.is_finite() && credits > 0.0 { credits } else { 0.0 },
            reasoning_tokens: reasoning_tokens.max(0) as u64,
        },
    );
    (StatusCode::OK, Json(response_body)).into_response()
}

fn build_non_stream_content(
    thinking_enabled: bool,
    text_content: String,
    native_thinking: String,
    native_thinking_signature: Option<String>,
    native_redacted_thinking: Vec<String>,
) -> Vec<serde_json::Value> {
    let mut content = Vec::new();
    let has_native_thinking = !native_thinking.is_empty();

    if thinking_enabled {
        if has_native_thinking {
            content.push(json!({
                "type": "thinking",
                "thinking": native_thinking.clone(),
                "signature": native_thinking_signature
                    .unwrap_or_else(|| super::stream::THINKING_SIGNATURE_PLACEHOLDER.to_string()),
            }));
        } else {
            // 从完整文本中提取 thinking 块，兼容旧的 <thinking> 文本路径。
            let (thinking, remaining_text) =
                super::stream::extract_thinking_from_complete_text(&text_content);

            if let Some(thinking_text) = thinking {
                content.push(json!({
                    "type": "thinking",
                    "thinking": thinking_text,
                    "signature": super::stream::THINKING_SIGNATURE_PLACEHOLDER,
                }));
            }

            if !remaining_text.is_empty() {
                content.push(json!({
                    "type": "text",
                    "text": remaining_text
                }));
            }
        }

        for redacted in native_redacted_thinking {
            content.push(json!({
                "type": "redacted_thinking",
                "data": redacted
            }));
        }

        if has_native_thinking && !text_content.is_empty() {
            content.push(json!({
                "type": "text",
                "text": text_content
            }));
        }
    } else if !text_content.is_empty() {
        content.push(json!({
            "type": "text",
            "text": text_content
        }));
    } else if has_native_thinking {
        content.push(json!({
            "type": "text",
            "text": native_thinking
        }));
    }
    content
}

/// 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
///
/// - Opus 4.6：覆写为 adaptive 类型
/// - 其他模型：覆写为 enabled 类型
/// - budget_tokens 固定为 20000
fn override_thinking_from_model_name(payload: &mut MessagesRequest) {
    let model_lower = payload.model.to_lowercase();
    if !model_lower.contains("thinking") {
        return;
    }

    // 根治 P0：带 `-thinking` 后缀的请求（老会话/历史 thread 里选过 "… Thinking" 的）
    // 统一走 **adaptive**，thinking 深度由 `output_config.effort` 驱动、上游服务端自动决定。
    // 旧逻辑把非 opus-4.6 的 -thinking 强制 `enabled` + budget_tokens 且不设 effort，
    // 会把 opus-4.8-thinking 打回老 budget 路径、丢掉 effort=max——这里彻底改掉。
    //
    // effort 兜底：客户端已带 `output_config.effort` 则尊重客户端；否则默认补 `xhigh`
    // （经 converter 的 `xhigh→max` 映射拿到上游最强 max；绝不依赖 `default_effort()`，
    // 它只返回 `high` 拿不到 max）。是否真发往上游仍由 converter 的
    // `should_emit_output_config` 门控（上游存在即放行），这里只负责补默认值。
    let client_supplied_effort = payload
        .output_config
        .as_ref()
        .map(|oc| oc.effort.trim())
        .is_some_and(|e| !e.is_empty());

    tracing::info!(
        model = %payload.model,
        client_effort = client_supplied_effort,
        "模型名包含 thinking 后缀，归一为 adaptive + effort 兜底"
    );

    payload.thinking = Some(Thinking {
        thinking_type: "adaptive".to_string(),
        budget_tokens: 20000,
    });

    if !client_supplied_effort {
        payload.output_config = Some(OutputConfig {
            effort: "xhigh".to_string(),
        });
    }
}

/// 兜底：客户端没给 effort 时，给高阶推理模型（opus）补默认 `xhigh`（经 converter 映射成上游 `max`）。
///
/// 根因（2026-06-20）：`override_thinking_from_model_name` 只兜 `-thinking` 后缀的老会话；而新会话
/// 用的是**裸** `claude-opus-4-8`，Codex App 的辅助/auto 调用常常不带 `reasoning.effort` → CPA 原样
/// 透传 → 这里若不兜底，请求就带着**空 effort** 打到上游，Opus 跑在内置（低）推理档而非用户期望的顶档。
/// 实测：删 CPA `-thinking` 后全部流量走裸模型，这个兜底是「Opus 永远拿满 Max」的最后保证。
/// catalog 里 `kiro-api/claude-opus-4-8` 的 `default_reasoning_level` 也是 xhigh，此处与之对齐。
///
/// 是否真发往上游仍由 converter 的 `should_emit_output_config` 门控（上游真实存在才放行 + opus-4.6
/// 的 adaptive 怪癖），故非 opus / 上游不存在的模型不受影响；显式客户端 effort 一律尊重不覆盖。
fn apply_default_effort_floor(payload: &mut MessagesRequest) {
    let has_effort = payload
        .output_config
        .as_ref()
        .map(|oc| !oc.effort.trim().is_empty())
        .unwrap_or(false);
    if has_effort {
        return; // 尊重客户端显式选择
    }
    // 只对高阶推理 opus 兜底（与 catalog 的 xhigh 默认一致）；其余模型保持原样。
    if !payload.model.to_lowercase().contains("opus") {
        return;
    }
    payload.output_config = Some(OutputConfig {
        effort: "xhigh".to_string(),
    });
}

/// POST /v1/messages/count_tokens
///
/// 计算消息的 token 数量
pub async fn count_tokens(
    Extension(_key_ctx): Extension<KeyContext>,
    JsonExtractor(payload): JsonExtractor<CountTokensRequest>,
) -> impl IntoResponse {
    tracing::info!(
        model = %payload.model,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages/count_tokens request"
    );

    let total_tokens = token::count_all_tokens(
        payload.model,
        payload.system,
        payload.messages,
        payload.tools,
    ) as i32;

    Json(CountTokensResponse {
        input_tokens: total_tokens.max(1) as i32,
    })
}

/// POST /cc/v1/messages
///
/// Claude Code 兼容端点，与 /v1/messages 的区别在于：
/// - 流式响应会等待 kiro 端返回 contextUsageEvent 后再发送 message_start
/// - message_start 中的 input_tokens 是从 contextUsageEvent 计算的准确值
pub async fn post_messages_cc(
    State(state): State<AppState>,
    Extension(key_ctx): Extension<KeyContext>,
    JsonExtractor(mut payload): JsonExtractor<MessagesRequest>,
) -> Response {
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        "Received POST /cc/v1/messages request"
    );
    let hook = UsageRecordHook::from_state(&state, key_ctx.key_id, payload.model.clone());

    // 检查 KiroProvider 是否可用
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload);
    // 裸高阶 opus（无 -thinking 后缀、客户端又没给 effort）兜底默认 xhigh→max（见函数注释，
    // 根因 2026-06-20：删 CPA -thinking 后全部走裸模型，无此兜底会让 Opus 丢掉 effort 降智）。
    apply_default_effort_floor(&mut payload);

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;

        let resp = websearch::handle_websearch_request(provider, &payload, input_tokens).await;
        let status = if resp.status().is_success() { "success" } else { "error" };
        hook.record(0, input_tokens, 0, 0, 0, 0.0, status);
        return resp;
    }

    let payload_stream = payload.stream;
    // Mixed-tools (web_search + exec...) case: web_search coexists with other tools and falls onto the normal chat path,
    // where the upstream may return a tool_use with name=web_search. Take the internal agentic loop: search internally and feed the results back.
    if websearch::has_web_search_among_tools(&payload) {
        tracing::info!("detected mixed tools containing web_search, entering the web_search agentic loop");
        let tracer = std::sync::Arc::new(RequestTracer::for_web_search(&state, &key_ctx, &payload));
        return super::websearch_loop::run_web_search_loop(
            provider,
            payload,
            hook,
            payload_stream,
            key_ctx.group.clone(),
            tracer,
        )
        .await;
    }

    // 转换请求
    let conversion_result = match convert_request(&payload) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("模型不支持: {}", model))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
                }
            };
            tracing::warn!("请求转换失败: {}", e);
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    // Codex thread id（从 metadata.user_id 提取的 conversationId）用于 trace 关联
    let conversation_id_for_trace = conversion_result.conversation_state.conversation_id.clone();

    // Build the Kiro request. profile_arn is injected by the provider layer from the actual
    // credentials; additional_model_request_fields is already filtered by converter model support.
    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
        additional_model_request_fields: conversion_result.additional_model_request_fields,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!("Kiro request body: {}", request_body);

    // 计算总 input tokens
    let total_input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system.clone(),
        payload.messages.clone(),
        payload.tools.clone(),
    ) as i32;

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    let tool_name_map = conversion_result.tool_name_map;
    let known_tool_names = conversion_result.known_tool_names;

    // CacheMeter：根据 cache_control 断点查 / 写中转层提示词缓存（estimate 口径）。
    let cache_usage = state
        .cache_meter
        .as_ref()
        .map(|cache| super::cache_metering::compute_cache_usage(cache, &payload, key_ctx.key_id))
        .unwrap_or_default();

    // trace 侧的 effort 快照：客户端请求档位 + 实际发往上游档位（映射后）。
    let (effort_requested, effort_sent) = trace_efforts(&payload, &payload.model);

    if payload.stream {
        // 流式响应（缓冲模式）
        let tracer = std::sync::Arc::new(RequestTracer::new(
            &state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: true,
                conversation_id: Some(conversation_id_for_trace.clone()),
                effort_requested: effort_requested.clone(),
                effort_sent: effort_sent.clone(),
            },
        ));
        handle_stream_request_buffered(
            provider,
            &request_body,
            &payload.model,
            thinking_enabled,
            tool_name_map,
            known_tool_names,
            hook,
            total_input_tokens,
            cache_usage,
            tracer,
            key_ctx.group.clone(),
            conversion_result.affinity_session_id.clone(),
        )
        .await
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking && thinking_enabled;
        let tracer = std::sync::Arc::new(RequestTracer::new(
            &state,
            RequestTraceOptions {
                key_ctx: key_ctx.clone(),
                model: payload.model.clone(),
                is_stream: false,
                conversation_id: Some(conversation_id_for_trace.clone()),
                effort_requested,
                effort_sent,
            },
        ));
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            total_input_tokens,
            extract_thinking,
            tool_name_map,
            known_tool_names,
            hook,
            cache_usage,
            tracer,
            key_ctx.group.clone(),
            conversion_result.affinity_session_id.clone(),
        )
        .await
    }
}

/// 处理流式请求（缓冲版本）
///
/// 与 `handle_stream_request` 不同，此函数会缓冲所有事件直到流结束，
/// 然后用从 contextUsageEvent 计算的正确 input_tokens 生成 message_start 事件。
async fn handle_stream_request_buffered(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    thinking_enabled: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    known_tool_names: std::collections::HashSet<String>,
    hook: UsageRecordHook,
    fallback_input_tokens: i32,
    cache_usage: super::cache_metering::CacheUsage,
    tracer: std::sync::Arc<RequestTracer>,
    group: Option<String>,
    session_key: Option<String>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let mut call_result = match provider
        .call_api_stream(
            request_body,
            Some(tracer.as_ref()),
            group.as_deref(),
            session_key.as_deref(),
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            hook.record(0, fallback_input_tokens, 0, 0, 0, 0.0, "error");
            tracer.finalize("error", last_attempt_outcome(&tracer), Some(&e.to_string()), None, TraceUsage::zero());
            return map_provider_error(e);
        }
    };
    let limiter_permit = call_result.limiter_permit.take();
    let response = call_result.response;
    let credential_id = call_result.credential_id;

    // 创建缓冲流处理上下文
    let mut ctx = BufferedStreamContext::new(
        model,
        fallback_input_tokens,
        thinking_enabled,
        tool_name_map,
        known_tool_names,
    );
    ctx.set_cache_usage(cache_usage);

    // 创建缓冲 SSE 流
    let stream = create_buffered_sse_stream(response, ctx, hook, credential_id, tracer);
    // M1：permit 随缓冲 SSE 流活到流结束才 drop（而非 handler 返回即 drop）。
    let stream = PermitHoldingStream::new(stream, limiter_permit);

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// 创建缓冲 SSE 事件流
///
/// 工作流程：
/// 1. 等待上游流完成，期间只发送 ping 保活信号
/// 2. 使用 StreamContext 的事件处理逻辑处理所有 Kiro 事件，结果缓存
/// 3. 流结束后，用正确的 input_tokens 更正 message_start 事件
/// 4. 一次性发送所有事件
fn create_buffered_sse_stream(
    response: reqwest::Response,
    ctx: BufferedStreamContext,
    hook: UsageRecordHook,
    credential_id: u64,
    tracer: std::sync::Arc<RequestTracer>,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let body_stream = response.bytes_stream();

    stream::unfold(
        (
            body_stream,
            ctx,
            EventStreamDecoder::new(),
            false,
            interval(Duration::from_secs(PING_INTERVAL_SECS)),
            hook,
            credential_id,
            tracer,
            0u64,
        ),
        |(mut body_stream, mut ctx, mut decoder, finished, mut ping_interval, hook, credential_id, tracer, mut sent_bytes)| async move {
            if finished {
                return None;
            }

            loop {
                tokio::select! {
                    // 使用 biased 模式，优先检查 ping 定时器
                    // 避免在上游 chunk 密集时 ping 被"饿死"
                    biased;

                    // 优先检查 ping 保活（等待期间唯一发送的数据）
                    _ = ping_interval.tick() => {
                        tracing::trace!("发送 ping 保活事件（缓冲模式）");
                        let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                        return Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval, hook, credential_id, tracer, sent_bytes)));
                    }

                    // 然后处理数据流
                    chunk_result = body_stream.next() => {
                        match chunk_result {
                            Some(Ok(chunk)) => {
                                tracer.mark_first_token();
                                sent_bytes += chunk.len() as u64;
                                // 解码事件
                                if let Err(e) = decoder.feed(&chunk) {
                                    tracing::warn!("缓冲区溢出: {}", e);
                                }

                                for result in decoder.decode_iter() {
                                    match result {
                                        Ok(frame) => {
                                            if let Ok(event) = Event::from_frame(frame) {
                                                // 缓冲事件（复用 StreamContext 的处理逻辑）
                                                ctx.process_and_buffer(&event);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("解码事件失败: {}", e);
                                        }
                                    }
                                }
                                // 继续读取下一个 chunk，不发送任何数据
                            }
                            Some(Err(e)) => {
                                tracing::error!("读取响应流失败: {}", e);
                                // 发生错误，完成处理并返回所有事件
                                let all_events = ctx.finish_and_get_all_events();
                                let (i, o, cc, cr, credits) = ctx.final_usage();
                                hook.record(credential_id, i, o, cc, cr, credits, "error");
                                // 缓冲模式 chunk 读取失败：上游中途断流
                                tracer.finalize(
                                    "interrupted",
                                    Some(outcome::STREAM_INTERRUPTED),
                                    Some(&e.to_string()),
                                    Some(sent_bytes),
                                    TraceUsage {
                                        input_tokens: i.max(0) as u64,
                                        output_tokens: o.max(0) as u64,
                                        cache_creation_tokens: cc.max(0) as u64,
                                        cache_read_tokens: cr.max(0) as u64,
                                        credits: if credits.is_finite() && credits > 0.0 { credits } else { 0.0 },
                                        reasoning_tokens: ctx.reasoning_tokens().max(0) as u64,
                                    },
                                );
                                let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                return Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, hook, credential_id, tracer, sent_bytes)));
                            }
                            None => {
                                // 流结束，完成处理并返回所有事件（已更正 input_tokens）
                                let all_events = ctx.finish_and_get_all_events();
                                let (i, o, cc, cr, credits) = ctx.final_usage();
                                hook.record(credential_id, i, o, cc, cr, credits, "success");
                                tracer.finalize(
                                    "success",
                                    None,
                                    None,
                                    None,
                                    TraceUsage {
                                        input_tokens: i.max(0) as u64,
                                        output_tokens: o.max(0) as u64,
                                        cache_creation_tokens: cc.max(0) as u64,
                                        cache_read_tokens: cr.max(0) as u64,
                                        credits: if credits.is_finite() && credits > 0.0 { credits } else { 0.0 },
                                        reasoning_tokens: ctx.reasoning_tokens().max(0) as u64,
                                    },
                                );
                                let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                return Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval, hook, credential_id, tracer, sent_bytes)));
                            }
                        }
                    }
                }
            }
        },
    )
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    // M1 回归：PermitHoldingStream 持有 permit 直到流被完整消费(或 drop)，
    // 而非构建后立即释放。验证「流未消费完时 inflight 仍占用，消费完才释放」。
    #[tokio::test]
    async fn permit_held_until_stream_fully_consumed() {
        use crate::kiro::rate_limiter::{AcquireOutcome, AdaptiveConfig, AdaptiveLimiter};
        use futures::StreamExt;

        // 单飞 limiter：拿到 permit 后，第二次 acquire 必须等到 permit 释放。
        let mut acfg = crate::model::config::AdaptiveLimitConfig::default();
        acfg.enabled = true;
        acfg.enforce = true;
        acfg.adaptive_concurrency.hard_max_inflight = 1;
        acfg.adaptive_concurrency.min_inflight = 1;
        let mut cfg = AdaptiveConfig::from_cfg(&acfg);
        cfg.hard_max_inflight = 1;
        cfg.min_inflight = 1;
        // 高速率 + 大 burst：让「令牌桶」几乎不拦，使测试只考验「inflight 槽位」这一维度
        // （否则第二次 acquire 会被令牌桶节流而非 inflight，掩盖 permit 释放语义）。
        cfg.initial_rate_rps = 1000.0;
        cfg.max_rate_rps = 1000.0;
        cfg.goodput_sanity_max_rps = 1000.0;
        cfg.burst = 10.0;
        let lim = AdaptiveLimiter::new(cfg);
        let permit = match lim.acquire().await {
            AcquireOutcome::Proceed(p) => p,
            other => panic!("expected Proceed, got {other:?}"),
        };
        // 构造一个 2 元素的 SSE 流，permit 交给 PermitHoldingStream。
        let inner = stream::iter(vec![
            Ok::<Bytes, Infallible>(Bytes::from_static(b"a")),
            Ok::<Bytes, Infallible>(Bytes::from_static(b"b")),
        ]);
        let mut held = PermitHoldingStream::new(inner, Some(permit));
        // 消费第一个元素：流没结束 → permit 仍被持有 → 第二次 acquire 拿不到。
        assert!(held.next().await.is_some());
        let blocked = tokio::time::timeout(Duration::from_millis(80), lim.acquire()).await;
        assert!(blocked.is_err(), "流未消费完时 permit 应仍占用 inflight");
        // 消费完整个流并 drop wrapper → permit 释放 → 第二次 acquire 能拿到。
        assert!(held.next().await.is_some());
        assert!(held.next().await.is_none());
        drop(held);
        let ok = tokio::time::timeout(Duration::from_millis(200), lim.acquire()).await;
        assert!(ok.is_ok(), "流结束 + wrapper drop 后 permit 应释放，inflight 可再获取");
    }

    #[test]
    fn bedrock_client_validation_errors_map_to_400() {
        // 客户端校验错误必须映射为 400（而非 5xx），否则会被 provider 当作上游
        // 瞬态错误触发冷却，放大成 503 风暴。识别逻辑集中在 endpoint 层。
        for needle in [
            // 精确 reason（provider 错误串里嵌着上游 body）
            "非流式 API 请求失败: 500 {\"reason\":\"TOOL_USE_RESULT_MISMATCH\"}",
            // message 级特异短语（纯文本报文）
            "Expected toolResult blocks but found none",
        ] {
            let resp = map_provider_error(anyhow::anyhow!(needle.to_string()));
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "错误串 `{needle}` 应映射为 400"
            );
        }
    }

    #[test]
    fn generic_upstream_error_still_maps_to_502() {
        // 回归：普通上游错误不应被新分支误伤，仍应是 502 BAD_GATEWAY。
        let resp = map_provider_error(anyhow::anyhow!("connection reset by peer"));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        // 回归：宽泛的 ValidationException 不再被当作客户端校验错误而误判为 400，
        // 仍按上游错误走 502（避免把可重试故障误杀）。
        let resp = map_provider_error(anyhow::anyhow!(
            "ValidationException: transient backend issue".to_string()
        ));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn rate_limit_throttling_maps_to_429_not_502() {
        // 纯速率限流（SERVICE_REQUEST_RATE_EXCEEDED / ThrottlingException）是
        // "请求太快、慢点重试"的瞬态信号，账号配额并未耗尽。
        //
        // 若兜底成 502，CPA 会把它当上游服务故障，对该 claude 凭据冷却 60 秒；
        // 单凭据场景下 60 秒内所有请求秒回 503（auth_unavailable 风暴）。
        //
        // 映射成 429 后，CPA 走配额退避分支（base 1 秒，远小于 60 秒），
        // 且语义诚实（确实是限流，不是把限流谎称成客户端 400）。
        for needle in [
            // provider 错误串里嵌着上游 throttling body（今天 2000 次真实样本的形态）
            "流式 API 请求失败: 429 Too Many Requests {\"__type\":\"com.amazon.kiro.runtimeservice#ThrottlingException\",\"message\":\"Too many requests, please wait before trying again.\",\"reason\":\"SERVICE_REQUEST_RATE_EXCEEDED\"}",
        ] {
            let resp = map_provider_error(anyhow::anyhow!(needle.to_string()));
            assert_eq!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "速率限流 `{needle}` 应映射为 429（而非 502），避免触发 60 秒 cooldown 风暴"
            );
        }
    }

    #[test]
    fn non_stream_native_thinking_precedes_redacted_and_text() {
        let content = build_non_stream_content(
            true,
            "final answer".to_string(),
            "native thinking".to_string(),
            Some("real-signature".to_string()),
            vec!["encrypted-thinking".to_string()],
        );

        assert_eq!(content.len(), 3);
        assert_eq!(content[0]["type"], "thinking");
        assert_eq!(content[0]["thinking"], "native thinking");
        assert_eq!(content[0]["signature"], "real-signature");
        assert_eq!(content[1]["type"], "redacted_thinking");
        assert_eq!(content[1]["data"], "encrypted-thinking");
        assert_eq!(content[2]["type"], "text");
        assert_eq!(content[2]["text"], "final answer");
    }

    #[test]
    fn non_stream_legacy_thinking_extraction_still_works_without_native_reasoning() {
        let content = build_non_stream_content(
            true,
            "<thinking>legacy thinking</thinking>\n\nfinal answer".to_string(),
            String::new(),
            None,
            Vec::new(),
        );

        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "thinking");
        assert_eq!(content[0]["thinking"], "legacy thinking");
        assert_eq!(
            content[0]["signature"],
            crate::anthropic::stream::THINKING_SIGNATURE_PLACEHOLDER
        );
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "final answer");
    }

    #[test]
    fn non_stream_native_thinking_downgrades_to_text_when_thinking_disabled() {
        let content = build_non_stream_content(
            false,
            String::new(),
            "native thinking fallback".to_string(),
            Some("ignored-signature".to_string()),
            vec!["ignored-redacted".to_string()],
        );

        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "native thinking fallback");
    }

    #[test]
    fn available_models_include_opus_4_7_variants() {
        let _g = crate::kiro::upstream_models::lock_test();
        crate::kiro::upstream_models::clear_cache_for_test();
        let models = available_models();
        let ids: Vec<&str> = models.iter().map(|model| model.id.as_str()).collect();

        // Task 4: -thinking variants are gone; bare opus-4.7 remains (thinking is driven by effort).
        assert!(ids.contains(&"claude-opus-4-7"));
        assert!(!ids.contains(&"claude-opus-4-7-thinking"));
    }

    #[test]
    fn count_image_budget_handles_empty() {
        let req: super::super::types::MessagesRequest = serde_json::from_str(r#"{
            "model": "claude-opus-4-7",
            "max_tokens": 100,
            "messages": []
        }"#).unwrap();
        let stats = count_image_budget(&req);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.total_b64_bytes, 0);
        assert_eq!(stats.largest_b64_bytes, 0);
    }

    #[test]
    fn count_image_budget_counts_inline_base64() {
        let req: super::super::types::MessagesRequest = serde_json::from_str(r#"{
            "model": "claude-opus-4-7",
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "hi"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA1111"}},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": "BBBBBBBBBB"}},
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/x.png"}}
                ]
            }]
        }"#).unwrap();
        let stats = count_image_budget(&req);
        assert_eq!(stats.count, 2);
        assert_eq!(stats.total_b64_bytes, 18);
        assert_eq!(stats.largest_b64_bytes, 10);
    }

    #[test]
    fn count_image_budget_skips_url_only_images() {
        let req: super::super::types::MessagesRequest = serde_json::from_str(r#"{
            "model": "claude-opus-4-7",
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/x.png"}}
                ]
            }]
        }"#).unwrap();
        let stats = count_image_budget(&req);
        assert_eq!(stats.count, 0);
    }

    #[test]
    fn available_models_include_4_8_variants() {
        let _g = crate::kiro::upstream_models::lock_test();
        crate::kiro::upstream_models::clear_cache_for_test();
        let models = available_models();
        let ids: Vec<&str> = models.iter().map(|model| model.id.as_str()).collect();

        // Task 4: opus-4.8 bare stays; all -thinking variants removed; sonnet-4.8 was a
        // 虚标 (upstream has no sonnet-4.8) and must not appear by default.
        assert!(ids.contains(&"claude-opus-4-8"));
        assert!(!ids.contains(&"claude-opus-4-8-thinking"));
        assert!(!ids.contains(&"claude-sonnet-4-8-thinking"));
    }

    /// Task 4 (dynamic model list): the exposed model list must contain ZERO `*-thinking`
    /// virtual variants — upstream AWS exposes no such id; thinking depth is driven by effort.
    #[test]
    fn available_models_have_no_thinking_variants() {
        let _g = crate::kiro::upstream_models::lock_test();
        crate::kiro::upstream_models::clear_cache_for_test();
        let models = available_models();
        for m in &models {
            assert!(
                !m.id.ends_with("-thinking"),
                "model list must not expose virtual -thinking variant: {}",
                m.id
            );
        }
        // sanity: the core bare models are still present
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert!(ids.contains(&"claude-opus-4-8"));
    }

    /// Task 4: when the upstream cache is warm, the list is filtered to only models the
    /// upstream truly exposes (bare-id catalog ∩ upstream snapshot).
    #[test]
    fn available_models_filtered_by_upstream_when_warm() {
        let _g = crate::kiro::upstream_models::lock_test();
        crate::kiro::upstream_models::set_cache_for_test(
            ["claude-opus-4.8", "claude-opus-4.7"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        let models = available_models();
        let ids: Vec<String> = models.iter().map(|m| m.id.clone()).collect();
        assert!(ids.contains(&"claude-opus-4-8".to_string()));
        assert!(ids.contains(&"claude-opus-4-7".to_string()));
        // opus-4.6 is in the bare catalog but NOT in the upstream snapshot → filtered out.
        assert!(
            !ids.contains(&"claude-opus-4-6".to_string()),
            "warm cache must filter out catalog models the upstream does not expose"
        );
        // still zero -thinking
        assert!(models.iter().all(|m| !m.id.ends_with("-thinking")));
        crate::kiro::upstream_models::clear_cache_for_test();
    }

    #[test]
    fn trace_effort_sent_matches_converter_wire_mapping() {
        // 修复 2026-06-20：trace 的 effort_sent 必须与 converter 真实出站值同口径
        // （复用单一真相源 map_effort_to_wire）。旧版本地副本漏了 low/medium→high
        // clamp，导致出站已 clamp 成 high、trace 却虚记 low/medium，污染降智埋点。
        assert_eq!(trace_effort_sent("xhigh"), "max"); // 顶档 → Kiro Max
        assert_eq!(trace_effort_sent("high"), "high"); // 原样
        assert_eq!(trace_effort_sent("medium"), "high"); // footgun clamp（修复后）
        assert_eq!(trace_effort_sent("low"), "high"); // footgun clamp（修复后）
        assert_eq!(trace_effort_sent("max"), "max"); // 原样
    }

    #[test]
    fn trace_efforts_extracts_requested_and_mapped_sent() {
        let _g = crate::kiro::upstream_models::lock_test();
        // Task 2 (dynamic effort gate): trace_effort_sent_emitted now delegates to converter's
        // upstream-existence gate. Seed the upstream cache with the real list (opus-4.8 present,
        // sonnet-4.8 absent — it was a 虚标) so the trace mirrors真实 send behavior.
        crate::kiro::upstream_models::set_cache_for_test(
            ["claude-opus-4.8", "claude-opus-4.7", "claude-opus-4.6"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        // 用 JSON 反序列化构造请求，避免与 MessagesRequest 字段集硬耦合。
        let parse = |model: &str, oc: Option<&str>| -> MessagesRequest {
            let mut v = serde_json::json!({
                "model": model,
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "hi"}]
            });
            if let Some(effort) = oc {
                v["output_config"] = serde_json::json!({ "effort": effort });
            }
            serde_json::from_value(v).expect("valid MessagesRequest")
        };
        // 主模型 opus-4.8（别名 hyphenated，需经 map_model 归一为 4.8）：output_config 会下发。
        let opus = |oc: Option<&str>| parse("claude-opus-4-8", oc);
        let pm = |m: &str, oc: Option<&str>| parse(m, oc);

        // opus-4.8 + xhigh → (xhigh, max)：上游确实收到 output_config，sent 记映射后线值。
        let (req, sent) = trace_efforts(&opus(Some("xhigh")), "claude-opus-4-8");
        assert_eq!(req.as_deref(), Some("xhigh"));
        assert_eq!(sent.as_deref(), Some("max"));

        // opus-4.8 + high 原样透传
        let (req, sent) = trace_efforts(&opus(Some("high")), "claude-opus-4-8");
        assert_eq!(req.as_deref(), Some("high"));
        assert_eq!(sent.as_deref(), Some("high"));

        // 无 output_config → 两者皆 None
        let (req, sent) = trace_efforts(&opus(None), "claude-opus-4-8");
        assert_eq!(req, None);
        assert_eq!(sent, None);

        // 空白 effort → 视作未指定（None）
        let (req, sent) = trace_efforts(&opus(Some("   ")), "claude-opus-4-8");
        assert_eq!(req, None);
        assert_eq!(sent, None);

        // 门控关键用例：sonnet + xhigh —— converter 不发 output_config，
        // 故 effort_requested 仍记 xhigh（客户端确实要了），但 effort_sent 必须是 None，
        // 绝不虚标 max（否则 downgrade 检测会被假信号污染）。
        let (req, sent) = trace_efforts(&pm("claude-sonnet-4-8", Some("xhigh")), "claude-sonnet-4-8");
        assert_eq!(req.as_deref(), Some("xhigh"));
        assert_eq!(sent, None, "non-gated model must NOT fabricate effort_sent");

        // opus-4.8-thinking 别名也应被 map_model 归一并放行。
        let (req, sent) = trace_efforts(&pm("claude-opus-4.8-thinking", Some("xhigh")), "claude-opus-4.8-thinking");
        assert_eq!(req.as_deref(), Some("xhigh"));
        assert_eq!(sent.as_deref(), Some("max"));
        crate::kiro::upstream_models::clear_cache_for_test();
    }

    // ---- P0: override_thinking_from_model_name 不再把 -thinking 打回老 budget 路径 ----
    // 历史 bug：带 `-thinking` 后缀的非 opus-4.6 模型被强制 thinking_type="enabled"+budget，
    // 且不设 output_config.effort → effort=max 丢失。根治后：一律走 adaptive，且 effort 兜底
    // 到 xhigh（经 converter xhigh→max 拿满），裸模型不受影响。
    fn req_with(model: &str, effort: Option<&str>) -> MessagesRequest {
        let mut v = serde_json::json!({
            "model": model,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}]
        });
        if let Some(e) = effort {
            v["output_config"] = serde_json::json!({ "effort": e });
        }
        serde_json::from_value(v).expect("valid MessagesRequest")
    }

    #[test]
    fn override_thinking_opus48_thinking_no_effort_defaults_to_adaptive_xhigh() {
        // 老会话/历史 thread 里选过 "Opus 4.8 Thinking" 的请求：model 带 -thinking、无 output_config。
        // 根治后必须走 adaptive 且兜底补 effort=xhigh（→ converter 映射成上游 max）。
        let mut payload = req_with("claude-opus-4-8-thinking", None);
        override_thinking_from_model_name(&mut payload);
        let thinking = payload.thinking.expect("thinking must be set for -thinking model");
        assert_eq!(thinking.thinking_type, "adaptive", "-thinking must use adaptive, not enabled");
        let oc = payload.output_config.expect("effort must be backfilled when client sent none");
        assert_eq!(oc.effort, "xhigh", "no-effort -thinking must default to xhigh (→max), not high");
    }

    #[test]
    fn override_thinking_opus48_thinking_keeps_client_effort() {
        // 客户端自带 effort 时不覆盖（尊重显式选择）。
        let mut payload = req_with("claude-opus-4-8-thinking", Some("high"));
        override_thinking_from_model_name(&mut payload);
        let oc = payload.output_config.expect("client output_config must be preserved");
        assert_eq!(oc.effort, "high", "client-supplied effort must not be overwritten");
        assert_eq!(payload.thinking.unwrap().thinking_type, "adaptive");
    }

    #[test]
    fn override_thinking_bare_opus48_is_untouched() {
        // 裸 claude-opus-4.8（无 -thinking 后缀）不被此函数改动。
        let mut payload = req_with("claude-opus-4-8", None);
        override_thinking_from_model_name(&mut payload);
        assert!(payload.thinking.is_none(), "bare model must not get thinking injected");
        assert!(payload.output_config.is_none(), "bare model must not get output_config injected");
    }

    #[test]
    fn default_effort_floor_bare_opus_no_effort_defaults_xhigh() {
        // 根因修复（2026-06-20）：裸 opus 无客户端 effort 时必须 server 端兜底 xhigh（→max），
        // 否则删 CPA -thinking 后裸模型请求会丢 effort 降智。
        let mut payload = req_with("claude-opus-4-8", None);
        apply_default_effort_floor(&mut payload);
        let oc = payload.output_config.expect("裸 opus 无 effort 必须被兜底");
        assert_eq!(oc.effort, "xhigh", "裸 opus 无 effort → 默认 xhigh(→max)");
    }

    #[test]
    fn default_effort_floor_respects_explicit_client_effort() {
        let mut payload = req_with("claude-opus-4-8", Some("high"));
        apply_default_effort_floor(&mut payload);
        assert_eq!(
            payload.output_config.unwrap().effort,
            "high",
            "显式客户端 effort 不被覆盖"
        );
    }

    #[test]
    fn default_effort_floor_skips_non_opus() {
        let mut payload = req_with("claude-haiku-4-5", None);
        apply_default_effort_floor(&mut payload);
        assert!(payload.output_config.is_none(), "非 opus 模型不应被兜底 effort");
    }

    // 回归（2026-06-21）：web_search agentic-loop 路径此前完全不写 traces.db，
    // 导致任何带 web_search 的请求在 trace 库里查无记录。这里证明 for_web_search
    // 构造的 tracer 在 finalize 后确实落库，且 effort / conversation_id 快照正确。
    #[test]
    fn web_search_tracer_finalize_lands_in_store() {
        let store: SharedTraceStore =
            std::sync::Arc::new(crate::admin::TraceStore::open_in_memory().unwrap());
        let mut state = AppState::new(false);
        state.trace_store = Some(store.clone());
        let key_ctx = KeyContext {
            key_id: 0,
            group: None,
            key_source: TraceKeySource::MasterApiKey,
        };
        // 带 web_search 工具 + 显式 session id 的请求（与真实 Codex 请求同形态）。
        let mut payload = req_with("claude-opus-4-8", Some("xhigh"));
        payload.metadata = serde_json::from_value(serde_json::json!({
            "user_id": "user_deadbeef_account__session_019ee8dc-5a2e-7e81-a3a9-5ab8eae69b40"
        }))
        .unwrap();

        let tracer = RequestTracer::for_web_search(&state, &key_ctx, &payload);
        tracer.finalize("success", None, None, None, TraceUsage::zero());

        let (rows, total) = store.query_paged(&crate::admin::trace_db::TraceQuery {
            limit: 10,
            ..Default::default()
        });
        assert_eq!(total, 1, "web_search 路径 finalize 后必须落 1 条 trace");
        assert_eq!(rows[0].final_status, "success");
        // effort_requested 永远记录客户端原始档位（不受上游缓存门控影响）。
        assert_eq!(rows[0].effort_requested.as_deref(), Some("xhigh"));
        // effort_sent 由 converter 的 should_emit_output_config 门控：仅当上游清单缓存里
        // 真有该模型才记映射后线值；测试环境上游缓存为空 → 合理地记 None（与普通路径同口径，
        // 不虚记）。这里只断言「与普通 chat 路径同口径」，不强求非 None。
        let (expected_req, expected_sent) = trace_efforts(&payload, &payload.model);
        assert_eq!(rows[0].effort_requested.as_deref(), expected_req.as_deref());
        assert_eq!(rows[0].effort_sent.as_deref(), expected_sent.as_deref());
        // conversation_id 取自 metadata.user_id 里的 Codex thread id。
        assert_eq!(
            rows[0].conversation_id.as_deref(),
            Some("019ee8dc-5a2e-7e81-a3a9-5ab8eae69b40"),
            "应记录 Codex thread id 作为 conversation_id"
        );
    }
}

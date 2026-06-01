//! web_search 局部 agentic loop
//!
//! 处理"混合工具(web_search + exec...)落普通对话后,上游回 name=web_search 的 tool_use"场景:
//! kiro-rs 内部调 /mcp 搜索 -> 把结果当 tool_result 回灌 -> 重转换重发 -> 循环到上游不再要搜索;
//! 非 web_search 的 tool_use(exec 等)照常返回客户端,不进 loop,不被吞。
//!
//! 复用:converter::convert_request(回灌)、provider.call_api_stream、EventStreamDecoder、
//! websearch::{create_mcp_request, call_mcp_api, parse_search_results, generate_search_summary}。

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use futures::{StreamExt, stream};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::kiro::model::events::Event;
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::kiro::provider::KiroProvider;
use crate::token;

use super::converter::{ConversionError, convert_request, get_context_window_size};
use super::handlers::{UsageRecordHook, map_provider_error};
use super::stream::SseEvent;
use super::types::{ErrorResponse, Message, MessagesRequest};
use super::websearch::{self, WebSearchResults};

/// 最大搜索轮次上限,防上游反复要搜索导致死循环
const MAX_WEB_SEARCH_ROUNDS: usize = 5;

/// 一轮上游响应缓冲解码的结果
struct RoundOutcome {
    /// 累积的助手文本
    text: String,
    /// 本轮完整的 tool_use(name 已经过 tool_name_map 还原)
    tool_uses: Vec<DecodedToolUse>,
    /// 从 contextUsageEvent 计算的实际输入 tokens
    context_input_tokens: Option<i32>,
    /// meteringEvent 累计 credits
    credits: f64,
    /// stop_reason 覆写(max_tokens / model_context_window_exceeded)
    stop_reason_override: Option<String>,
}

/// 一个已解码完成的 tool_use
struct DecodedToolUse {
    id: String,
    name: String,
    input: Value,
}

impl DecodedToolUse {
    fn query(&self) -> String {
        self.input
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }
}

/// 判断本轮是否应继续搜索(进入下一轮 loop)
///
/// 继续条件:本轮 tool_use 全部是 web_search(至少一个) 且 未达轮次上限。
/// 一旦混入 exec 等客户端工具、没有任何 tool_use、或已达上限,就终止并 flush(exec 永不被吞)。
fn should_search_round(round_idx: usize, tool_uses: &[DecodedToolUse]) -> bool {
    let only_web_search =
        !tool_uses.is_empty() && tool_uses.iter().all(|t| t.name == "web_search");
    only_web_search && round_idx < MAX_WEB_SEARCH_ROUNDS
}

/// 缓冲解码上游一轮流式响应
async fn decode_round(
    response: reqwest::Response,
    model: &str,
    tool_name_map: &std::collections::HashMap<String, String>,
) -> RoundOutcome {
    let mut body_stream = response.bytes_stream();
    let mut decoder = EventStreamDecoder::new();

    let mut text = String::new();
    // id -> (name, json_buffer)，保持出现顺序
    let mut buffers: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut tool_uses: Vec<DecodedToolUse> = Vec::new();
    let mut context_input_tokens: Option<i32> = None;
    let mut credits = 0.0;
    let mut stop_reason_override: Option<String> = None;

    while let Some(chunk) = body_stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("web_search loop 读取响应流失败: {}", e);
                break;
            }
        };
        if let Err(e) = decoder.feed(&chunk) {
            tracing::warn!("缓冲区溢出: {}", e);
        }
        for result in decoder.decode_iter() {
            let frame = match result {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!("解码事件失败: {}", e);
                    continue;
                }
            };
            let event = match Event::from_frame(frame) {
                Ok(ev) => ev,
                Err(_) => continue,
            };
            match event {
                Event::AssistantResponse(resp) => text.push_str(&resp.content),
                Event::ToolUse(tu) => {
                    let entry = buffers.entry(tu.tool_use_id.clone()).or_insert_with(|| {
                        order.push(tu.tool_use_id.clone());
                        (String::new(), String::new())
                    });
                    if entry.0.is_empty() {
                        entry.0 = tu.name.clone();
                    }
                    entry.1.push_str(&tu.input);
                }
                Event::ContextUsage(cu) => {
                    let window = get_context_window_size(model);
                    let actual = (cu.context_usage_percentage * (window as f64) / 100.0) as i32;
                    context_input_tokens = Some(actual);
                    if cu.context_usage_percentage >= 100.0 {
                        stop_reason_override = Some("model_context_window_exceeded".to_string());
                    }
                }
                Event::Metering(m) => credits += m.usage,
                Event::Exception { exception_type, .. } => {
                    if exception_type == "ContentLengthExceededException" {
                        stop_reason_override = Some("max_tokens".to_string());
                    }
                }
                _ => {}
            }
        }
    }

    // 按出现顺序组装完整 tool_use(还原 tool_name_map 短名)
    for id in order {
        if let Some((name, buf)) = buffers.remove(&id) {
            let input: Value = if buf.is_empty() {
                json!({})
            } else {
                serde_json::from_str(&buf).unwrap_or_else(|e| {
                    tracing::warn!("工具输入 JSON 解析失败: {}", e);
                    json!({})
                })
            };
            let original_name = tool_name_map.get(&name).cloned().unwrap_or(name);
            tool_uses.push(DecodedToolUse {
                id,
                name: original_name,
                input,
            });
        }
    }

    RoundOutcome {
        text,
        tool_uses,
        context_input_tokens,
        credits,
        stop_reason_override,
    }
}

/// 执行一轮上游调用(转换 + 流式请求 + 缓冲解码)
///
/// 上游/转换失败时返回 Err(已构造好的透传错误 Response)
async fn run_round(
    provider: &Arc<KiroProvider>,
    payload: &MessagesRequest,
    hook: &UsageRecordHook,
    fallback_input_tokens: i32,
) -> Result<(RoundOutcome, u64), Response> {
    let conversion = match convert_request(payload) {
        Ok(c) => c,
        Err(e) => {
            let (et, msg) = match &e {
                ConversionError::UnsupportedModel(m) => {
                    ("invalid_request_error", format!("模型不支持: {}", m))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
                }
            };
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new(et, msg))).into_response());
        }
    };

    let kiro_request = KiroRequest {
        conversation_state: conversion.conversation_state,
        profile_arn: None,
        additional_model_request_fields: conversion.additional_model_request_fields,
    };
    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(b) => b,
        Err(e) => {
            hook.record(0, 0, 0, 0, 0, 0.0, "error");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("internal_error", format!("序列化请求失败: {}", e))),
            )
                .into_response());
        }
    };

    let call_result = match provider.call_api_stream(&request_body, None).await {
        Ok(r) => r,
        Err(e) => {
            hook.record(0, fallback_input_tokens, 0, 0, 0, 0.0, "error");
            return Err(map_provider_error(e));
        }
    };
    let credential_id = call_result.credential_id;
    let outcome =
        decode_round(call_result.response, &payload.model, &conversion.tool_name_map).await;
    Ok((outcome, credential_id))
}

/// 把一轮 assistant(text + web_search tool_use) + user(tool_result) 回灌进 payload.messages,
/// 并把 server_tool_use + web_search_tool_result block(契约A 字段)追加到 presentation。
///
/// `searched` 与 `round.tool_uses` 一一对应(同序),已预先搜索完成。
fn append_search_round(
    payload: &mut MessagesRequest,
    round: &RoundOutcome,
    searched: &[Option<WebSearchResults>],
    presentation: &mut Vec<Value>,
) {
    // assistant:文本 + 本轮 web_search tool_use(Kiro 历史需要 tool_use<->tool_result 配对)
    let mut assistant_content: Vec<Value> = Vec::new();
    if !round.text.is_empty() {
        assistant_content.push(json!({"type": "text", "text": round.text}));
    }
    for tu in &round.tool_uses {
        assistant_content.push(json!({
            "type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input
        }));
    }
    payload.messages.push(Message {
        role: "assistant".to_string(),
        content: Value::Array(assistant_content),
    });

    // user:每个 web_search tool_use 配一个 tool_result(内容=搜索摘要,给上游看)
    let mut user_content: Vec<Value> = Vec::new();
    for (tu, results) in round.tool_uses.iter().zip(searched.iter()) {
        let query = tu.query();
        let summary = websearch::generate_search_summary(&query, results);
        user_content.push(json!({
            "type": "tool_result", "tool_use_id": tu.id, "content": summary
        }));

        // 客户端呈现:server_tool_use + web_search_tool_result(契约A)
        let (srv_id, _mcp) = websearch::create_mcp_request(&query);
        presentation.push(json!({
            "type": "server_tool_use", "id": srv_id, "name": "web_search",
            "input": {"query": query}
        }));
        // 契约A:web_search_tool_result 只有 type + content(无 tool_use_id),与 generate_websearch_events 一致
        presentation.push(json!({
            "type": "web_search_tool_result",
            "content": build_result_block(results)
        }));
    }
    payload.messages.push(Message {
        role: "user".to_string(),
        content: Value::Array(user_content),
    });
}

/// 把搜索结果转成 web_search_result block 数组(契约A 字段)
fn build_result_block(results: &Option<WebSearchResults>) -> Vec<Value> {
    match results {
        Some(r) => r
            .results
            .iter()
            .map(|item| {
                let page_age = item.published_date.and_then(|ms| {
                    chrono::DateTime::from_timestamp_millis(ms)
                        .map(|dt| dt.format("%B %-d, %Y").to_string())
                });
                json!({
                    "type": "web_search_result",
                    "title": item.title,
                    "url": item.url,
                    "encrypted_content": item.snippet.clone().unwrap_or_default(),
                    "page_age": page_age
                })
            })
            .collect(),
        None => vec![],
    }
}

/// web_search loop 主入口
///
/// `stream_client`:客户端要 SSE(true)还是一次性 JSON(false)。
pub(super) async fn run_web_search_loop(
    provider: Arc<KiroProvider>,
    mut payload: MessagesRequest,
    hook: UsageRecordHook,
    stream_client: bool,
) -> Response {
    let fallback_input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system.clone(),
        payload.messages.clone(),
        payload.tools.clone(),
    ) as i32;

    let mut presentation: Vec<Value> = Vec::new();
    let mut last_credential_id: u64 = 0;
    let mut last_context_input: Option<i32> = None;
    let mut total_credits = 0.0;

    for round_idx in 0..=MAX_WEB_SEARCH_ROUNDS {
        let (round, credential_id) =
            match run_round(&provider, &payload, &hook, fallback_input_tokens).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
        last_credential_id = credential_id;
        last_context_input = round.context_input_tokens.or(last_context_input);
        total_credits += round.credits;

        if should_search_round(round_idx, &round.tool_uses) {
            // 真搜索:任一失败 -> 透传错误,绝不静默成 "No results found"
            let mut searched: Vec<Option<WebSearchResults>> = Vec::with_capacity(round.tool_uses.len());
            for tu in &round.tool_uses {
                let (_id, mcp_request) = websearch::create_mcp_request(&tu.query());
                match websearch::call_mcp_api(&provider, &mcp_request).await {
                    Ok(resp) => searched.push(websearch::parse_search_results(&resp)),
                    Err(e) => {
                        tracing::warn!("web_search MCP 调用失败: {}", e);
                        hook.record(
                            last_credential_id,
                            fallback_input_tokens,
                            0,
                            0,
                            0,
                            total_credits,
                            "error",
                        );
                        return map_provider_error(e);
                    }
                }
            }
            append_search_round(&mut payload, &round, &searched, &mut presentation);
            continue;
        }

        // 终止:本轮不是"纯 web_search",或已达上限 -> flush 给客户端
        let stop_reason = round.stop_reason_override.clone().unwrap_or_else(|| {
            if round.tool_uses.is_empty() {
                "end_turn".to_string()
            } else {
                "tool_use".to_string()
            }
        });
        let final_input = last_context_input.unwrap_or(fallback_input_tokens);

        // 最终 content:呈现 block(逐轮搜索) + 终轮文本 + 终轮 tool_use(exec 等,原样返回)
        let mut content: Vec<Value> = presentation.clone();
        if !round.text.is_empty() {
            content.push(json!({"type": "text", "text": round.text}));
        }
        for tu in &round.tool_uses {
            content.push(json!({
                "type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input
            }));
        }

        let output_tokens = token::estimate_output_tokens(&content);
        hook.record(
            last_credential_id,
            final_input,
            output_tokens,
            0,
            0,
            total_credits,
            "success",
        );

        return if stream_client {
            render_sse(&payload.model, content, &stop_reason, final_input, output_tokens)
        } else {
            render_json(&payload.model, content, &stop_reason, final_input, output_tokens)
        };
    }

    // 理论不可达(循环内必返回)
    hook.record(last_credential_id, fallback_input_tokens, 0, 0, 0, total_credits, "error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse::new("internal_error", "web_search loop 异常退出")),
    )
        .into_response()
}

/// 一次性 JSON 响应(非流式)
fn render_json(
    model: &str,
    content: Vec<Value>,
    stop_reason: &str,
    input_tokens: i32,
    output_tokens: i32,
) -> Response {
    let body = json!({
        "id": format!("msg_{}", Uuid::new_v4().to_string().replace('-', "")),
        "type": "message",
        "role": "assistant",
        "content": content,
        "model": model,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0
        }
    });
    (StatusCode::OK, Json(body)).into_response()
}

/// SSE 响应(流式):把最终 content 拆成 Anthropic content_block 事件序列
fn render_sse(
    model: &str,
    content: Vec<Value>,
    stop_reason: &str,
    input_tokens: i32,
    output_tokens: i32,
) -> Response {
    let events = build_sse_events(model, content, stop_reason, input_tokens, output_tokens);
    let stream = stream::iter(
        events
            .into_iter()
            .map(|e| Ok::<Bytes, Infallible>(Bytes::from(e.to_sse_string()))),
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// 把最终 content 数组渲染成 SSE 事件序列
fn build_sse_events(
    model: &str,
    content: Vec<Value>,
    stop_reason: &str,
    input_tokens: i32,
    output_tokens: i32,
) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let message_id = format!(
        "msg_{}",
        Uuid::new_v4().to_string().replace('-', "")[..24].to_string()
    );

    events.push(SseEvent::new(
        "message_start",
        json!({
            "type": "message_start",
            "message": {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": null,
                "stop_sequence": null,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0
                }
            }
        }),
    ));

    for (index, block) in content.iter().enumerate() {
        let index = index as i32;
        let btype = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match btype {
            "text" => {
                let text = block.get("text").and_then(|v| v.as_str()).unwrap_or("");
                events.push(SseEvent::new("content_block_start", json!({
                    "type": "content_block_start", "index": index,
                    "content_block": {"type": "text", "text": ""}
                })));
                events.push(SseEvent::new("content_block_delta", json!({
                    "type": "content_block_delta", "index": index,
                    "delta": {"type": "text_delta", "text": text}
                })));
                events.push(SseEvent::new("content_block_stop", json!({
                    "type": "content_block_stop", "index": index
                })));
            }
            "tool_use" => {
                let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let input = block.get("input").cloned().unwrap_or_else(|| json!({}));
                let partial = serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string());
                events.push(SseEvent::new("content_block_start", json!({
                    "type": "content_block_start", "index": index,
                    "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}
                })));
                events.push(SseEvent::new("content_block_delta", json!({
                    "type": "content_block_delta", "index": index,
                    "delta": {"type": "input_json_delta", "partial_json": partial}
                })));
                events.push(SseEvent::new("content_block_stop", json!({
                    "type": "content_block_stop", "index": index
                })));
            }
            "server_tool_use" | "web_search_tool_result" => {
                events.push(SseEvent::new("content_block_start", json!({
                    "type": "content_block_start", "index": index,
                    "content_block": block
                })));
                events.push(SseEvent::new("content_block_stop", json!({
                    "type": "content_block_stop", "index": index
                })));
            }
            _ => {}
        }
    }

    events.push(SseEvent::new("message_delta", json!({
        "type": "message_delta",
        "delta": {"stop_reason": stop_reason},
        "usage": {"output_tokens": output_tokens}
    })));
    events.push(SseEvent::new("message_stop", json!({"type": "message_stop"})));

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::websearch::{WebSearchResult, WebSearchResults};

    fn tu(name: &str) -> DecodedToolUse {
        DecodedToolUse {
            id: format!("toolu_{}", name),
            name: name.to_string(),
            input: json!({"query": "rust 2026"}),
        }
    }

    // ---- should_search_round: 命中 / 不进 / 达上限 ----

    #[test]
    fn round_with_only_web_search_continues() {
        // 命中:本轮全是 web_search 且未达上限 -> 继续搜索
        let tools = vec![tu("web_search"), tu("web_search")];
        assert!(should_search_round(0, &tools));
        assert!(should_search_round(MAX_WEB_SEARCH_ROUNDS - 1, &tools));
    }

    #[test]
    fn round_with_exec_does_not_enter_loop() {
        // 不进:混入 exec(非 web_search)-> 终止,exec 原样返回客户端
        let mixed = vec![tu("web_search"), tu("exec")];
        assert!(!should_search_round(0, &mixed));
        // 纯 exec 同理
        let exec_only = vec![tu("exec")];
        assert!(!should_search_round(0, &exec_only));
    }

    #[test]
    fn round_with_no_tool_use_does_not_enter_loop() {
        // 不进:没有任何 tool_use(纯文本回答)-> 终止
        let empty: Vec<DecodedToolUse> = vec![];
        assert!(!should_search_round(0, &empty));
    }

    #[test]
    fn round_at_limit_stops_even_if_web_search() {
        // 达上限:即便本轮全是 web_search,到上限也必须停(防死循环)
        let tools = vec![tu("web_search")];
        assert!(!should_search_round(MAX_WEB_SEARCH_ROUNDS, &tools));
        assert!(!should_search_round(MAX_WEB_SEARCH_ROUNDS + 1, &tools));
    }

    // ---- build_result_block: 搜索结果 -> 契约A web_search_result 字段 ----

    #[test]
    fn result_block_maps_contract_a_fields() {
        let results = WebSearchResults {
            results: vec![WebSearchResult {
                title: "Rust 1.99".to_string(),
                url: "https://example.com/rust".to_string(),
                snippet: Some("Rust 1.99 released".to_string()),
                published_date: None,
                id: None,
                domain: None,
                max_verbatim_word_limit: None,
                public_domain: None,
            }],
            total_results: Some(1),
            query: Some("rust".to_string()),
            error: None,
        };
        let block = build_result_block(&Some(results));
        assert_eq!(block.len(), 1);
        assert_eq!(block[0]["type"], "web_search_result");
        assert_eq!(block[0]["title"], "Rust 1.99");
        assert_eq!(block[0]["url"], "https://example.com/rust");
        assert_eq!(block[0]["encrypted_content"], "Rust 1.99 released");
    }

    #[test]
    fn result_block_none_is_empty() {
        // 无结果 -> 空 block(不伪造内容)
        assert!(build_result_block(&None).is_empty());
    }

    // ---- 搜索失败透传:MCP 调用 Err 必须映射成错误响应,绝不静默成 200 "No results found" ----

    #[test]
    fn mcp_failure_maps_to_error_response_not_silent_success() {
        // loop 在 call_mcp_api 返回 Err 时直接 `return map_provider_error(e)`,
        // 早于任何 generate_search_summary,因此搜索失败永远不会变成成功的摘要响应。
        // 这里验证 map_provider_error 对通用 MCP 错误返回非 2xx(BAD_GATEWAY),
        // 而不是 200,证明透传链路不会假绿。
        let err = anyhow::anyhow!("MCP error: -1 - upstream unavailable");
        let resp = map_provider_error(err);
        assert!(
            !resp.status().is_success(),
            "MCP 搜索失败必须返回错误状态,不能静默成功"
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    // ---- build_sse_events: 呈现 server_tool_use + result,且 exec tool_use 不被吞 ----

    #[test]
    fn sse_events_render_search_presentation_and_keep_exec() {
        let content = vec![
            json!({"type": "server_tool_use", "id": "srvtoolu_x", "name": "web_search", "input": {"query": "q"}}),
            json!({"type": "web_search_tool_result", "content": []}),
            json!({"type": "text", "text": "done"}),
            json!({"type": "tool_use", "id": "toolu_exec", "name": "exec", "input": {"cmd": "ls"}}),
        ];
        let events = build_sse_events("claude-sonnet-4-8", content, "tool_use", 10, 5);

        // 必含 message_start / message_delta(stop_reason) / message_stop
        assert_eq!(events.first().unwrap().event, "message_start");
        assert_eq!(events.last().unwrap().event, "message_stop");
        let delta = events.iter().find(|e| e.event == "message_delta").unwrap();
        assert_eq!(delta.data["delta"]["stop_reason"], "tool_use");

        // server_tool_use block 被原样放进 content_block_start
        let has_server_tool = events.iter().any(|e| {
            e.event == "content_block_start"
                && e.data["content_block"]["type"] == "server_tool_use"
        });
        assert!(has_server_tool, "server_tool_use block 应被呈现");

        // web_search_tool_result block 被呈现
        let has_result = events.iter().any(|e| {
            e.event == "content_block_start"
                && e.data["content_block"]["type"] == "web_search_tool_result"
        });
        assert!(has_result, "web_search_tool_result block 应被呈现");

        // exec tool_use 没有被吞:start 里出现 name=exec
        let has_exec = events.iter().any(|e| {
            e.event == "content_block_start"
                && e.data["content_block"]["type"] == "tool_use"
                && e.data["content_block"]["name"] == "exec"
        });
        assert!(has_exec, "exec tool_use 必须原样返回客户端,不被吞");
    }
}

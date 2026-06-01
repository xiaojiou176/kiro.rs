//! Kiro 端点抽象
//!
//! 不同 Kiro 端点（如 `ide` / `cli`）在 URL、请求头、请求体上存在差异，
//! 但共享凭据池、Token 刷新、重试逻辑和 AWS event-stream 响应解码。
//!
//! [`KiroEndpoint`] 抽象了请求侧的差异点；`KiroProvider` 持有一个 endpoint 注册表，
//! 按凭据的 `endpoint` 字段选择对应实现。

use reqwest::RequestBuilder;

use crate::kiro::model::credentials::KiroCredentials;
use crate::model::config::Config;

pub mod cli;
pub mod ide;

pub use cli::CliEndpoint;
pub use ide::IdeEndpoint;

/// Kiro 端点
///
/// 同一个 `KiroProvider` 可持有多个 endpoint 实现，按凭据级字段切换。
pub trait KiroEndpoint: Send + Sync {
    /// 端点名称（对应 credentials.endpoint / config.defaultEndpoint 的取值）
    fn name(&self) -> &'static str;

    /// API 请求的 Content-Type（默认 application/json）
    fn content_type(&self) -> &'static str {
        "application/json"
    }

    /// API endpoint URL
    fn api_url(&self, ctx: &RequestContext<'_>) -> String;

    /// MCP endpoint URL
    fn mcp_url(&self, ctx: &RequestContext<'_>) -> String;

    /// 装饰 API 请求的端点特有 header
    ///
    /// Provider 已经设置好 URL、content-type、Connection 和 body；
    /// 实现负责追加 Authorization、host、user-agent 等端点相关头。
    fn decorate_api(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder;

    /// 装饰 MCP 请求的端点特有 header
    fn decorate_mcp(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder;

    /// 对已序列化的 API 请求体做端点特有加工（如注入 profileArn）
    fn transform_api_body(&self, body: &str, ctx: &RequestContext<'_>) -> String;

    /// 对已序列化的 MCP 请求体做端点特有加工（默认不变）
    fn transform_mcp_body(&self, body: &str, _ctx: &RequestContext<'_>) -> String {
        body.to_string()
    }

    /// 判断响应体是否表示"月度配额用尽"（禁用凭据并转移）
    fn is_monthly_request_limit(&self, body: &str) -> bool {
        default_is_monthly_request_limit(body)
    }

    /// 判断响应体是否表示"上游 bearer token 失效"（触发强制刷新）
    fn is_bearer_token_invalid(&self, body: &str) -> bool {
        default_is_bearer_token_invalid(body)
    }

    /// 判断响应体是否表示"账号级临时风控"（429 + suspicious activity）
    ///
    /// 与普通 429（high traffic）区分：账号级风控只针对当前凭据生效，
    /// 故障转移到其它凭据后可立即恢复；普通 429 是上游全局过载，切换无意义。
    fn is_account_throttled(&self, body: &str) -> bool {
        default_is_account_throttled(body)
    }
}

/// 装饰请求时可用的上下文
///
/// 包含单次调用已确定的所有运行时信息。引用形式避免无谓 clone。
pub struct RequestContext<'a> {
    /// 当前凭据
    pub credentials: &'a KiroCredentials,
    /// 有效的 access token（API Key 凭据下即 kiroApiKey）
    pub token: &'a str,
    /// 当前凭据对应的 machineId
    pub machine_id: &'a str,
    /// 全局配置
    pub config: &'a Config,
}

/// 触发"额度耗尽 → 禁用并切换"的 reason 取值集合
///
/// - `MONTHLY_REQUEST_COUNT`: 月度请求额度用尽
/// - `OVERAGE_REQUEST_LIMIT_EXCEEDED`: 超额（overage）额度也耗尽
///
/// 两类语义都是「该凭据当前计费周期内不能再用」，处理方式一致：
/// 立刻禁用凭据并故障转移到下一个可用凭据。
const QUOTA_EXHAUSTED_REASONS: &[&str] = &[
    "MONTHLY_REQUEST_COUNT",
    "OVERAGE_REQUEST_LIMIT_EXCEEDED",
];

/// 默认的"请求额度耗尽"判断逻辑
///
/// 同时识别顶层 `reason` 字段和嵌套 `error.reason` 字段。
/// 任一已知额度耗尽 reason 命中即返回 true。
pub fn default_is_monthly_request_limit(body: &str) -> bool {
    // 先快速字符串扫描，避免对 99% 不命中的响应体做 JSON 解析
    if QUOTA_EXHAUSTED_REASONS.iter().any(|r| body.contains(r)) {
        // 进一步用 JSON 解析确认 reason 字段而非偶然出现的子串
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
            let top = value.get("reason").and_then(|v| v.as_str());
            let nested = value.pointer("/error/reason").and_then(|v| v.as_str());
            return [top, nested]
                .into_iter()
                .flatten()
                .any(|r| QUOTA_EXHAUSTED_REASONS.contains(&r));
        }
        // body 是非 JSON 但包含关键词（兼容简单文本响应）
        return true;
    }
    false
}

/// 默认的 bearer token 失效判断逻辑
pub fn default_is_bearer_token_invalid(body: &str) -> bool {
    body.contains("The bearer token included in the request is invalid")
}

/// 默认的账号级风控判断逻辑
///
/// 上游 Kiro/Q-Developer 风控会返回 429 + 类似：
/// `Due to suspicious activity, we are imposing temporary limits on how
/// frequently your account (d-...) can send a request to Kiro while we investigate.`
///
/// 与普通 429（high traffic / rate limit exceeded）的关键差异是
/// 提到 "suspicious activity" 与具体账号 ID。
pub fn default_is_account_throttled(body: &str) -> bool {
    body.contains("suspicious activity")
        && body.contains("temporary limits")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_monthly_request_limit_detects_reason() {
        let body = r#"{"message":"You have reached the limit.","reason":"MONTHLY_REQUEST_COUNT"}"#;
        assert!(default_is_monthly_request_limit(body));
    }

    #[test]
    fn test_default_monthly_request_limit_nested_reason() {
        let body = r#"{"error":{"reason":"MONTHLY_REQUEST_COUNT"}}"#;
        assert!(default_is_monthly_request_limit(body));
    }

    #[test]
    fn test_default_monthly_request_limit_false() {
        let body = r#"{"message":"nope","reason":"DAILY_REQUEST_COUNT"}"#;
        assert!(!default_is_monthly_request_limit(body));
    }

    #[test]
    fn test_default_quota_exhausted_overage() {
        let body = r#"{"message":"You have reached the limit for overages.","reason":"OVERAGE_REQUEST_LIMIT_EXCEEDED"}"#;
        assert!(default_is_monthly_request_limit(body));
    }

    #[test]
    fn test_default_quota_exhausted_overage_nested() {
        let body = r#"{"error":{"reason":"OVERAGE_REQUEST_LIMIT_EXCEEDED"}}"#;
        assert!(default_is_monthly_request_limit(body));
    }

    #[test]
    fn test_default_quota_exhausted_substring_does_not_false_match() {
        // 关键字出现在普通字段而非 reason 字段：仍然命中（向后兼容旧行为）
        // 但 reason 字段是其他值时应严格不命中
        let body =
            r#"{"message":"some text MONTHLY_REQUEST_COUNT-like phrase","reason":"OTHER"}"#;
        assert!(!default_is_monthly_request_limit(body));
    }

    #[test]
    fn test_default_bearer_token_invalid() {
        assert!(default_is_bearer_token_invalid(
            "The bearer token included in the request is invalid"
        ));
        assert!(!default_is_bearer_token_invalid("unrelated error"));
    }

    #[test]
    fn test_default_is_account_throttled() {
        let body = r#"{"message":"Due to suspicious activity, we are imposing temporary limits on how frequently your account (d-9067c98495.84f894a8) can send a request to Kiro while we investigate.","reason":null}"#;
        assert!(default_is_account_throttled(body));
        // 普通 429 不应被识别为账号风控
        assert!(!default_is_account_throttled(
            "{\"message\":\"Too many requests\"}"
        ));
        // 仅有一半关键词时也不命中
        assert!(!default_is_account_throttled("suspicious activity detected"));
    }
}

//! Kiro CLI 端点（Amazon Q for CLI）
//!
//! 对应 Kiro CLI / Amazon Q for CLI 使用的 AWS JSON 协议端点：
//! - URL: `https://q.{api_region}.amazonaws.com/`（根路径 + x-amz-target 头）
//! - Content-Type: `application/x-amz-json-1.0`
//! - User-Agent: aws-sdk-rust 格式
//! - 请求体 origin: `KIRO_CLI`
//!
//! 适用于使用 `ksk_` 前缀 API Key 的凭据。

use reqwest::RequestBuilder;
use uuid::Uuid;

use super::{KiroEndpoint, RequestContext};

pub const CLI_ENDPOINT_NAME: &str = "cli";

pub struct CliEndpoint;

impl CliEndpoint {
    pub fn new() -> Self {
        Self
    }

    fn api_region<'a>(&self, ctx: &'a RequestContext<'_>) -> &'a str {
        ctx.credentials.effective_api_region(ctx.config)
    }

    fn host(&self, ctx: &RequestContext<'_>) -> String {
        if ctx.config.runtime_endpoint {
            // 现役 Kiro CLI 推理端点（实测：apikey 仍免费、429 更低）
            format!("runtime.{}.kiro.dev", self.api_region(ctx))
        } else {
            format!("q.{}.amazonaws.com", self.api_region(ctx))
        }
    }

    fn user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.16551 os/{} lang/rust/1.92.0 md/appVersion-{} app/AmazonQ-For-CLI",
            ctx.config.system_version, ctx.config.cli_version,
        )
    }

    fn x_amz_user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.16551 os/{} lang/rust/1.92.0 m/F app/AmazonQ-For-CLI",
            ctx.config.system_version,
        )
    }
}

impl Default for CliEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl KiroEndpoint for CliEndpoint {
    fn name(&self) -> &'static str {
        CLI_ENDPOINT_NAME
    }

    fn content_type(&self) -> &'static str {
        "application/x-amz-json-1.0"
    }

    fn api_url(&self, ctx: &RequestContext<'_>) -> String {
        format!("https://{}/", self.host(ctx))
    }

    fn mcp_url(&self, ctx: &RequestContext<'_>) -> String {
        // 指纹对齐真实 Kiro CLI V3：web_search/MCP 走 runtime 根路径 `/` + x-amz-target
        // `InvokeMCP`（AWS json-1.0 包装），不是 `/mcp` 子路径裸 JSON-RPC。
        format!("https://{}/", self.host(ctx))
    }

    fn decorate_api(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header(
                "x-amz-target",
                "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
            )
            .header("x-amzn-codewhisperer-optout", "true")
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("accept", "*/*")
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        if ctx.credentials.is_api_key_credential() {
            req = req.header("tokentype", "API_KEY");
        }
        req
    }

    fn decorate_mcp(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header(
                "x-amz-target",
                "AmazonCodeWhispererStreamingService.InvokeMCP",
            )
            .header("x-amzn-codewhisperer-optout", "true")
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("accept", "*/*")
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        // 指纹对齐真实 V3 InvokeMCP：profileArn 走**请求体顶层字段**（见 transform_mcp_body），
        // 不再发 `x-amzn-kiro-profile-arn` header（真 V3 不发这个头）。
        if ctx.credentials.is_api_key_credential() {
            req = req.header("tokentype", "API_KEY");
        }
        req
    }

    fn transform_mcp_body(&self, body: &str, ctx: &RequestContext<'_>) -> String {
        // 真 V3 InvokeMCP 把 profileArn 作为请求体顶层字段（与 JSON-RPC 同级）注入。
        // IdC/Builder ID：streaming_profile_arn() 返回占位符 AAAACCCCXXXX（上游接受）。
        // API Key 凭据：streaming_profile_arn() 返回 None → inject_profile_arn 原样返回，
        // body 不含 profileArn（指纹不变量：api_key 的 MCP body 永不带 profileArn）。
        crate::kiro::endpoint::ide::inject_profile_arn(
            body,
            ctx.credentials.streaming_profile_arn().as_deref(),
        )
    }

    fn transform_api_body(&self, body: &str, ctx: &RequestContext<'_>) -> String {
        let body = set_origin_kiro_cli(body);
        // Builder ID / IdC 凭据：cli 端点也必须把 profileArn 注入请求体——上游
        // runtime 要求带 profileArn（占位符 AAAACCCCXXXX 也接受，原生 Kiro CLI 实测照发占位符即成功）。
        // 不发会被上游以 400 `profileArn is required` 拒。
        // API Key 凭据：streaming_profile_arn() 返回 None → inject_profile_arn 原样返回，不受影响。
        crate::kiro::endpoint::ide::inject_profile_arn(
            &body,
            ctx.credentials.streaming_profile_arn().as_deref(),
        )
    }
}

/// 将请求体转换为 KIRO_CLI 格式：
/// 1. 所有 "AI_EDITOR" origin 替换为 "KIRO_CLI"
/// 2. 移除 conversationState.agentContinuationId（Kiro CLI 不发送此字段）
/// 3. 移除 history 中用户消息的 modelId（Kiro CLI 不在历史消息里发送此字段）
fn set_origin_kiro_cli(body: &str) -> String {
    let body = body.replace("\"origin\":\"AI_EDITOR\"", "\"origin\":\"KIRO_CLI\"");

    let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&body) else {
        return body;
    };

    if let Some(state) = json
        .get_mut("conversationState")
        .and_then(|v| v.as_object_mut())
    {
        state.remove("agentContinuationId");

        if let Some(history) = state.get_mut("history").and_then(|v| v.as_array_mut()) {
            for msg in history.iter_mut() {
                if let Some(user_input) = msg
                    .get_mut("userInputMessage")
                    .and_then(|v| v.as_object_mut())
                {
                    user_input.remove("modelId");
                }
            }
        }
    }

    serde_json::to_string(&json).unwrap_or(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_origin_kiro_cli_current_message() {
        let body = r#"{"conversationState":{"currentMessage":{"userInputMessage":{"content":"hi","origin":"AI_EDITOR"}}}}"#;
        let result = set_origin_kiro_cli(body);
        assert!(result.contains("\"origin\":\"KIRO_CLI\""));
        assert!(!result.contains("\"origin\":\"AI_EDITOR\""));
    }

    #[test]
    fn test_set_origin_kiro_cli_history() {
        let body = r#"{"conversationState":{"history":[{"userInputMessage":{"content":"hi","origin":"AI_EDITOR"}},{"userInputMessage":{"content":"hello","origin":"AI_EDITOR"}}],"currentMessage":{"userInputMessage":{"origin":"AI_EDITOR"}}}}"#;
        let result = set_origin_kiro_cli(body);
        assert!(!result.contains("\"origin\":\"AI_EDITOR\""));
        assert_eq!(result.matches("\"origin\":\"KIRO_CLI\"").count(), 3);
    }

    #[test]
    fn test_set_origin_kiro_cli_no_origin() {
        let body = r#"{"conversationState":{}}"#;
        assert_eq!(set_origin_kiro_cli(body), r#"{"conversationState":{}}"#);
    }

    // ===== 指纹对齐回归测试（防止 UA/header 再次偏离真实 Kiro CLI V3）=====
    // 真实 Kiro CLI V3 (pty 抓包基线) 出站 UA：
    //   user-agent:       aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.16551 os/macos lang/rust/1.92.0 md/appVersion-2.8.1 app/AmazonQ-For-CLI
    //   x-amz-user-agent: ...lang/rust/1.92.0 m/F app/AmazonQ-For-CLI
    // 关键：均**不含** `exec-env/AmazonQ-For-CLI Version/2.7.0`（旧 bug，已删）。
    fn test_ctx<'a>(
        creds: &'a crate::kiro::model::credentials::KiroCredentials,
        cfg: &'a crate::model::config::Config,
    ) -> RequestContext<'a> {
        RequestContext { credentials: creds, token: "t", machine_id: "m", config: cfg }
    }

    #[test]
    fn fingerprint_ua_no_legacy_version_2_7_0() {
        let creds = crate::kiro::model::credentials::KiroCredentials::default();
        let cfg = crate::model::config::Config::default();
        let ep = CliEndpoint;
        let ua = ep.user_agent(&test_ctx(&creds, &cfg));
        let xua = ep.x_amz_user_agent(&test_ctx(&creds, &cfg));
        // 真 V3 不含这两段（指纹泄露点，删过一次，别再加回来）
        assert!(!ua.contains("Version/2.7.0"), "user-agent 含旧 Version/2.7.0: {ua}");
        assert!(!ua.contains("exec-env"), "user-agent 含 exec-env(真V3无): {ua}");
        assert!(!xua.contains("Version/2.7.0"), "x-amz-user-agent 含旧 Version/2.7.0: {xua}");
        assert!(!xua.contains("exec-env"), "x-amz-user-agent 含 exec-env: {xua}");
        // 仍保留真 V3 该有的核心标识
        assert!(ua.contains("api/codewhispererstreaming/0.1.16551"), "ua 缺核心标识: {ua}");
        assert!(ua.contains("app/AmazonQ-For-CLI"), "ua 缺 app 标识: {ua}");
        assert!(xua.contains("m/F app/AmazonQ-For-CLI"), "x-amz-ua 缺 m/F: {xua}");
    }

    // ===== B2: web_search/MCP 指纹对齐真 V3 InvokeMCP（含 G2 fitness-function）=====
    #[test]
    fn fingerprint_mcp_url_is_root_not_subpath() {
        // 真 V3 web_search 走 runtime 根路径 `/`，不是 `/mcp` 子路径
        let creds = crate::kiro::model::credentials::KiroCredentials::default();
        let cfg = crate::model::config::Config::default();
        let url = CliEndpoint.mcp_url(&test_ctx(&creds, &cfg));
        assert!(url.ends_with("/"), "mcp_url 应是根路径: {url}");
        assert!(!url.contains("/mcp"), "mcp_url 不应再走 /mcp 子路径: {url}");
    }

    #[test]
    fn fingerprint_decorate_mcp_has_invokemcp_target_optout_no_profilearn_header() {
        // 真 V3 InvokeMCP：带 x-amz-target=InvokeMCP + optout；profileArn 走 body 不走 header
        let creds = crate::kiro::model::credentials::KiroCredentials::default();
        let cfg = crate::model::config::Config::default();
        let client = reqwest::Client::new();
        let rb = client.post("https://runtime.us-east-1.kiro.dev/");
        let req = CliEndpoint
            .decorate_mcp(rb, &test_ctx(&creds, &cfg))
            .build()
            .expect("build req");
        let target = req.headers().get("x-amz-target").and_then(|v| v.to_str().ok());
        assert_eq!(
            target,
            Some("AmazonCodeWhispererStreamingService.InvokeMCP"),
            "decorate_mcp 应带 InvokeMCP x-amz-target"
        );
        assert_eq!(
            req.headers().get("x-amzn-codewhisperer-optout").and_then(|v| v.to_str().ok()),
            Some("true"),
            "decorate_mcp 应带 optout=true"
        );
        // profileArn 移进 body，header 不再带（真 V3 不发 x-amzn-kiro-profile-arn）
        assert!(
            req.headers().get("x-amzn-kiro-profile-arn").is_none(),
            "decorate_mcp 不应再发 x-amzn-kiro-profile-arn header（profileArn 走 body）"
        );
    }

    #[test]
    fn fitness_apikey_mcp_body_never_has_profilearn() {
        // 🔒 G2 fitness-function（焊死 archive R9-F20 的坑）：
        // api_key 凭据走 transform_mcp_body 后，body **永不**含 profileArn。
        let mut creds = crate::kiro::model::credentials::KiroCredentials::default();
        creds.auth_method = Some("api_key".to_string());
        creds.kiro_api_key = Some("ksk_test_dummy".to_string());
        let cfg = crate::model::config::Config::default();
        let raw = r#"{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"web_search","arguments":{"query":"x"}}}"#;
        let out = CliEndpoint.transform_mcp_body(raw, &test_ctx(&creds, &cfg));
        assert!(
            !out.contains("profileArn"),
            "🔴 fitness 违反：api_key 的 MCP body 不该含 profileArn（会重蹈 R9-F20 破坏 apikey）: {out}"
        );
    }

    #[test]
    fn builderid_mcp_body_injects_placeholder_profilearn() {
        // Builder ID/IdC 凭据：transform_mcp_body 把占位符 profileArn 注入 body 顶层（对齐真 V3）
        let creds = crate::kiro::model::credentials::KiroCredentials::default(); // 无 kiro_api_key = 非 api_key
        assert!(!creds.is_api_key_credential(), "默认 creds 应为非 api_key");
        let cfg = crate::model::config::Config::default();
        let raw = r#"{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"web_search","arguments":{"query":"x"}}}"#;
        let out = CliEndpoint.transform_mcp_body(raw, &test_ctx(&creds, &cfg));
        assert!(out.contains("profileArn"), "Builder ID 的 MCP body 应含 profileArn: {out}");
        assert!(
            out.contains("AAAACCCCXXXX"),
            "应注入占位符 profileArn（上游接受，原生 CLI 实测照发）: {out}"
        );
    }

    #[test]
    fn fingerprint_decorate_api_has_accept_no_connection() {
        // 真 V3 出站带 `accept: */*`，且不在 decorate 里设 Connection（keep-alive）。
        let creds = crate::kiro::model::credentials::KiroCredentials::default();
        let cfg = crate::model::config::Config::default();
        let client = reqwest::Client::new();
        let rb = client.post("https://runtime.us-east-1.kiro.dev/");
        let ep = CliEndpoint;
        let req = ep
            .decorate_api(rb, &test_ctx(&creds, &cfg))
            .build()
            .expect("build req");
        let accept = req.headers().get("accept").and_then(|v| v.to_str().ok());
        assert_eq!(accept, Some("*/*"), "decorate_api 应带 accept: */*");
        // decorate 层不设 Connection（出站 keep-alive，对齐真 V3）
        assert!(
            req.headers().get("connection").is_none(),
            "decorate_api 不应设 Connection 头（真 V3 无）"
        );
        // UA 同样不含 legacy 段
        let ua = req.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(!ua.contains("Version/2.7.0") && !ua.contains("exec-env"), "出站 UA 含 legacy: {ua}");
    }
}

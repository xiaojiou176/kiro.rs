//! Token 管理模块
//!
//! 负责 Token 过期检测和刷新，支持 Social 和 IdC 认证方式
//! 支持多凭据 (MultiTokenManager) 管理

use anyhow::bail;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as TokioMutex;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration as StdDuration, Instant};

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::kiro_version::USAGE_API_KIRO_VERSION;
use crate::kiro::machine_id;
use crate::kiro::account_learning::LearningStore;
use crate::kiro::rate_limiter::{AdaptiveConfig, AccountState, LimiterRegistry, ThrottleScope};
use crate::kiro::model::available_models::ListAvailableModelsResponse;
use crate::kiro::model::available_profiles::ListAvailableProfilesResponse;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::token_refresh::{
    IdcRefreshRequest, IdcRefreshResponse, RefreshRequest, RefreshResponse,
};
use crate::kiro::model::usage_limits::UsageLimitsResponse;
use crate::model::config::Config;

/// 检查 Token 是否在指定时间内过期
pub(crate) fn is_token_expiring_within(
    credentials: &KiroCredentials,
    minutes: i64,
) -> Option<bool> {
    credentials
        .expires_at
        .as_ref()
        .and_then(|expires_at| DateTime::parse_from_rfc3339(expires_at).ok())
        .map(|expires| expires <= Utc::now() + Duration::minutes(minutes))
}

/// 检查 Token 是否已过期（提前 5 分钟判断）
pub(crate) fn is_token_expired(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 5).unwrap_or(true)
}

/// 检查 Token 是否即将过期（10分钟内）
pub(crate) fn is_token_expiring_soon(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 10).unwrap_or(false)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// 生成 API Key 脱敏展示(前 4 + ... + 后 4,长度不足或非 ASCII 回退 ***)
fn mask_api_key(key: &str) -> String {
    if key.is_ascii() && key.len() > 16 {
        format!("{}...{}", &key[..4], &key[key.len() - 4..])
    } else {
        "***".to_string()
    }
}

/// 验证 refreshToken 的基本有效性
pub(crate) fn validate_refresh_token(credentials: &KiroCredentials) -> anyhow::Result<()> {
    let refresh_token = credentials
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;

    if refresh_token.is_empty() {
        bail!("refreshToken 为空");
    }

    if refresh_token.len() < 100 || refresh_token.ends_with("...") || refresh_token.contains("...")
    {
        bail!(
            "refreshToken 已被截断（长度: {} 字符）。\n\
             这通常是 Kiro IDE 为了防止凭证被第三方工具使用而故意截断的。",
            refresh_token.len()
        );
    }

    Ok(())
}

/// Refresh Token 永久失效错误
///
/// 当服务端返回 400 + `invalid_grant` 时，表示 refreshToken 已被撤销或过期，
/// 不应重试，需立即禁用对应凭据。
#[derive(Debug)]
pub(crate) struct RefreshTokenInvalidError {
    pub message: String,
}

impl fmt::Display for RefreshTokenInvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RefreshTokenInvalidError {}

/// 刷新 Token
pub(crate) async fn refresh_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    // API Key 凭据不支持 Token 刷新：底层契约级拦截
    // 其他调用点（try_ensure_token / 活跃路径 / add_credential）在调用前已显式分流 API Key；
    // 仅 force_refresh_token_for 未分流，此处 bail 让错误自然传播为 400 BAD_REQUEST。
    if credentials.is_api_key_credential() {
        bail!("API Key 凭据不支持刷新 Token");
    }

    validate_refresh_token(credentials)?;

    // 根据 auth_method 选择刷新方式
    // 如果未指定 auth_method，根据是否有 clientId/clientSecret 自动判断
    let auth_method = credentials.auth_method.as_deref().unwrap_or_else(|| {
        if credentials.client_id.is_some() && credentials.client_secret.is_some() {
            "idc"
        } else {
            "social"
        }
    });

    if auth_method.eq_ignore_ascii_case("idc")
        || auth_method.eq_ignore_ascii_case("builder-id")
        || auth_method.eq_ignore_ascii_case("iam")
    {
        refresh_idc_token(credentials, config, proxy).await
    } else {
        refresh_social_token(credentials, config, proxy).await
    }
}

/// 刷新 Social Token
async fn refresh_social_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 Social Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);

    let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);
    let refresh_domain = format!("prod.{}.auth.desktop.kiro.dev", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = crate::kiro::kiro_version::effective(&config.kiro_version);

    let client = build_client(proxy, 60, config.tls_backend)?;
    let body = RefreshRequest {
        refresh_token: refresh_token.to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("Accept", "application/json, text/plain, */*")
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("KiroIDE-{}-{}", kiro_version, machine_id),
        )
        .header("Accept-Encoding", "gzip, compress, deflate, br")
        .header("host", &refresh_domain)
        .header("Connection", "close")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        // 400 + invalid_grant + Invalid refresh token provided → refreshToken 永久失效
        if status.as_u16() == 400
            && body_text.contains("\"invalid_grant\"")
            && body_text.contains("Invalid refresh token provided")
        {
            return Err(RefreshTokenInvalidError {
                message: format!("Social refreshToken 已失效 (invalid_grant): {}", body_text),
            }
            .into());
        }

        let error_msg = match status.as_u16() {
            401 => "OAuth 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OAuth 服务暂时不可用",
            _ => "Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: RefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    Ok(new_credentials)
}

/// 刷新 IdC Token (AWS SSO OIDC)
async fn refresh_idc_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 IdC Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    let client_id = credentials
        .client_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientId"))?;
    let client_secret = credentials
        .client_secret
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientSecret"))?;

    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);
    let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let x_amz_user_agent = "aws-sdk-js/3.980.0 KiroIDE";
    let user_agent = format!(
        "aws-sdk-js/3.980.0 ua/2.1 os/{} lang/js md/nodejs#{} api/sso-oidc#3.980.0 m/E KiroIDE",
        os_name, node_version
    );

    let client = build_client(proxy, 60, config.tls_backend)?;
    let body = IdcRefreshRequest {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        refresh_token: refresh_token.to_string(),
        grant_type: "refresh_token".to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("content-type", "application/json")
        .header("x-amz-user-agent", x_amz_user_agent)
        .header("user-agent", &user_agent)
        .header("host", format!("oidc.{}.amazonaws.com", region))
        .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
        .header("amz-sdk-request", "attempt=1; max=4")
        .header("Connection", "close")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        // 400 + invalid_grant + Invalid refresh token provided → refreshToken 永久失效
        if status.as_u16() == 400
            && body_text.contains("\"invalid_grant\"")
            && body_text.contains("Invalid refresh token provided")
        {
            return Err(RefreshTokenInvalidError {
                message: format!("IdC refreshToken 已失效 (invalid_grant): {}", body_text),
            }
            .into());
        }

        let error_msg = match status.as_u16() {
            401 => "IdC 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OIDC 服务暂时不可用",
            _ => "IdC Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: IdcRefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    // 同步更新 profile_arn（如果 IdC 响应中包含）
    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    Ok(new_credentials)
}

/// 官方 Kiro 用量 / 模型 REST 接口（getUsageLimits / ListAvailableModels /
/// setUserPreference）仅在 `us-east-1` 与 `eu-central-1` 两个端点提供服务。
///
/// 依据凭据的 SSO 区域选择主端点，并返回另一个端点作为 403 回退候选：
/// - `eu-central-1` 或任何 `eu-*` 区域 → 主端点 `eu-central-1`
/// - 其余区域 → 主端点 `us-east-1`
///
/// 这样导入的 Enterprise / IAM Identity Center (IdC) 账号即使 SSO 区域不是
/// `us-east-1`，也能命中正确的端点，避免 `403 {"message":"Invalid token"}`。
fn rest_api_region_candidates(sso_region: &str) -> [&'static str; 2] {
    let primary_eu = sso_region == "eu-central-1" || sso_region.starts_with("eu-");
    if primary_eu {
        ["eu-central-1", "us-east-1"]
    } else {
        ["us-east-1", "eu-central-1"]
    }
}

/// 获取使用额度信息
pub(crate) async fn get_usage_limits(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<UsageLimitsResponse> {
    tracing::debug!("正在获取使用额度信息...");

    // getUsageLimits 仅在 us-east-1 / eu-central-1 提供服务，
    // 依据凭据 SSO 区域选择主端点，403 时回退到另一个端点。
    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    // 用量类接口固定用 USAGE_API_KIRO_VERSION：新版 IDE 会强制要求 profileArn，
    // 对 Enterprise/IdC 账号失败；该版本无需 profileArn。
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    // profileArn 查询串：仅发送真实 ARN，跳过 BuilderID 占位符
    let profile_arn_query = credentials
        .effective_profile_arn()
        .map(|arn| format!("&profileArn={}", urlencoding::encode(arn)))
        .unwrap_or_default();

    // 构建 User-Agent headers
    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = build_client(proxy, 60, config.tls_backend)?;

    let mut last_error: Option<String> = None;
    for (idx, region) in candidates.iter().enumerate() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!(
            "https://{}/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true{}",
            host, profile_arn_query
        );

        let mut request = client
            .get(&url)
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close");

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        }

        let response = request.send().await?;

        let status = response.status();
        if status.is_success() {
            let data: UsageLimitsResponse = response.json().await?;
            return Ok(data);
        }

        let body_text = response.text().await.unwrap_or_default();

        // 403 且仍有备用端点时，尝试下一个区域端点（Enterprise/IdC 跨区兼容）
        if status.as_u16() == 403 && idx + 1 < candidates.len() {
            tracing::debug!(
                "getUsageLimits 在 {} 返回 403，尝试备用端点 {}",
                region,
                candidates[idx + 1]
            );
            last_error = Some(format!("{} {}", status, body_text));
            continue;
        }

        let error_msg = match status.as_u16() {
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法获取使用额度",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "获取使用额度失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    // 所有候选端点均失败（理论上循环内已 return / bail，此处为兜底）
    bail!(
        "权限不足，无法获取使用额度: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

/// 获取该凭据当前可用的模型列表
///
/// 上游接口：`GET https://q.{api_region}.amazonaws.com/ListAvailableModels?origin=AI_EDITOR`
/// 返回值随订阅等级不同而不同（如 FREE 账号不含 Opus）。
/// 请求头与构造方式与 [`get_usage_limits`] 完全一致。
pub(crate) async fn get_available_models(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<ListAvailableModelsResponse> {
    tracing::debug!("正在获取可用模型列表...");

    // ListAvailableModels 仅在 us-east-1 / eu-central-1 提供服务，
    // 依据凭据 SSO 区域选择主端点，403 时回退到另一个端点。
    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    // profileArn 查询串：仅发送真实 ARN，跳过 BuilderID 占位符
    let profile_arn_query = credentials
        .effective_profile_arn()
        .map(|arn| format!("&profileArn={}", urlencoding::encode(arn)))
        .unwrap_or_default();

    // 构建 User-Agent headers（与 get_usage_limits 保持一致）
    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = build_client(proxy, 60, config.tls_backend)?;

    let mut last_error: Option<String> = None;
    for (idx, region) in candidates.iter().enumerate() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!(
            "https://{}/ListAvailableModels?origin=AI_EDITOR{}",
            host, profile_arn_query
        );

        let mut request = client
            .get(&url)
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close");

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        }

        let response = request.send().await?;

        let status = response.status();
        if status.is_success() {
            let data: ListAvailableModelsResponse = response.json().await?;
            return Ok(data);
        }

        let body_text = response.text().await.unwrap_or_default();

        // 403 且仍有备用端点时，尝试下一个区域端点（Enterprise/IdC 跨区兼容）
        if status.as_u16() == 403 && idx + 1 < candidates.len() {
            tracing::debug!(
                "ListAvailableModels 在 {} 返回 403，尝试备用端点 {}",
                region,
                candidates[idx + 1]
            );
            last_error = Some(format!("{} {}", status, body_text));
            continue;
        }

        let error_msg = match status.as_u16() {
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法获取可用模型",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "获取可用模型失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    // 所有候选端点均失败（理论上循环内已 return / bail，此处为兜底）
    bail!(
        "权限不足，无法获取可用模型: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

/// 获取该凭据可用的真实 profileArn 列表（`ListAvailableProfiles`）。
///
/// Enterprise / IAM Identity Center (IdC) 账号必须用真实 profileArn 调用流式端点；
/// 该 ARN 既不是 BuilderID 占位符，也不在 OIDC 刷新响应里返回，只能通过本接口获取。
///
/// 上游接口（AWS JSON 1.0，**与用量类的 REST GET 不同**）：
/// `POST https://q.{region}.amazonaws.com/`，请求头
/// `x-amz-target: AmazonCodeWhispererService.ListAvailableProfiles`，
/// `Content-Type: application/x-amz-json-1.0`，Body `{"maxResults":N}`。
///
/// 与 [`get_usage_limits`] 一样仅在 `us-east-1` / `eu-central-1` 提供服务，
/// 依据凭据 SSO 区域选择主端点，主端点未返回 profile 时回退到另一个端点。
pub(crate) async fn list_available_profiles(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<ListAvailableProfilesResponse> {
    tracing::debug!("正在获取可用 profile 列表...");

    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = build_client(proxy, 60, config.tls_backend)?;

    let mut last_error: Option<String> = None;
    let mut empty_seen = false;
    // 确定性「此账号类型上游不支持解析 profile」信号（如纯个人 Builder ID 收到
    // 403「... is not supported for this operation.」）。与「网络瞬态错」区分：
    // 确定性不支持 → 回退占位符且让调用方标记已尝试（重启前不再重试）；
    // 瞬态错 → bail! 让调用方下次再试。
    let mut definitive_unsupported = false;
    for region in candidates.iter() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!("https://{}/", host);

        let mut request = client
            .post(&url)
            .header("content-type", "application/x-amz-json-1.0")
            .header(
                "x-amz-target",
                "AmazonCodeWhispererService.ListAvailableProfiles",
            )
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close")
            .body(r#"{"maxResults":10}"#);

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        }

        let response = request.send().await?;
        let status = response.status();

        if status.is_success() {
            let data: ListAvailableProfilesResponse = response.json().await?;
            // 该区域无 profile 时尝试另一个区域端点（账号可能在 eu-central-1）
            if data.first_arn().is_none() {
                empty_seen = true;
                continue;
            }
            return Ok(data);
        }

        let body_text = response.text().await.unwrap_or_default();
        if is_definitive_profile_unsupported(status, &body_text) {
            definitive_unsupported = true;
        }
        last_error = Some(format!("{} {}", status, body_text));
        // 403 等错误继续尝试下一个候选端点
    }

    // 没有任何端点返回 profile：若至少有一次成功但为空，视为"该账号无 Enterprise profile"
    // （BuilderID 等），返回空结果让调用方回退到占位符逻辑。
    if empty_seen {
        return Ok(ListAvailableProfilesResponse::default());
    }

    // 所有候选端点都以「确定性不支持」拒绝（纯个人 Builder ID 等）：这不是瞬态错，
    // 而是上游对该账号类型的确定结论。返回空结果（=「无 Enterprise profile」），
    // 让调用方 `ensure_profile_arn` 走 Ok(None) 分支标记已尝试、回退占位符、
    // 不再每个请求重打一次 403。瞬态错仍走下面的 bail!。
    if definitive_unsupported {
        return Ok(ListAvailableProfilesResponse::default());
    }

    bail!(
        "获取可用 profile 失败: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

/// 判定一次 ListAvailableProfiles 响应是否是「确定性：上游不支持为此账号类型解析
/// profile」——区别于网络瞬态错（超时/连接失败/5xx）。
///
/// 确定性条件：HTTP 403（Forbidden / AccessDenied 语义）或响应体明确含
/// 「is not supported」「not supported for this operation」「Builder ID ... not
/// supported」之类措辞。这类错误重试多少次结果都一样，应回退占位符且不再重试。
pub(crate) fn is_definitive_profile_unsupported(
    status: reqwest::StatusCode,
    body: &str,
) -> bool {
    let lower = body.to_ascii_lowercase();
    let says_unsupported = lower.contains("is not supported")
        || lower.contains("not supported for this operation")
        || (lower.contains("builder id") && lower.contains("not supported"));
    // 403 = 上游确定性拒绝（个人 Builder ID 对该操作无权限）；或任意状态码但 body
    // 明确说「不支持」。两者都属于「重试无意义」的确定性结论。
    status == reqwest::StatusCode::FORBIDDEN || says_unsupported
}

/// 设置用户偏好（开启/关闭超额）
///
/// 上游接口：`POST https://q.{region}.amazonaws.com/setUserPreference`
/// Body: `{ "overageConfiguration": { "overageStatus": "ENABLED" | "DISABLED" }, "profileArn": "..." }`
pub(crate) async fn set_user_preference(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
    overage_status: &str, // "ENABLED" or "DISABLED"
) -> anyhow::Result<()> {
    tracing::debug!("正在设置用户偏好 overageStatus={}", overage_status);

    // setUserPreference 仅在 us-east-1 / eu-central-1 提供服务，
    // 依据凭据 SSO 区域选择主端点，403 时回退到另一个端点。
    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = build_client(proxy, 60, config.tls_backend)?;

    // 构建 body：仅发送真实 profileArn，跳过 BuilderID 占位符
    let body = if let Some(profile_arn) = credentials.effective_profile_arn() {
        serde_json::json!({
            "overageConfiguration": { "overageStatus": overage_status },
            "profileArn": profile_arn,
        })
    } else {
        serde_json::json!({
            "overageConfiguration": { "overageStatus": overage_status },
        })
    };

    let mut last_error: Option<String> = None;
    for (idx, region) in candidates.iter().enumerate() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!("https://{}/setUserPreference", host);

        let mut request = client
            .post(&url)
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("content-type", "application/json")
            .header("Connection", "close")
            .json(&body);

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        }

        let response = request.send().await?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let body_text = response.text().await.unwrap_or_default();

        // 403 且仍有备用端点时，尝试下一个区域端点（Enterprise/IdC 跨区兼容）
        if status.as_u16() == 403 && idx + 1 < candidates.len() {
            tracing::debug!(
                "setUserPreference 在 {} 返回 403，尝试备用端点 {}",
                region,
                candidates[idx + 1]
            );
            last_error = Some(format!("{} {}", status, body_text));
            continue;
        }

        let error_msg = match status.as_u16() {
            400 => "请求参数错误，账号可能不支持超额",
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法设置用户偏好",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "设置用户偏好失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    // 所有候选端点均失败（理论上循环内已 return / bail，此处为兜底）
    bail!(
        "权限不足，无法设置用户偏好: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

// ============================================================================
// 多凭据 Token 管理器
// ============================================================================

/// 单个凭据条目的状态
struct CredentialEntry {
    /// 凭据唯一 ID
    id: u64,
    /// 凭据信息
    credentials: KiroCredentials,
    /// API 调用连续失败次数
    failure_count: u32,
    /// API 调用累计失败次数（含所有失败类型：鉴权/额度/风控/瞬态/网络）。
    /// 只增不减，成功不清零，仅手动重置失败计数时归零。仅用于展示与排查。
    total_failure_count: u64,
    /// Token 刷新连续失败次数
    refresh_failure_count: u32,
    /// 是否已禁用
    disabled: bool,
    /// 禁用原因（用于区分手动禁用 vs 自动禁用，便于自愈）
    disabled_reason: Option<DisabledReason>,
    /// API 调用成功次数
    success_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    last_used_at: Option<String>,
    /// 临时冷却到期时间（账号级 429 风控触发后短期跳过该凭据）
    /// `Some(t)` 且 `t > now()` 时视为不可用；`t <= now()` 时自动恢复。
    /// 不持久化，进程重启后清空。
    throttled_until: Option<Instant>,
}

/// 禁用原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisabledReason {
    /// Admin API 手动禁用
    Manual,
    /// 连续失败达到阈值后自动禁用
    TooManyFailures,
    /// Token 刷新连续失败达到阈值后自动禁用
    TooManyRefreshFailures,
    /// 额度已用尽（如 MONTHLY_REQUEST_COUNT）
    QuotaExceeded,
    /// Refresh Token 永久失效（服务端返回 invalid_grant）
    InvalidRefreshToken,
    /// 凭据配置无效（如 authMethod=api_key 但缺少 kiroApiKey）
    InvalidConfig,
}

/// 统计数据持久化条目
#[derive(Serialize, Deserialize)]
struct StatsEntry {
    success_count: u64,
    #[serde(default)]
    total_failure_count: u64,
    last_used_at: Option<String>,
}

/// 会话亲和绑定条目（多号 + 强制 session affinity 的核心状态，持久化到 `session_affinity.json`）。
///
/// 时间用 RFC3339（wall-clock）存储：既便于人工观测，也能跨重启正确判断 TTL / 切号防抖。
#[derive(Clone, Serialize, Deserialize)]
struct AffinityBinding {
    /// 当前黏定的凭据 id
    credential_id: u64,
    /// 首次绑定时间
    bound_at: DateTime<Utc>,
    /// 最近一次活动时间（用于 TTL 释放）
    last_seen: DateTime<Utc>,
    /// 最近一次切号时间（用于切号防抖；从未切过为 None）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_switch_at: Option<DateTime<Utc>>,
    /// 会话优先级（越高越重要；影响新绑 / 强制切号时的选号偏好）
    #[serde(default)]
    priority: i32,
}

/// 观测面板：单个号的运行态快照。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountObservability {
    pub id: u64,
    pub email: Option<String>,
    pub disabled: bool,
    pub rpm: usize,
    pub active_sessions: usize,
    pub bound_sessions: Vec<String>,
    pub limiter_rate_rps: Option<f64>,
    pub cooldown_remaining_ms: u64,
    pub state: AccountState,
    pub state_reason: String,
    pub reopen_in_ms: u64,
    pub current_max_inflight: usize,
    pub current_inflight: usize,
    pub current_rate_rps: f64,
    pub effective_rate_floor_rps: f64,
    pub learned_safe_rps_lo: f64,
    pub learned_safe_rps_hi: f64,
    pub p80_held_ms: u64,
    pub learned_optimal_t_secs: u64,
    pub bottleneck_dimension: crate::kiro::account_learning::BottleneckDimension,
    pub upstream429_rate5m: f64,
    pub consecutive_throttles: u32,
    /// goodput 控制器：窗口内成功请求/秒（真吞吐，控制器优化目标）。
    pub goodput_rps: f64,
    /// goodput 控制器：是否 app-limited（在飞低于并发上限=没活干，非到顶）。
    pub app_limited: bool,
    /// 自适应退避当前 beta（乘性减速系数）。
    pub adaptive_beta: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservabilitySnapshot {
    pub multi_account_enabled: bool,
    pub active_window_secs: u64,
    pub accounts: Vec<AccountObservability>,
    pub session_to_account: HashMap<String, u64>,
    pub active_session_total: usize,
    pub pinned_sessions: HashMap<String, u64>,
    pub session_priority: HashMap<String, i32>,
    pub global_upstream429_rate5m: f64,
    pub account_state_counts: HashMap<String, usize>,
    pub scheduling_mode: String,
}

// ============================================================================
// Admin API 公开结构
// ============================================================================

/// 凭据条目快照（用于 Admin API 读取）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialEntrySnapshot {
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 累计失败次数（所有失败类型，只增不减，仅手动重置归零）
    pub total_failure_count: u64,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 身份提供商（BuilderId / Enterprise / Github / Google / IAM_SSO）
    pub provider: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
    /// Token 过期时间
    pub expires_at: Option<String>,
    /// refreshToken 的 SHA-256 哈希（仅 OAuth 凭据，用于前端去重）
    pub refresh_token_hash: Option<String>,
    /// kiroApiKey 的 SHA-256 哈希（仅 API Key 凭据，用于前端去重）
    pub api_key_hash: Option<String>,
    /// kiroApiKey 的脱敏展示（仅 API Key 凭据，用于前端显示）
    pub masked_api_key: Option<String>,
    /// 用户邮箱（用于前端显示）
    pub email: Option<String>,
    /// API 调用成功次数
    pub success_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    pub last_used_at: Option<String>,
    /// 是否配置了凭据级代理
    pub has_proxy: bool,
    /// 代理 URL（用于前端展示）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Token 刷新连续失败次数
    pub refresh_failure_count: u32,
    /// 禁用原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// 临时冷却剩余秒数（账号级 429 风控）；冷却中且 `> 0` 才返回
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttled_remaining_secs: Option<u64>,
    /// 端点名称（未显式配置时返回 None，由 Admin 层回退到默认值）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// 账号所属分组（可属于多个分组）
    #[serde(default)]
    pub groups: Vec<String>,
    /// 账号来源渠道（纯备注）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_channel: Option<String>,
}

/// 凭据管理器状态快照
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagerSnapshot {
    /// 凭据条目列表
    pub entries: Vec<CredentialEntrySnapshot>,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 总凭据数量
    pub total: usize,
    /// 可用凭据数量
    pub available: usize,
}

/// 多凭据 Token 管理器
///
/// 支持多个凭据的管理，实现固定优先级 + 故障转移策略
/// 故障统计基于 API 调用结果，而非 Token 刷新结果
pub struct MultiTokenManager {
    config: Config,
    /// 全局代理（运行时可修改）
    proxy: Mutex<Option<ProxyConfig>>,
    /// 凭据条目列表
    entries: Mutex<Vec<CredentialEntry>>,
    /// 当前活动凭据 ID
    current_id: Mutex<u64>,
    /// Token 刷新锁，确保同一时间只有一个刷新操作
    refresh_lock: TokioMutex<()>,
    /// 凭据文件路径（用于回写）
    credentials_path: Option<PathBuf>,
    /// 是否为多凭据格式（数组格式才回写；通过 add_credential 动态升级为 true）
    is_multiple_format: AtomicBool,
    /// 负载均衡模式（运行时可修改）
    load_balancing_mode: Mutex<String>,
    /// 账号级 429 风控故障转移开关（运行时可修改）
    account_throttle_failover: AtomicBool,
    /// 账号级风控冷却时长（秒，运行时可修改）
    account_throttle_cooldown_secs: AtomicU64,
    /// 最近一次统计持久化时间（用于 debounce）
    last_stats_save_at: Mutex<Option<Instant>>,
    /// 统计数据是否有未落盘更新
    stats_dirty: AtomicBool,
    /// 自适应限速器容器（多号共享一个实例）。
    /// selection 据此查询各号「剩余冷却」做切号判定；provider 复用同一实例做发送前闸门。
    /// `enabled=false` 时仍可安全持有（完全不介入）。
    limiters: Arc<LimiterRegistry>,
    /// 每个凭据近 `RPM_WINDOW` 内的请求时间戳窗口（用于「最低负载选号」=最低 RPM）。
    request_window: Mutex<HashMap<u64, VecDeque<Instant>>>,
    /// 会话亲和映射：conversation_id → 绑定信息（多号 + 强制 session affinity 的核心状态）。
    affinity: Mutex<HashMap<String, AffinityBinding>>,
    /// 最近一次亲和映射落盘时间（用于 debounce）
    last_affinity_save_at: Mutex<Option<Instant>>,
    /// 亲和映射是否有未落盘更新
    affinity_dirty: AtomicBool,
    /// 手动 pin：会话 id → 强制使用的凭据 id（持久化到 session_pins.json）。
    pin_map: Mutex<HashMap<String, u64>>,
    /// 最近一次 pin 映射落盘时间（用于 debounce）
    last_pins_save_at: Mutex<Option<Instant>>,
    /// pin 映射是否有未落盘更新
    pins_dirty: AtomicBool,
    /// 尚未建立 affinity 绑定的会话优先级（下次绑定时写入 AffinityBinding）。
    pending_priority: Mutex<HashMap<String, i32>>,
}

/// 每个凭据最大 API 调用失败次数
const MAX_FAILURES_PER_CREDENTIAL: u32 = 10;
/// 统计数据持久化防抖间隔
const STATS_SAVE_DEBOUNCE: StdDuration = StdDuration::from_secs(30);
/// 会话亲和映射持久化防抖间隔
const AFFINITY_SAVE_DEBOUNCE: StdDuration = StdDuration::from_secs(30);
/// 会话 pin 映射持久化防抖间隔
const PINS_SAVE_DEBOUNCE: StdDuration = StdDuration::from_secs(30);
/// RPM 负载窗口长度（统计近 N 秒内的请求数作为负载度量）
const RPM_WINDOW: StdDuration = StdDuration::from_secs(60);

/// API 调用上下文
///
/// 绑定特定凭据的调用上下文，确保 token、credentials 和 id 的一致性
/// 用于解决并发调用时 current_id 竞态问题
#[derive(Clone)]
pub struct CallContext {
    /// 凭据 ID（用于 report_success/report_failure）
    pub id: u64,
    /// 凭据信息（用于构建请求头）
    pub credentials: KiroCredentials,
    /// 访问 Token
    pub token: String,
}

/// 判断某账号的分组集合是否匹配请求所属分组（严格隔离）
///
/// - `group = None`：Key 未绑定分组（含 master apiKey），匹配所有账号。
/// - `group = Some(g)`：仅匹配 `cred_groups` 包含 `g` 的账号。
fn group_matches(cred_groups: &[String], group: Option<&str>) -> bool {
    match group {
        None => true,
        Some(g) => cred_groups.iter().any(|cg| cg == g),
    }
}

impl MultiTokenManager {
    /// 创建多凭据 Token 管理器
    ///
    /// # Arguments
    /// * `config` - 应用配置
    /// * `credentials` - 凭据列表
    /// * `proxy` - 可选的代理配置
    /// * `credentials_path` - 凭据文件路径（用于回写）
    /// * `is_multiple_format` - 是否为多凭据格式（数组格式才回写）
    pub fn new(
        config: Config,
        credentials: Vec<KiroCredentials>,
        proxy: Option<ProxyConfig>,
        credentials_path: Option<PathBuf>,
        is_multiple_format: bool,
    ) -> anyhow::Result<Self> {
        // 计算当前最大 ID，为没有 ID 的凭据分配新 ID
        let max_existing_id = credentials.iter().filter_map(|c| c.id).max().unwrap_or(0);
        let mut next_id = max_existing_id + 1;
        let mut has_new_ids = false;
        let mut has_new_machine_ids = false;
        let config_ref = &config;

        let entries: Vec<CredentialEntry> = credentials
            .into_iter()
            .map(|mut cred| {
                cred.canonicalize_auth_method();
                let id = cred.id.unwrap_or_else(|| {
                    let id = next_id;
                    next_id += 1;
                    cred.id = Some(id);
                    has_new_ids = true;
                    id
                });
                if cred.fill_default_profile_arn() {
                    has_new_ids = true;
                }
                if cred.machine_id.is_none() {
                    cred.machine_id =
                        Some(machine_id::generate_from_credentials(&cred, config_ref));
                    has_new_machine_ids = true;
                }
                CredentialEntry {
                    id,
                    credentials: cred.clone(),
                    failure_count: 0,
                    total_failure_count: 0,
                    refresh_failure_count: 0,
                    disabled: cred.disabled, // 从配置文件读取 disabled 状态
                    disabled_reason: if cred.disabled {
                        Some(DisabledReason::Manual)
                    } else {
                        None
                    },
                    success_count: 0,
                    last_used_at: None,
                    throttled_until: None,
                }
            })
            .collect();

        // 校验 API Key 凭据配置完整性：authMethod=api_key 时必须提供 kiroApiKey
        let mut entries = entries;
        for entry in &mut entries {
            if entry.credentials.kiro_api_key.is_none()
                && entry
                    .credentials
                    .auth_method
                    .as_deref()
                    .map(|m| m.eq_ignore_ascii_case("api_key") || m.eq_ignore_ascii_case("apikey"))
                    .unwrap_or(false)
            {
                tracing::warn!(
                    "凭据 #{} 配置了 authMethod=api_key 但缺少 kiroApiKey 字段，已自动禁用",
                    entry.id
                );
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::InvalidConfig);
            }
        }

        // 检测重复 ID
        let mut seen_ids = std::collections::HashSet::new();
        let mut duplicate_ids = Vec::new();
        for entry in &entries {
            if !seen_ids.insert(entry.id) {
                duplicate_ids.push(entry.id);
            }
        }
        if !duplicate_ids.is_empty() {
            anyhow::bail!("检测到重复的凭据 ID: {:?}", duplicate_ids);
        }

        // 选择初始凭据：优先级最高（priority 最小）的可用凭据，无可用凭据时为 0
        let initial_id = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
            .map(|e| e.id)
            .unwrap_or(0);

        let load_balancing_mode = config.load_balancing_mode.clone();
        let throttle_failover = config.account_throttle_failover;
        let throttle_cooldown_secs = config.account_throttle_cooldown_secs;
        // 自适应限速器：多号共享一个 registry（provider 通过 limiters() 复用同一实例，
        // 这样 selection 查到的「剩余冷却」与 provider 实际闸门是同一份状态）。
        let learning_path = credentials_path.as_ref().and_then(|p| {
            p.parent().map(|d| {
                let base = if d.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    d.to_path_buf()
                };
                base.join(&config.adaptive_limit.learning.persist_path)
            })
        });
        let learning = if config.adaptive_limit.learning.enabled {
            Some(LearningStore::new(
                config.adaptive_limit.learning.clone(),
                learning_path,
            ))
        } else {
            None
        };
        let limiters = Arc::new(LimiterRegistry::new(
            AdaptiveConfig::from_cfg(&config.adaptive_limit),
            learning,
        ));
        let manager = Self {
            config,
            proxy: Mutex::new(proxy),
            entries: Mutex::new(entries),
            current_id: Mutex::new(initial_id),
            refresh_lock: TokioMutex::new(()),
            credentials_path,
            is_multiple_format: AtomicBool::new(is_multiple_format),
            load_balancing_mode: Mutex::new(load_balancing_mode),
            account_throttle_failover: AtomicBool::new(throttle_failover),
            account_throttle_cooldown_secs: AtomicU64::new(throttle_cooldown_secs),
            last_stats_save_at: Mutex::new(None),
            stats_dirty: AtomicBool::new(false),
            limiters,
            request_window: Mutex::new(HashMap::new()),
            affinity: Mutex::new(HashMap::new()),
            last_affinity_save_at: Mutex::new(None),
            affinity_dirty: AtomicBool::new(false),
            pin_map: Mutex::new(HashMap::new()),
            last_pins_save_at: Mutex::new(None),
            pins_dirty: AtomicBool::new(false),
            pending_priority: Mutex::new(HashMap::new()),
        };

        // 单凭据格式自动迁移：升级为数组格式，确保 token rotation 能写盘
        // 触发条件：原文件是单对象格式 && 存在凭据 && 有文件路径
        if !is_multiple_format
            && !manager.entries.lock().is_empty()
            && manager.credentials_path.is_some()
        {
            manager.is_multiple_format.store(true, Ordering::Relaxed);
            if let Err(e) = manager.persist_credentials() {
                tracing::warn!("单凭据格式迁移到数组格式失败: {}", e);
            } else {
                tracing::info!(
                    "已将凭据文件从单对象格式迁移到数组格式，token rotation 将正确持久化"
                );
            }
        }

        // 如果有新分配的 ID 或新生成的 machineId，立即持久化到配置文件
        if has_new_ids || has_new_machine_ids {
            if let Err(e) = manager.persist_credentials() {
                tracing::warn!("补全凭据 ID/machineId 后持久化失败: {}", e);
            } else {
                tracing::info!("已补全凭据 ID/machineId 并写回配置文件");
            }
        }

        // 加载持久化的统计数据（success_count, last_used_at）
        manager.load_stats();
        // 加载持久化的会话亲和映射（多号 + session affinity，重启后同会话仍黏同号）
        manager.load_affinity();
        // 加载持久化的会话 pin 映射
        manager.load_pins();

        Ok(manager)
    }

    /// 手动 pin：将会话强制绑定到指定凭据（选号时优先于 affinity）。
    pub fn pin_session(&self, session: &str, credential_id: u64) {
        if session.is_empty() {
            return;
        }
        self.pin_map
            .lock()
            .insert(session.to_string(), credential_id);
        self.save_pins_debounced();
    }

    /// 取消会话的手动 pin。
    pub fn unpin_session(&self, session: &str) {
        if session.is_empty() {
            return;
        }
        self.pin_map.lock().remove(session);
        self.save_pins_debounced();
    }

    /// 返回当前全部 pin 映射的克隆。
    pub fn pinned_sessions(&self) -> HashMap<String, u64> {
        self.pin_map.lock().clone()
    }

    /// 设置会话优先级（越高越重要）。已有 affinity 绑定时立即写入并持久化；
    /// 否则存入 pending，下次绑定时应用。
    pub fn set_session_priority(&self, session: &str, priority: i32) {
        if session.is_empty() {
            return;
        }
        let mut aff = self.affinity.lock();
        if let Some(b) = aff.get_mut(session) {
            b.priority = priority;
            drop(aff);
            self.save_affinity_debounced();
        } else {
            drop(aff);
            self.pending_priority
                .lock()
                .insert(session.to_string(), priority);
        }
    }

    /// 获取配置的引用
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 获取自适应限速器容器（供 provider 复用同一实例做发送前闸门）。
    pub fn limiters(&self) -> Arc<LimiterRegistry> {
        self.limiters.clone()
    }

    /// 观测面板快照：聚合每个号的 RPM / 活跃会话数 / 绑定会话列表 / 限速器速率与冷却，
    /// 以及反向 会话→号 映射。只读，按「先取各资源快照再聚合」的顺序避免锁交叉。
    pub fn observability_snapshot(&self) -> ObservabilitySnapshot {
        let ma = &self.config.adaptive_limit.multi_account;
        let active_window = Duration::seconds(ma.rebalance_active_window_secs as i64);
        let ttl = Duration::seconds(ma.affinity_ttl_secs as i64);
        let now = Utc::now();

        // 1) 号基础信息快照（释放 entries 锁后再做其余）。
        let accounts_base: Vec<(u64, Option<String>, bool)> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| (e.id, e.credentials.email.clone(), e.disabled))
                .collect()
        };

        // 2) affinity 快照：统计每个号的绑定会话（TTL 内）+ 活跃会话（active_window 内）+ 反向映射。
        let mut bound: HashMap<u64, Vec<String>> = HashMap::new();
        let mut active_counts: HashMap<u64, usize> = HashMap::new();
        let mut session_to_account: HashMap<String, u64> = HashMap::new();
        let mut session_priority: HashMap<String, i32> = HashMap::new();
        let mut active_session_total = 0usize;
        {
            let aff = self.affinity.lock();
            for (sid, b) in aff.iter() {
                if (now - b.last_seen) > ttl {
                    continue;
                }
                bound.entry(b.credential_id).or_default().push(sid.clone());
                session_to_account.insert(sid.clone(), b.credential_id);
                session_priority.insert(sid.clone(), b.priority);
                if (now - b.last_seen) <= active_window {
                    *active_counts.entry(b.credential_id).or_default() += 1;
                    active_session_total += 1;
                }
            }
        }

        // 2b) pin 快照 + pending 优先级（不与 affinity 锁交叉）。
        let pinned_sessions = self.pin_map.lock().clone();
        {
            let pending = self.pending_priority.lock();
            for (sid, p) in pending.iter() {
                session_priority.entry(sid.clone()).or_insert(*p);
            }
        }

        // 3) 逐号聚合 RPM + limiter（不在持 affinity 锁期间调用）。
        let accounts = accounts_base
            .into_iter()
            .map(|(id, email, disabled)| {
                let scope = ThrottleScope::UserCredential(id);
                let obs = self.limiters.observe_full(&scope);
                let (rate, cd) = match self.limiters.observe(&scope) {
                    Some((r, c)) => (Some(r), c.as_millis() as u64),
                    None => (None, 0),
                };
                let mut sessions = bound.remove(&id).unwrap_or_default();
                sessions.sort();
                let state = if disabled {
                    AccountState::Disabled
                } else {
                    obs.as_ref().map(|o| o.state).unwrap_or(AccountState::Healthy)
                };
                AccountObservability {
                    id,
                    email,
                    disabled,
                    rpm: self.rpm(id),
                    active_sessions: *active_counts.get(&id).unwrap_or(&0),
                    bound_sessions: sessions,
                    limiter_rate_rps: rate,
                    cooldown_remaining_ms: cd,
                    state,
                    state_reason: obs.as_ref().map(|o| o.state_reason.clone()).unwrap_or_default(),
                    reopen_in_ms: obs.as_ref().map(|o| o.reopen_in_ms).unwrap_or(0),
                    current_max_inflight: obs.as_ref().map(|o| o.current_max_inflight).unwrap_or(0),
                    current_inflight: obs.as_ref().map(|o| o.current_inflight).unwrap_or(0),
                    current_rate_rps: obs.as_ref().map(|o| o.current_rate_rps).unwrap_or(0.0),
                    effective_rate_floor_rps: obs
                        .as_ref()
                        .map(|o| o.effective_rate_floor_rps)
                        .unwrap_or(0.1),
                    learned_safe_rps_lo: obs.as_ref().map(|o| o.learned_safe_rps_lo).unwrap_or(0.5),
                    learned_safe_rps_hi: obs.as_ref().map(|o| o.learned_safe_rps_hi).unwrap_or(1.0),
                    p80_held_ms: obs.as_ref().map(|o| o.p80_held_ms).unwrap_or(0),
                    learned_optimal_t_secs: obs
                        .as_ref()
                        .map(|o| o.learned_optimal_t_secs)
                        .unwrap_or(30),
                    bottleneck_dimension: obs
                        .as_ref()
                        .map(|o| o.bottleneck_dimension)
                        .unwrap_or_default(),
                    upstream429_rate5m: obs.as_ref().map(|o| o.upstream_429_rate_5m).unwrap_or(0.0),
                    consecutive_throttles: obs.as_ref().map(|o| o.consecutive_throttles).unwrap_or(0),
                    goodput_rps: obs.as_ref().map(|o| o.goodput_rps).unwrap_or(0.0),
                    app_limited: obs.as_ref().map(|o| o.app_limited).unwrap_or(false),
                    adaptive_beta: obs.as_ref().map(|o| o.adaptive_beta).unwrap_or(0.0),
                }
            })
            .collect();

        let scheduling_mode = if ma.enabled {
            "multi_account_affinity".to_string()
        } else {
            "single_account".to_string()
        };

        ObservabilitySnapshot {
            multi_account_enabled: ma.enabled,
            active_window_secs: ma.rebalance_active_window_secs,
            accounts,
            session_to_account,
            active_session_total,
            pinned_sessions,
            session_priority,
            global_upstream429_rate5m: self.limiters.global_upstream_429_rate(),
            account_state_counts: self
                .limiters
                .account_state_counts()
                .into_iter()
                .map(|(s, c)| (format!("{s:?}"), c))
                .collect(),
            scheduling_mode,
        }
    }

    /// 获取全局代理配置的克隆（可安全跨锁使用）
    pub fn proxy(&self) -> Option<ProxyConfig> {
        self.proxy.lock().clone()
    }

    /// 设置全局代理配置（运行时修改，可传 None 清除）
    pub fn set_global_proxy(&self, proxy: Option<ProxyConfig>) {
        *self.proxy.lock() = proxy;
    }

    /// 获取凭据总数
    pub fn total_count(&self) -> usize {
        self.entries.lock().len()
    }

    /// 获取指定分组的凭据总数（group=None 时等于 total_count）
    ///
    /// 用于按分组计算 failover 重试预算，避免小分组按全局账号数获得过多无效重试。
    pub fn total_count_in_group(&self, group: Option<&str>) -> usize {
        self.entries
            .lock()
            .iter()
            .filter(|e| group_matches(&e.credentials.groups, group))
            .count()
    }

    /// 获取可用凭据数量
    pub fn available_count(&self) -> usize {
        let now = Instant::now();
        self.entries
            .lock()
            .iter()
            .filter(|e| !e.disabled && !e.throttled_until.map(|t| t > now).unwrap_or(false))
            .count()
    }

    /// 根据负载均衡模式选择下一个凭据
    ///
    /// - priority 模式：选择优先级最高（priority 最小）的可用凭据
    /// - balanced 模式：均衡选择可用凭据
    ///
    /// # 参数
    /// - `model`: 可选的模型名称，用于过滤支持该模型的凭据（如 opus 模型需要付费订阅）
    fn select_next_credential(
        &self,
        model: Option<&str>,
        group: Option<&str>,
        session_key: Option<&str>,
    ) -> Option<(u64, KiroCredentials)> {
        // 多号 + 强制 session affinity：整条选号逻辑交给 affinity（黏定 / 切号 / 最低负载新绑）。
        if self.config.adaptive_limit.multi_account.enabled {
            return self.select_with_affinity(model, group, session_key);
        }

        let entries = self.entries.lock();
        let now = Instant::now();

        // 检查是否是 opus 模型
        let is_opus = model
            .map(|m| m.to_lowercase().contains("opus"))
            .unwrap_or(false);

        // 过滤可用凭据
        let available: Vec<_> = entries
            .iter()
            .filter(|e| {
                if e.disabled {
                    return false;
                }
                // 临时冷却中（账号级 429 风控）：跳过
                if e.throttled_until.map(|t| t > now).unwrap_or(false) {
                    return false;
                }
                // 如果是 opus 模型，需要检查订阅等级
                if is_opus && !e.credentials.supports_opus() {
                    return false;
                }
                // 账号分组隔离：Key 绑定分组时只用该分组内的账号
                if !group_matches(&e.credentials.groups, group) {
                    return false;
                }
                true
            })
            .collect();

        if available.is_empty() {
            return None;
        }

        let mode = self.load_balancing_mode.lock().clone();
        let mode = mode.as_str();

        match mode {
            "balanced" => {
                // 最低负载策略：选近 60s 请求数（RPM）最少的号；
                // 平局按优先级（数字越小越高）、再按 id（稳定）。
                let entry = available
                    .iter()
                    .min_by_key(|e| (self.rpm(e.id), e.credentials.priority, e.id))?;

                Some((entry.id, entry.credentials.clone()))
            }
            _ => {
                // priority 模式（默认）：选择优先级最高的
                let entry = available.iter().min_by_key(|e| e.credentials.priority)?;
                Some((entry.id, entry.credentials.clone()))
            }
        }
    }

    /// 构造「当前可用」凭据列表（与 [`Self::select_next_credential`] 同口径：未禁用 /
    /// 未账号级冷却 / opus 订阅匹配 / 分组匹配）。返回 `(id, credentials)` 克隆，
    /// 调用方拿到后不再持 `entries` 锁，避免与 `request_window` / `affinity` 锁交叉。
    fn available_credentials(
        &self,
        model: Option<&str>,
        group: Option<&str>,
    ) -> Vec<(u64, KiroCredentials)> {
        let entries = self.entries.lock();
        let now = Instant::now();
        let is_opus = model
            .map(|m| m.to_lowercase().contains("opus"))
            .unwrap_or(false);
        entries
            .iter()
            .filter(|e| {
                if e.disabled {
                    return false;
                }
                if e.throttled_until.map(|t| t > now).unwrap_or(false) {
                    return false;
                }
                if is_opus && !e.credentials.supports_opus() {
                    return false;
                }
                if !group_matches(&e.credentials.groups, group) {
                    return false;
                }
                true
            })
            .map(|e| (e.id, e.credentials.clone()))
            .collect()
    }

    /// 记录一次对某凭据的请求（RPM 负载窗口）。在选号后调用，供后续请求的最低负载比较。
    fn note_request(&self, id: u64) {
        let now = Instant::now();
        let mut win = self.request_window.lock();
        let dq = win.entry(id).or_default();
        dq.push_back(now);
        while let Some(front) = dq.front() {
            if now.duration_since(*front) > RPM_WINDOW {
                dq.pop_front();
            } else {
                break;
            }
        }
    }

    /// 某凭据近 [`RPM_WINDOW`] 内的请求数（负载度量）。读时顺手修剪过期项。
    pub fn account_rpm(&self, id: u64) -> usize {
        self.rpm(id)
    }

    pub fn flush_learning_if_dirty(&self) {
        if let Some(store) = self.limiters.learning() {
            store.flush_if_dirty();
        }
    }

    /// 后台 tick：按经过时间对学习分桶做指数衰减（H1：旧 429 随时间被遗忘）。
    pub fn decay_learning_now(&self) {
        if let Some(store) = self.limiters.learning() {
            store.decay_tick_now();
        }
    }

    fn is_account_open(&self, id: u64) -> bool {
        self.limiters
            .is_account_open(&ThrottleScope::UserCredential(id))
    }

    fn rpm(&self, id: u64) -> usize {
        let now = Instant::now();
        let mut win = self.request_window.lock();
        match win.get_mut(&id) {
            Some(dq) => {
                while let Some(front) = dq.front() {
                    if now.duration_since(*front) > RPM_WINDOW {
                        dq.pop_front();
                    } else {
                        break;
                    }
                }
                dq.len()
            }
            None => 0,
        }
    }

    /// 在 `available` 中挑「最低负载」（最低 RPM）的号；平局按 priority、再按 id（稳定）。
    /// `exclude` 用于切号时排除原号。无候选返回 None。
    fn lowest_load(
        &self,
        available: &[(u64, KiroCredentials)],
        exclude: Option<u64>,
    ) -> Option<(u64, KiroCredentials)> {
        self.lowest_load_prioritized(available, exclude, false)
    }

    /// M2 全 OPEN 兜底：当所有可用号都处于 OPEN 熔断窗口、正常选号(过滤 open)全灭时，
    /// 退而求其次——挑 cooldown 剩余最短的那个号（最快能恢复的），而不是直接返回 None
    /// 导致 acquire_context bail（"所有凭据均已禁用"）。OPEN 号被选中后，limiter 的
    /// acquire 仍会按熔断状态本地排队/退避，不会真把请求硬打到上游——只是不再"无号可用"。
    fn shortest_cooldown_fallback(
        &self,
        available: &[(u64, KiroCredentials)],
    ) -> Option<(u64, KiroCredentials)> {
        available
            .iter()
            .min_by_key(|(id, c)| {
                let cd_ms = self
                    .limiters
                    .cooldown_remaining(&ThrottleScope::UserCredential(*id))
                    .as_millis() as u64;
                (cd_ms, c.priority, *id)
            })
            .map(|(id, c)| (*id, c.clone()))
    }

    /// 选号：默认最低 RPM；`prefer_healthy=true` 时优先最低冷却，再最低 RPM，再凭据 priority/id。
    fn lowest_load_prioritized(
        &self,
        available: &[(u64, KiroCredentials)],
        exclude: Option<u64>,
        prefer_healthy: bool,
    ) -> Option<(u64, KiroCredentials)> {
        available
            .iter()
            .filter(|(id, _)| Some(*id) != exclude)
            .filter(|(id, _)| !self.is_account_open(*id))
            .min_by_key(|(id, c)| {
                let cd_ms = if prefer_healthy {
                    self.limiters
                        .cooldown_remaining(&ThrottleScope::UserCredential(*id))
                        .as_millis() as u64
                } else {
                    0
                };
                let headroom = if prefer_healthy {
                    let limiter = self
                        .limiters
                        .for_scope(&ThrottleScope::UserCredential(*id));
                    let h = limiter.headroom();
                    (-h).clamp(0, isize::MAX as isize) as u64
                } else {
                    0
                };
                (headroom, cd_ms, self.rpm(*id), c.priority, *id)
            })
            .map(|(id, c)| (*id, c.clone()))
    }

    /// 读取会话优先级：pending 优先，否则已有绑定，默认 0。
    fn session_priority_for(&self, key: &str, existing: Option<&AffinityBinding>) -> i32 {
        if let Some(p) = self.pending_priority.lock().get(key) {
            return *p;
        }
        existing.map(|b| b.priority).unwrap_or(0)
    }

    /// 取出并清除 pending 优先级（绑定时写入 AffinityBinding）。
    fn take_pending_priority(&self, key: &str, existing: Option<&AffinityBinding>) -> i32 {
        let from_pending = self.pending_priority.lock().remove(key);
        from_pending.unwrap_or_else(|| existing.map(|b| b.priority).unwrap_or(0))
    }

    /// 打一条选号决策日志（与 provider 的 `kiro_limiter_decision` 同事件名，scope=select）。
    fn log_select(
        action: &'static str,
        credential_id: u64,
        rpm: usize,
        cooldown_remaining_ms: u64,
        session: Option<&str>,
        priority: i32,
    ) {
        let session_short = session.map(|s| {
            if s.len() > 8 {
                &s[..8]
            } else {
                s
            }
        });
        tracing::info!(
            event = "kiro_limiter_decision",
            scope = "select",
            action = action,
            credential_id = credential_id,
            rpm = rpm,
            cooldown_remaining_ms = cooldown_remaining_ms,
            session = session_short,
            priority = priority,
            "多号选号决策"
        );
    }

    /// 统计各号「活跃会话数」：affinity map 中 `last_seen` 在 `active_window` 内、且绑到 `available` 内号的会话。
    /// 只读 affinity 快照，不调 rpm/limiters（避免锁交叉）。返回 `id -> 活跃会话数`（available 中的号至少为 0）。
    fn active_session_counts(
        &self,
        available: &[(u64, KiroCredentials)],
        active_window: Duration,
    ) -> HashMap<u64, usize> {
        let now = Utc::now();
        let mut counts: HashMap<u64, usize> = available.iter().map(|(id, _)| (*id, 0)).collect();
        let aff = self.affinity.lock();
        for b in aff.values() {
            if (now - b.last_seen) <= active_window {
                if let Some(c) = counts.get_mut(&b.credential_id) {
                    *c += 1;
                }
            }
        }
        counts
    }

    /// 被动负载再平衡是否启用：利用率信号 或 会话数信号 任一开启即启用（P2-b）。
    /// 抽成纯函数便于单测，并消除调用门处的内联布尔魔法。
    /// - util_gap > 0 → 利用率信号开（rebalance_target 内 util 分支优先）；
    /// - min_gap > 0 → 会话数信号开（util 未触发时的 fallback）；
    /// - 两者都 0 → 完全关闭被动再平衡。
    fn rebalance_signal_enabled(ma: &crate::model::config::MultiAccountConfig) -> bool {
        ma.rebalance_utilization_gap > 0.0 || ma.rebalance_min_gap > 0
    }

    /// 被动负载再平衡：若 `current` 号的活跃会话数比最空号多 ≥ `rebalance_min_gap`，
    /// 返回应迁往的最空号（排除 `current`）；否则 `None`（不迁，保持黏定）。
    /// 滞后阈值(≥2)+ 调用方的防抖保证迁移后不会 A↔B 反复横跳。
    fn rebalance_target(
        &self,
        available: &[(u64, KiroCredentials)],
        current: u64,
        ma: &crate::model::config::MultiAccountConfig,
    ) -> Option<(u64, KiroCredentials)> {
        if available.len() < 2 {
            return None;
        }
        // ① 利用率信号（Task 7 根治：会话数 ≠ 真实负载）。利用率 = current_rate / safe_rps_hi
        //    （≥1=贴墙/过载，<1=有余量）+ 429 率叠加。一个号会话少但每个都在撞墙(利用率高)，
        //    应把会话迁给会话多但很闲(利用率低)的号——这是会话数指标永远做不到的。
        if ma.rebalance_utilization_gap > 0.0 {
            let cur_util = self.account_utilization(current);
            // 前置门：仅当原号「真的接近/超过自己的天花板」(util ≥ SATURATED)才考虑按利用率迁移。
            // 否则单次瞬态 429 也会把 util 抬高、引发不必要的会话搬家(churn)。
            const SATURATED: f64 = 1.0;
            if cur_util >= SATURATED {
                // 找利用率最低的「别的号」（最有余量）。
                if let Some((tid, tcreds)) = available
                    .iter()
                    .filter(|(id, _)| *id != current)
                    .min_by(|(a, _), (b, _)| {
                        self.account_utilization(*a)
                            .partial_cmp(&self.account_utilization(*b))
                            .unwrap_or(std::cmp::Ordering::Equal)
                            .then(a.cmp(b))
                    })
                {
                    let target_util = self.account_utilization(*tid);
                    if cur_util - target_util >= ma.rebalance_utilization_gap {
                        return Some((*tid, tcreds.clone()));
                    }
                }
            }
        }
        // ② 会话数信号（回退/补充）：原号活跃会话数比最空号多 ≥ rebalance_min_gap。
        if ma.rebalance_min_gap == 0 {
            return None;
        }
        let window = Duration::seconds(ma.rebalance_active_window_secs as i64);
        let counts = self.active_session_counts(available, window);
        let current_load = *counts.get(&current).unwrap_or(&0);
        // 找活跃会话数最少的「别的号」（平局按 priority、再按 id 稳定）。
        let target = available
            .iter()
            .filter(|(id, _)| *id != current)
            .min_by_key(|(id, c)| (*counts.get(id).unwrap_or(&0), c.priority, *id))?;
        let target_load = *counts.get(&target.0).unwrap_or(&0);
        if current_load >= target_load + ma.rebalance_min_gap {
            Some((target.0, target.1.clone()))
        } else {
            None
        }
    }

    /// 账号「真实利用率」：current_rate / safe_rps_hi（越接近/超过 1 越满载），
    /// 叠加「持续撞墙」的额外压力。无 limiter 数据时返回 0（视为空闲）。
    /// 用于负载再平衡：把会话从高利用率(撞墙)号迁到低利用率(有余量)号。
    ///
    /// ⚠️ 429 压力只在**持续**撞墙(consecutive_throttles ≥ 2)时才计入，避免单次瞬态 429
    /// 把利用率瞬间抬高引发不必要的会话搬家(churn)——单次 429 由 limiter 自己冷却消化即可。
    fn account_utilization(&self, id: u64) -> f64 {
        let scope = ThrottleScope::UserCredential(id);
        match self.limiters.observe_full(&scope) {
            Some(o) => {
                let safe = o.learned_safe_rps_hi.max(1e-6);
                let rate_util = (o.current_rate_rps / safe).clamp(0.0, 4.0);
                // 持续撞墙才把 429 率计入；单次瞬态(consecutive < 2)不算「过载」。
                let throttle_pressure = if o.consecutive_throttles >= 2 {
                    o.upstream_429_rate_5m
                } else {
                    0.0
                };
                rate_util + throttle_pressure
            }
            None => 0.0,
        }
    }

    /// 多号 + 强制 session affinity 的选号核心。
    ///
    /// - `session_key = Some(非空)`：同一会话黏定同一号；原号「剩余冷却 > 阈值且不在切号防抖窗口」
    ///   才切到最低负载的别的号（切号后写 `last_switch_at`，不再自动黏回旧号）；原号已不可用
    ///   （禁用/账号级风控/分组/opus）则强制切；新会话按最低负载落号并绑定。
    /// - `session_key = None/空`：无稳定会话可黏，直接按最低负载选号、不绑定。
    fn select_with_affinity(
        &self,
        model: Option<&str>,
        group: Option<&str>,
        session_key: Option<&str>,
    ) -> Option<(u64, KiroCredentials)> {
        let all_available = self.available_credentials(model, group);
        if all_available.is_empty() {
            return None;
        }
        let healthy_available: Vec<(u64, KiroCredentials)> = all_available
            .iter()
            .filter(|(id, _)| !self.is_account_open(*id))
            .map(|(id, c)| (*id, c.clone()))
            .collect();
        let pick_pool = if healthy_available.is_empty() {
            &all_available
        } else {
            &healthy_available
        };

        let ma = &self.config.adaptive_limit.multi_account;
        let ttl = Duration::seconds(ma.affinity_ttl_secs as i64);
        let switch_threshold = StdDuration::from_secs(ma.switch_threshold_secs);
        let debounce = Duration::seconds(ma.switch_debounce_secs as i64);
        let now = Utc::now();

        // 无稳定会话：纯最低负载选号，不绑定。
        let key = match session_key {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => {
                let pick = self.lowest_load(pick_pool, None).or_else(|| {
                    self.lowest_load(&all_available, None)
                })
                // M2 全 OPEN 兜底：无会话的纯负载选号同样别在全 OPEN 时返回 None。
                .or_else(|| self.shortest_cooldown_fallback(&all_available))?;
                Self::log_select("load_select", pick.0, self.rpm(pick.0), 0, None, 0);
                return Some(pick);
            }
        };

        // 读现有绑定的只读快照（pin / 选号共用；不在持 affinity 锁期间调用 rpm/limiters）。
        let existing = self.affinity.lock().get(&key).cloned();

        // 手动 pin：优先于 affinity 决策（pin 不在 available 时 soft fallback）。
        {
            let pinned_id = self.pin_map.lock().get(&key).copied();
            if let Some(pinned_id) = pinned_id {
                if let Some(creds) = all_available
                    .iter()
                    .find(|(id, _)| *id == pinned_id)
                    .map(|(_, c)| c.clone())
                {
                    if !self.is_account_open(pinned_id) {
                    let cd = self
                        .limiters
                        .cooldown_remaining(&ThrottleScope::UserCredential(pinned_id));
                    let prio = self.session_priority_for(&key, existing.as_ref());
                    Self::log_select(
                        "affinity_pin",
                        pinned_id,
                        self.rpm(pinned_id),
                        cd.as_millis() as u64,
                        Some(&key),
                        prio,
                    );
                    return Some((pinned_id, creds));
                    }
                }
                tracing::warn!(
                    session = %key,
                    pinned_id = pinned_id,
                    "手动 pin 的目标号当前不可用，回退到正常 affinity 选号"
                );
            }
        }

        let session_prio = self.session_priority_for(&key, existing.as_ref());
        let prefer_healthy = session_prio > 0;

        enum Act {
            Stick,
            Switch,
            NewBind,
        }

        let pick_from_pool = |exclude: Option<u64>| {
            self.lowest_load_prioritized(pick_pool, exclude, prefer_healthy)
                .or_else(|| self.lowest_load_prioritized(&all_available, exclude, prefer_healthy))
                // M2 全 OPEN 兜底：上面两步会过滤掉 OPEN 号，全 OPEN 时返回 None。
                // 这里退到「cooldown 最短的号」，保证有号可用而非整体 bail。
                .or_else(|| self.shortest_cooldown_fallback(&all_available))
        };

        let (act, mut chosen, cd_ms) = match &existing {
            Some(b) if (now - b.last_seen) <= ttl => {
                let bound_in_pool = all_available
                    .iter()
                    .any(|(id, _)| *id == b.credential_id);
                let bound_available = bound_in_pool && !self.is_account_open(b.credential_id);
                if bound_available {
                    let cd = self
                        .limiters
                        .cooldown_remaining(&ThrottleScope::UserCredential(b.credential_id));
                    let in_debounce = b
                        .last_switch_at
                        .map(|t| (now - t) < debounce)
                        .unwrap_or(false);
                    if cd > switch_threshold && !in_debounce {
                        // 原号卡太久 → 切到别的最低负载号（排除原号）。没有别的号则只能黏着。
                        match self
                            .lowest_load(pick_pool, Some(b.credential_id))
                            .or_else(|| self.lowest_load(&all_available, Some(b.credential_id)))
                        {
                            Some(pick) => (Act::Switch, pick, cd.as_millis() as u64),
                            None => {
                                let creds = all_available
                                    .iter()
                                    .find(|(id, _)| *id == b.credential_id)
                                    .map(|(_, c)| c.clone())?;
                                (Act::Stick, (b.credential_id, creds), cd.as_millis() as u64)
                            }
                        }
                    } else {
                        // 原号健康（不到切号阈值）。先看是否该「被动负载再平衡」：
                        // 触发条件 = 「利用率信号 或 会话数信号」任一启用，且不在切号防抖窗口（P2-b 修复：
                        // 旧逻辑只看 min_gap>0，min_gap=0 时连 rebalance_target 都不调 → util 信号被绑死摸不到）。
                        // rebalance_target 内部 util 分支优先、会话数分支 fallback；迁移复用切号路径
                        // （写 last_switch_at + 防抖 + 不黏回），滞后阈值(≥2)保证迁完两边不会立刻反向触发。
                        let rebalanced = if Self::rebalance_signal_enabled(ma) && !in_debounce {
                            self.rebalance_target(pick_pool, b.credential_id, ma)
                        } else {
                            None
                        };
                        match rebalanced {
                            Some(pick) => (Act::Switch, pick, cd.as_millis() as u64),
                            None => {
                                let creds = all_available
                                    .iter()
                                    .find(|(id, _)| *id == b.credential_id)
                                    .map(|(_, c)| c.clone())?;
                                (Act::Stick, (b.credential_id, creds), cd.as_millis() as u64)
                            }
                        }
                    }
                } else {
                    if bound_in_pool && self.is_account_open(b.credential_id) {
                        tracing::info!(
                            session = %key,
                            credential_id = b.credential_id,
                            "绑定号处于 OPEN 风控窗口，强制切号"
                        );
                    }
                    // 原号已不可用（禁用/OPEN/分组等）→ 强制切号；高优先级会话偏好最健康号。
                    let pick = pick_from_pool(None)?;
                    (Act::Switch, pick, 0)
                }
            }
            // 无绑定或绑定已过 TTL → 新会话：最低负载落号并绑定。
            _ => {
                let pick = pick_from_pool(None)?;
                (Act::NewBind, pick, 0)
            }
        };

        let bind_priority = self.take_pending_priority(&key, existing.as_ref());

        // 短暂写锁更新绑定。
        {
            let mut aff = self.affinity.lock();
            match act {
                Act::Stick => {
                    if let Some(e) = aff.get_mut(&key) {
                        e.last_seen = now;
                        e.priority = bind_priority;
                    } else {
                        // 期间被并发清理：重新建绑定（last-writer-wins，幂等）。
                        aff.insert(
                            key.clone(),
                            AffinityBinding {
                                credential_id: chosen.0,
                                bound_at: now,
                                last_seen: now,
                                last_switch_at: None,
                                priority: bind_priority,
                            },
                        );
                    }
                }
                Act::Switch => {
                    let e = aff.entry(key.clone()).or_insert_with(|| AffinityBinding {
                        credential_id: chosen.0,
                        bound_at: now,
                        last_seen: now,
                        last_switch_at: Some(now),
                        priority: bind_priority,
                    });
                    e.credential_id = chosen.0;
                    e.last_switch_at = Some(now);
                    e.last_seen = now;
                    e.priority = bind_priority;
                }
                Act::NewBind => {
                    // H3 串号竞态根治（check-and-adopt）：本请求开头读 existing=None 走到这里，
                    // 但 pick_from_pool 期间不持 affinity 锁（避免与 rpm/limiter 锁交叉死锁）。
                    // 这个窗口里另一个同会话并发请求可能已经绑好号。提交前在锁内 re-check：
                    // 若已存在未过 TTL 的有效绑定，**采纳它**（把 chosen 改成已绑号），绝不用自己
                    // 独立选的号覆盖——否则两请求各打不同号 = 同会话串号(封号高危)。
                    let adopt = aff
                        .get(&key)
                        .filter(|b| (now - b.last_seen) <= ttl)
                        .filter(|b| {
                            all_available.iter().any(|(id, _)| *id == b.credential_id)
                        })
                        .map(|b| b.credential_id);
                    if let Some(adopt_id) = adopt {
                        if adopt_id != chosen.0 {
                            if let Some(creds) = all_available
                                .iter()
                                .find(|(id, _)| *id == adopt_id)
                                .map(|(_, c)| c.clone())
                            {
                                tracing::debug!(
                                    session = %key,
                                    picked = chosen.0,
                                    adopted = adopt_id,
                                    "并发 NewBind：采纳已存在的会话绑定，避免同会话串号"
                                );
                                chosen = (adopt_id, creds);
                            }
                        }
                        // 已有有效绑定：只刷新 last_seen/priority，不覆盖 credential_id。
                        if let Some(e) = aff.get_mut(&key) {
                            e.last_seen = now;
                            e.priority = bind_priority;
                        }
                    } else {
                        aff.insert(
                            key.clone(),
                            AffinityBinding {
                                credential_id: chosen.0,
                                bound_at: now,
                                last_seen: now,
                                last_switch_at: None,
                                priority: bind_priority,
                            },
                        );
                    }
                }
            }
        }

        let action_str = match act {
            Act::Stick => "affinity_stick",
            Act::Switch => "affinity_switch",
            Act::NewBind => "new_session_bind",
        };
        Self::log_select(
            action_str,
            chosen.0,
            self.rpm(chosen.0),
            cd_ms,
            Some(&key),
            session_prio,
        );
        self.save_affinity_debounced();
        Some(chosen)
    }

    /// 会话亲和映射文件路径（与凭据文件同目录）。
    fn affinity_path(&self) -> Option<PathBuf> {
        self.cache_dir().map(|d| d.join("session_affinity.json"))
    }

    /// 启动时从磁盘加载会话亲和映射（过滤过期项 + 指向不存在凭据的死绑定）。
    fn load_affinity(&self) {
        let path = match self.affinity_path() {
            Some(p) => p,
            None => return,
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // 首次运行时文件不存在
        };
        let map: HashMap<String, AffinityBinding> = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("解析会话亲和缓存失败，将忽略: {}", e);
                return;
            }
        };

        let now = Utc::now();
        let ttl = Duration::seconds(self.config.adaptive_limit.multi_account.affinity_ttl_secs as i64);
        let valid_ids: std::collections::HashSet<u64> =
            self.entries.lock().iter().map(|e| e.id).collect();

        let mut loaded = self.affinity.lock();
        let mut kept = 0usize;
        for (k, b) in map {
            if (now - b.last_seen) <= ttl && valid_ids.contains(&b.credential_id) {
                loaded.insert(k, b);
                kept += 1;
            }
        }
        drop(loaded);
        *self.last_affinity_save_at.lock() = Some(Instant::now());
        self.affinity_dirty.store(false, Ordering::Relaxed);
        tracing::info!("已从缓存加载 {} 条会话亲和绑定", kept);
    }

    /// 把会话亲和映射落盘（原子写）。落盘前顺手清理过期项，避免文件无限增长。
    fn save_affinity(&self) {
        let path = match self.affinity_path() {
            Some(p) => p,
            None => return,
        };
        let now = Utc::now();
        let ttl = Duration::seconds(self.config.adaptive_limit.multi_account.affinity_ttl_secs as i64);
        let map: HashMap<String, AffinityBinding> = {
            let mut aff = self.affinity.lock();
            aff.retain(|_, b| (now - b.last_seen) <= ttl);
            aff.clone()
        };
        match serde_json::to_string_pretty(&map) {
            Ok(json) => {
                if let Err(e) = crate::observability::write_atomic(&path, json.as_bytes()) {
                    tracing::warn!("保存会话亲和缓存失败: {}", e);
                } else {
                    *self.last_affinity_save_at.lock() = Some(Instant::now());
                    self.affinity_dirty.store(false, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!("序列化会话亲和数据失败: {}", e),
        }
    }

    /// 标记亲和映射已更新，按 debounce 决定是否立即落盘。
    fn save_affinity_debounced(&self) {
        self.affinity_dirty.store(true, Ordering::Relaxed);
        let should_flush = {
            let last = *self.last_affinity_save_at.lock();
            match last {
                Some(t) => t.elapsed() >= AFFINITY_SAVE_DEBOUNCE,
                None => true,
            }
        };
        if should_flush {
            self.save_affinity();
        }
    }

    /// 周期性刷盘钩子（绕过 debounce）：若亲和映射有未落盘更新则立即写盘。
    /// 由后台任务每 ~30s 调用一次，把 debounce 窗口内积累的新绑定兜底落盘，
    /// 保证「重启后同会话仍黏同号」的最长丢失窗口 ≤ 刷盘间隔。
    pub fn flush_affinity_if_dirty(&self) {
        if self.affinity_dirty.load(Ordering::Relaxed) {
            self.save_affinity();
        }
    }

    /// 会话 pin 映射文件路径（与 affinity 同目录）。
    fn pins_path(&self) -> Option<PathBuf> {
        self.cache_dir().map(|d| d.join("session_pins.json"))
    }

    /// 启动时从磁盘加载会话 pin 映射（过滤指向不存在凭据的条目）。
    fn load_pins(&self) {
        let path = match self.pins_path() {
            Some(p) => p,
            None => return,
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        let map: HashMap<String, u64> = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("解析会话 pin 缓存失败，将忽略: {}", e);
                return;
            }
        };

        let valid_ids: std::collections::HashSet<u64> =
            self.entries.lock().iter().map(|e| e.id).collect();

        let mut loaded = self.pin_map.lock();
        let mut kept = 0usize;
        for (k, id) in map {
            if valid_ids.contains(&id) {
                loaded.insert(k, id);
                kept += 1;
            }
        }
        drop(loaded);
        *self.last_pins_save_at.lock() = Some(Instant::now());
        self.pins_dirty.store(false, Ordering::Relaxed);
        tracing::info!("已从缓存加载 {} 条会话 pin", kept);
    }

    /// 把会话 pin 映射落盘（原子写）。
    fn save_pins(&self) {
        let path = match self.pins_path() {
            Some(p) => p,
            None => return,
        };
        let map: HashMap<String, u64> = self.pin_map.lock().clone();
        match serde_json::to_string_pretty(&map) {
            Ok(json) => {
                if let Err(e) = crate::observability::write_atomic(&path, json.as_bytes()) {
                    tracing::warn!("保存会话 pin 缓存失败: {}", e);
                } else {
                    *self.last_pins_save_at.lock() = Some(Instant::now());
                    self.pins_dirty.store(false, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!("序列化会话 pin 数据失败: {}", e),
        }
    }

    /// 标记 pin 映射已更新，按 debounce 决定是否立即落盘。
    fn save_pins_debounced(&self) {
        self.pins_dirty.store(true, Ordering::Relaxed);
        let should_flush = {
            let last = *self.last_pins_save_at.lock();
            match last {
                Some(t) => t.elapsed() >= PINS_SAVE_DEBOUNCE,
                None => true,
            }
        };
        if should_flush {
            self.save_pins();
        }
    }

    /// 周期性刷盘钩子：若 pin 映射有未落盘更新则立即写盘。
    pub fn flush_pins_if_dirty(&self) {
        if self.pins_dirty.load(Ordering::Relaxed) {
            self.save_pins();
        }
    }

    /// 获取 API 调用上下文
    ///
    /// 返回绑定了 id、credentials 和 token 的调用上下文
    /// 确保整个 API 调用过程中使用一致的凭据信息
    ///
    /// 如果 Token 过期或即将过期，会自动刷新
    /// Token 刷新失败会累计到当前凭据，达到阈值后禁用并切换
    ///
    /// # 参数
    /// - `model`: 可选的模型名称，用于过滤支持该模型的凭据（如 opus 模型需要付费订阅）
    pub async fn acquire_context(
        &self,
        model: Option<&str>,
        group: Option<&str>,
        session_key: Option<&str>,
    ) -> anyhow::Result<CallContext> {
        let total = self.total_count_in_group(group);
        let max_attempts = (total * MAX_FAILURES_PER_CREDENTIAL as usize).max(1);
        let mut attempt_count = 0;

        loop {
            if attempt_count >= max_attempts {
                anyhow::bail!(
                    "所有凭据均无法获取有效 Token（可用: {}/{}）",
                    self.available_count(),
                    total
                );
            }

            let (id, credentials) = {
                // balanced 或多号 affinity：每次请求都重新选号，不固定 current_id。
                // priority 模式：优先复用 current_id 指向的凭据。
                let skip_sticky = self.load_balancing_mode.lock().as_str() == "balanced"
                    || self.config.adaptive_limit.multi_account.enabled;
                let current_hit = if skip_sticky {
                    None
                } else {
                    let entries = self.entries.lock();
                    let current_id = *self.current_id.lock();
                    let now = Instant::now();
                    entries
                        .iter()
                        .find(|e| {
                            e.id == current_id
                                && !e.disabled
                                && !e.throttled_until.map(|t| t > now).unwrap_or(false)
                                && group_matches(&e.credentials.groups, group)
                        })
                        .map(|e| (e.id, e.credentials.clone()))
                };

                if let Some(hit) = current_hit {
                    hit
                } else {
                    // 当前凭据不可用 / balanced / 多号 affinity：按选号策略重新选择
                    let mut best = self.select_next_credential(model, group, session_key);

                    // 没有可用凭据：如果是"自动禁用导致全灭"，做一次类似重启的自愈
                    if best.is_none() {
                        let mut entries = self.entries.lock();
                        if entries.iter().any(|e| {
                            e.disabled && e.disabled_reason == Some(DisabledReason::TooManyFailures)
                        }) {
                            tracing::warn!(
                                "所有凭据均已被自动禁用，执行自愈：重置失败计数并重新启用（等价于重启）"
                            );
                            for e in entries.iter_mut() {
                                if e.disabled_reason == Some(DisabledReason::TooManyFailures) {
                                    e.disabled = false;
                                    e.disabled_reason = None;
                                    e.failure_count = 0;
                                }
                            }
                            drop(entries);
                            best = self.select_next_credential(model, group, session_key);
                        }
                    }

                    if let Some((new_id, new_creds)) = best {
                        // 更新 current_id
                        let mut current_id = self.current_id.lock();
                        *current_id = new_id;
                        (new_id, new_creds)
                    } else {
                        let entries = self.entries.lock();
                        // 注意：必须在 bail! 之前计算 available_count，
                        // 因为 available_count() 会尝试获取 entries 锁，
                        // 而此时我们已经持有该锁，会导致死锁
                        let available = entries.iter().filter(|e| !e.disabled).count();
                        anyhow::bail!("所有凭据均已禁用（{}/{}）", available, total);
                    }
                }
            };

            // 记录一次对该号的请求（RPM 负载窗口，供后续请求的最低负载选号）。
            self.note_request(id);

            // 尝试获取/刷新 Token
            match self.try_ensure_token(id, &credentials).await {
                Ok(ctx) => {
                    return Ok(ctx);
                }
                Err(e) => {
                    let has_available = if e.downcast_ref::<RefreshTokenInvalidError>().is_some() {
                        // 先尝试从源文件重新加载（适用于 IDE 退出后 token rotation 导致失效的场景）
                        if self.try_reload_credential_from_file(id) {
                            // 找到新 Token，不计入失败次数，直接重试
                            continue;
                        }
                        tracing::warn!("凭据 #{} refreshToken 永久失效: {}", id, e);
                        self.report_refresh_token_invalid(id)
                    } else {
                        tracing::warn!("凭据 #{} Token 刷新失败: {}", id, e);
                        self.report_refresh_failure(id)
                    };
                    attempt_count += 1;
                    if !has_available {
                        anyhow::bail!("所有凭据均已禁用（0/{}）", total);
                    }
                }
            }
        }
    }

    /// 选择优先级最高的未禁用凭据作为当前凭据（内部方法）
    ///
    /// 纯粹按优先级选择，不排除当前凭据，用于优先级变更后立即生效
    fn select_highest_priority(&self) {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（不排除当前凭据）
        if let Some(best) = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
        {
            if best.id != *current_id {
                tracing::info!(
                    "优先级变更后切换凭据: #{} -> #{}（优先级 {}）",
                    *current_id,
                    best.id,
                    best.credentials.priority
                );
                *current_id = best.id;
            }
        }
    }

    /// 尝试使用指定凭据获取有效 Token
    ///
    /// 使用双重检查锁定模式，确保同一时间只有一个刷新操作
    ///
    /// # Arguments
    /// * `id` - 凭据 ID，用于更新正确的条目
    /// * `credentials` - 凭据信息
    async fn try_ensure_token(
        &self,
        id: u64,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<CallContext> {
        // API Key 凭据直接使用 kiro_api_key 作为 Bearer Token，无需刷新
        if credentials.is_api_key_credential() {
            let token = credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            return Ok(CallContext {
                id,
                credentials: credentials.clone(),
                token,
            });
        }

        // 第一次检查（无锁）：快速判断是否需要刷新
        let needs_refresh = is_token_expired(credentials) || is_token_expiring_soon(credentials);

        let creds = if needs_refresh {
            // 获取刷新锁，确保同一时间只有一个刷新操作
            let _guard = self.refresh_lock.lock().await;

            // 第二次检查：获取锁后重新读取凭据，因为其他请求可能已经完成刷新
            let current_creds = {
                let entries = self.entries.lock();
                entries
                    .iter()
                    .find(|e| e.id == id)
                    .map(|e| e.credentials.clone())
                    .ok_or_else(|| anyhow::anyhow!("凭据 #{} 不存在", id))?
            };

            if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                // 确实需要刷新
                let global_proxy = self.proxy.lock().clone();
                let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
                let new_creds =
                    refresh_token(&current_creds, &self.config, effective_proxy.as_ref()).await?;

                if is_token_expired(&new_creds) {
                    anyhow::bail!("刷新后的 Token 仍然无效或已过期");
                }

                // 更新凭据
                {
                    let mut entries = self.entries.lock();
                    if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                        entry.credentials = new_creds.clone();
                    }
                }

                // 回写凭据到文件（仅多凭据格式），失败只记录警告
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                }

                new_creds
            } else {
                // 其他请求已经完成刷新，直接使用新凭据
                tracing::debug!("Token 已被其他请求刷新，跳过刷新");
                current_creds
            }
        } else {
            credentials.clone()
        };

        let token = creds
            .access_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))?;

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.refresh_failure_count = 0;
            }
        }

        Ok(CallContext {
            id,
            credentials: creds,
            token,
        })
    }

    /// 将凭据列表回写到源文件
    ///
    /// 仅在以下条件满足时回写：
    /// - 源文件是多凭据格式（数组）
    /// - credentials_path 已设置
    ///
    /// # Returns
    /// - `Ok(true)` - 成功写入文件
    /// - `Ok(false)` - 跳过写入（非多凭据格式或无路径配置）
    /// - `Err(_)` - 写入失败
    fn persist_credentials(&self) -> anyhow::Result<bool> {
        use anyhow::Context;

        // 仅多凭据格式才回写
        if !self.is_multiple_format.load(Ordering::Relaxed) {
            return Ok(false);
        }

        let path = match &self.credentials_path {
            Some(p) => p,
            None => return Ok(false),
        };

        // 收集所有凭据
        let credentials: Vec<KiroCredentials> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    let mut cred = e.credentials.clone();
                    cred.canonicalize_auth_method();
                    // 同步 disabled 状态到凭据对象
                    cred.disabled = e.disabled;
                    cred
                })
                .collect()
        };

        // 序列化为 pretty JSON
        let json = serde_json::to_string_pretty(&credentials).context("序列化凭据失败")?;

        // 写入文件（在 Tokio runtime 内使用 block_in_place 避免阻塞 worker）
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| std::fs::write(path, &json))
                .with_context(|| format!("回写凭据文件失败: {:?}", path))?;
        } else {
            std::fs::write(path, &json).with_context(|| format!("回写凭据文件失败: {:?}", path))?;
        }

        tracing::debug!("已回写凭据到文件: {:?}", path);
        Ok(true)
    }

    /// 尝试从凭据文件重新加载指定凭据的 Token
    ///
    /// 当 refreshToken 失效 (invalid_grant) 时，检查源文件是否已被其他客户端更新
    /// （例如本地 IDE 退出时刷新了 Token，导致 token rotation）。
    /// 如果文件中存在不同的 refreshToken，更新内存凭据并返回 true。
    ///
    /// # 匹配规则（按优先级）
    /// 1. 文件中与内存凭据 `id` 相同的条目
    /// 2. 文件中与内存凭据 `email` 相同的条目
    /// 3. 文件与内存均只有一个凭据时，直接匹配
    ///
    /// # 更新范围
    /// 仅更新 token 相关字段（refreshToken / accessToken / expiresAt），
    /// 保留代理、region、machineId 等配置不变。
    fn try_reload_credential_from_file(&self, id: u64) -> bool {
        use crate::kiro::model::credentials::CredentialsConfig;

        let path = match self.credentials_path.as_ref() {
            Some(p) => p.clone(),
            None => return false,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let file_config: CredentialsConfig = match serde_json::from_str(&content) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let file_creds = file_config.into_sorted_credentials();
        if file_creds.is_empty() {
            return false;
        }

        // 先读取当前凭据的身份信息（不持有锁，避免死锁）
        let (current_cred_id, current_email, current_refresh_token, entries_len) = {
            let entries = self.entries.lock();
            match entries.iter().find(|e| e.id == id) {
                Some(entry) => (
                    entry.credentials.id,
                    entry.credentials.email.clone(),
                    entry.credentials.refresh_token.clone(),
                    entries.len(),
                ),
                None => return false,
            }
        };

        // 从文件中查找对应凭据
        let matched = file_creds
            .iter()
            .find(|fc| {
                if fc.id.is_some() && fc.id == current_cred_id {
                    return true;
                }
                if fc.email.is_some() && fc.email == current_email {
                    return true;
                }
                false
            })
            .or_else(|| {
                if file_creds.len() == 1 && entries_len == 1 {
                    file_creds.first()
                } else {
                    None
                }
            });

        let file_cred = match matched {
            Some(c) => c,
            None => return false,
        };

        // 文件中的 refreshToken 必须存在且与当前不同，才值得更新
        if file_cred.refresh_token.is_none() || file_cred.refresh_token == current_refresh_token {
            return false;
        }

        let new_refresh_token = file_cred.refresh_token.clone();
        let new_access_token = file_cred.access_token.clone();
        let new_expires_at = file_cred.expires_at.clone();

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.credentials.refresh_token = new_refresh_token;
                entry.credentials.access_token = new_access_token;
                entry.credentials.expires_at = new_expires_at;
                entry.disabled = false;
                entry.disabled_reason = None;
                entry.refresh_failure_count = 0;
                entry.failure_count = 0;
            }
        }

        tracing::info!(
            "凭据 #{} 从文件检测到新 refreshToken（疑似 IDE token rotation），已自动恢复，将重试",
            id
        );
        true
    }

    /// 获取缓存目录（凭据文件所在目录）
    pub fn cache_dir(&self) -> Option<PathBuf> {
        self.credentials_path.as_ref().and_then(|p| {
            p.parent().map(|d| {
                // 当传入相对路径如 "credentials.json"（无目录前缀）时 parent 为空串，
                // 直接 join 出来的子路径会落到 CWD，且 read_dir("") 会报错导致历史日志重建为 0。
                // 这里归一化为 "."，保证 join / read_dir 行为正确。
                if d.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    d.to_path_buf()
                }
            })
        })
    }

    /// 统计数据文件路径
    fn stats_path(&self) -> Option<PathBuf> {
        self.cache_dir().map(|d| d.join("kiro_stats.json"))
    }

    /// 从磁盘加载统计数据并应用到当前条目
    fn load_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // 首次运行时文件不存在
        };

        let stats: HashMap<String, StatsEntry> = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("解析统计缓存失败，将忽略: {}", e);
                return;
            }
        };

        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if let Some(s) = stats.get(&entry.id.to_string()) {
                entry.success_count = s.success_count;
                entry.total_failure_count = s.total_failure_count;
                entry.last_used_at = s.last_used_at.clone();
            }
        }
        *self.last_stats_save_at.lock() = Some(Instant::now());
        self.stats_dirty.store(false, Ordering::Relaxed);
        tracing::info!("已从缓存加载 {} 条统计数据", stats.len());
    }

    /// 将当前统计数据持久化到磁盘
    fn save_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let stats: HashMap<String, StatsEntry> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    (
                        e.id.to_string(),
                        StatsEntry {
                            success_count: e.success_count,
                            total_failure_count: e.total_failure_count,
                            last_used_at: e.last_used_at.clone(),
                        },
                    )
                })
                .collect()
        };

        match serde_json::to_string_pretty(&stats) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("保存统计缓存失败: {}", e);
                } else {
                    *self.last_stats_save_at.lock() = Some(Instant::now());
                    self.stats_dirty.store(false, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!("序列化统计数据失败: {}", e),
        }
    }

    /// 标记统计数据已更新，并按 debounce 策略决定是否立即落盘
    fn save_stats_debounced(&self) {
        self.stats_dirty.store(true, Ordering::Relaxed);

        let should_flush = {
            let last = *self.last_stats_save_at.lock();
            match last {
                Some(last_saved_at) => last_saved_at.elapsed() >= STATS_SAVE_DEBOUNCE,
                None => true,
            }
        };

        if should_flush {
            self.save_stats();
        }
    }

    /// 报告指定凭据 API 调用成功
    ///
    /// 重置该凭据的失败计数
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_success(&self, id: u64) {
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.success_count += 1;
                entry.last_used_at = Some(Utc::now().to_rfc3339());
                // 成功 = 风控已解除，提前结束冷却
                entry.throttled_until = None;
                tracing::debug!(
                    "凭据 #{} API 调用成功（累计 {} 次）",
                    id,
                    entry.success_count
                );
            }
        }
        self.save_stats_debounced();
    }

    /// 报告指定凭据 API 调用失败
    ///
    /// 增加失败计数，达到阈值时禁用凭据并切换到优先级最高的可用凭据
    /// 返回是否还有可用凭据可以重试
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_failure(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.failure_count += 1;
            entry.total_failure_count += 1;
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            let failure_count = entry.failure_count;

            tracing::warn!(
                "凭据 #{} API 调用失败（{}/{}）",
                id,
                failure_count,
                MAX_FAILURES_PER_CREDENTIAL
            );

            if failure_count >= MAX_FAILURES_PER_CREDENTIAL {
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::TooManyFailures);
                tracing::error!("凭据 #{} 已连续失败 {} 次，已被禁用", id, failure_count);

                // 切换到优先级最高的可用凭据
                if let Some(next) = entries
                    .iter()
                    .filter(|e| !e.disabled)
                    .min_by_key(|e| e.credentials.priority)
                {
                    *current_id = next.id;
                    tracing::info!(
                        "已切换到凭据 #{}（优先级 {}）",
                        next.id,
                        next.credentials.priority
                    );
                } else {
                    tracing::error!("所有凭据均已禁用！");
                }
            }

            entries.iter().any(|e| !e.disabled)
        };
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据额度已用尽
    ///
    /// 用于处理 402 Payment Required 且 reason 为 `MONTHLY_REQUEST_COUNT` 的场景：
    /// - 立即禁用该凭据（不等待连续失败阈值）
    /// - 切换到下一个可用凭据继续重试
    /// - 返回是否还有可用凭据
    pub fn report_quota_exhausted(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::QuotaExceeded);
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            // 设为阈值，便于在管理面板中直观看到该凭据已不可用
            entry.failure_count = MAX_FAILURES_PER_CREDENTIAL;
            entry.total_failure_count += 1;

            tracing::error!(
                "凭据 #{} 额度已用尽（MONTHLY_REQUEST_COUNT 或 OVERAGE_REQUEST_LIMIT_EXCEEDED），已被禁用",
                id
            );

            // 切换到优先级最高的可用凭据
            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据刷新 Token 失败。
    ///
    /// 连续刷新失败达到阈值后禁用凭据并切换，阈值内保持当前凭据不切换，
    /// 与 API 401/403 的累计失败策略保持一致。
    pub fn report_refresh_failure(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.last_used_at = Some(Utc::now().to_rfc3339());
            entry.refresh_failure_count += 1;
            let refresh_failure_count = entry.refresh_failure_count;

            tracing::warn!(
                "凭据 #{} Token 刷新失败（{}/{}）",
                id,
                refresh_failure_count,
                MAX_FAILURES_PER_CREDENTIAL
            );

            if refresh_failure_count < MAX_FAILURES_PER_CREDENTIAL {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::TooManyRefreshFailures);

            tracing::error!(
                "凭据 #{} Token 已连续刷新失败 {} 次，已被禁用",
                id,
                refresh_failure_count
            );

            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据的 refreshToken 永久失效（invalid_grant）。
    ///
    /// 立即禁用凭据，不累计、不重试。
    /// 返回是否还有可用凭据。
    pub fn report_refresh_token_invalid(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.last_used_at = Some(Utc::now().to_rfc3339());
            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::InvalidRefreshToken);

            tracing::error!(
                "凭据 #{} refreshToken 已失效 (invalid_grant)，已立即禁用",
                id
            );

            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        self.save_stats_debounced();
        result
    }

    /// 切换到优先级最高的可用凭据
    ///
    /// 返回是否成功切换
    pub fn switch_to_next(&self) -> bool {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（排除当前凭据）
        if let Some(next) = entries
            .iter()
            .filter(|e| !e.disabled && e.id != *current_id)
            .min_by_key(|e| e.credentials.priority)
        {
            *current_id = next.id;
            tracing::info!(
                "已切换到凭据 #{}（优先级 {}）",
                next.id,
                next.credentials.priority
            );
            true
        } else {
            // 没有其他可用凭据，检查当前凭据是否可用
            entries.iter().any(|e| e.id == *current_id && !e.disabled)
        }
    }

    // ========================================================================
    // Admin API 方法
    // ========================================================================

    /// 克隆全部凭据（含敏感字段：refreshToken、accessToken、clientSecret 等）
    ///
    /// 仅用于 Admin API 导出场景，调用方需自行保证脱敏与权限控制。
    /// 返回值按调用时的顺序克隆，未做排序。
    pub fn clone_all_credentials(&self) -> Vec<KiroCredentials> {
        let entries = self.entries.lock();
        entries
            .iter()
            .map(|e| {
                let mut cred = e.credentials.clone();
                cred.canonicalize_auth_method();
                cred.disabled = e.disabled;
                cred.id = Some(e.id);
                cred
            })
            .collect()
    }

    /// 获取管理器状态快照（用于 Admin API）
    pub fn snapshot(&self) -> ManagerSnapshot {
        let entries = self.entries.lock();
        let current_id = *self.current_id.lock();
        let now = Instant::now();
        let available = entries
            .iter()
            .filter(|e| !e.disabled && !e.throttled_until.map(|t| t > now).unwrap_or(false))
            .count();

        ManagerSnapshot {
            entries: entries
                .iter()
                .map(|e| CredentialEntrySnapshot {
                    id: e.id,
                    priority: e.credentials.priority,
                    disabled: e.disabled,
                    failure_count: e.failure_count,
                    total_failure_count: e.total_failure_count,
                    auth_method: if e.credentials.is_api_key_credential() {
                        Some("api_key".to_string())
                    } else {
                        e.credentials.auth_method.as_deref().map(|m| {
                            if m.eq_ignore_ascii_case("builder-id") || m.eq_ignore_ascii_case("iam")
                            {
                                "idc".to_string()
                            } else {
                                m.to_string()
                            }
                        })
                    },
                    provider: if e.credentials.is_api_key_credential() {
                        None
                    } else {
                        e.credentials.provider.clone()
                    },
                    has_profile_arn: e.credentials.profile_arn.is_some(),
                    expires_at: if e.credentials.is_api_key_credential() {
                        None // API Key 凭据本地不维护过期时间（服务端策略未知）
                    } else {
                        e.credentials.expires_at.clone()
                    },
                    refresh_token_hash: if e.credentials.is_api_key_credential() {
                        None
                    } else {
                        e.credentials.refresh_token.as_deref().map(sha256_hex)
                    },
                    api_key_hash: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(sha256_hex)
                    } else {
                        None
                    },
                    masked_api_key: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(mask_api_key)
                    } else {
                        None
                    },
                    email: e.credentials.email.clone(),
                    success_count: e.success_count,
                    last_used_at: e.last_used_at.clone(),
                    has_proxy: e.credentials.proxy_url.is_some(),
                    proxy_url: e.credentials.proxy_url.clone(),
                    refresh_failure_count: e.refresh_failure_count,
                    disabled_reason: e.disabled_reason.map(|r| {
                        match r {
                            DisabledReason::Manual => "Manual",
                            DisabledReason::TooManyFailures => "TooManyFailures",
                            DisabledReason::TooManyRefreshFailures => "TooManyRefreshFailures",
                            DisabledReason::QuotaExceeded => "QuotaExceeded",
                            DisabledReason::InvalidRefreshToken => "InvalidRefreshToken",
                            DisabledReason::InvalidConfig => "InvalidConfig",
                        }
                        .to_string()
                    }),
                    throttled_remaining_secs: e
                        .throttled_until
                        .and_then(|t| t.checked_duration_since(now))
                        .map(|d| d.as_secs())
                        .filter(|s| *s > 0),
                    endpoint: e.credentials.endpoint.clone(),
                    groups: e.credentials.groups.clone(),
                    source_channel: e.credentials.source_channel.clone(),
                })
                .collect(),
            current_id,
            total: entries.len(),
            available,
        }
    }

    /// 设置凭据禁用状态（Admin API）
    pub fn set_disabled(&self, id: u64, disabled: bool) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.disabled = disabled;
            if !disabled {
                // 启用时重置失败计数
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.disabled_reason = None;
                entry.throttled_until = None;
            } else {
                entry.disabled_reason = Some(DisabledReason::Manual);
            }
        }
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 标记凭据进入临时冷却期（账号级 429 风控触发）
    ///
    /// 与 `report_failure` 不同：不计入永久禁用，到期自动恢复，可用于"`suspicious activity` 429"
    /// 这种短期账号级风控——当前凭据先冷却 N 分钟，故障转移到其它凭据。
    ///
    /// 返回剩余可用凭据数（已排除冷却中的）。
    pub fn report_account_throttled(&self, id: u64, cooldown: StdDuration) -> usize {
        let now = Instant::now();
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                let until = now + cooldown;
                // 取较晚的到期时间（多次触发时延长冷却）
                entry.throttled_until = Some(match entry.throttled_until {
                    Some(prev) if prev > until => prev,
                    _ => until,
                });
                // 计入累计失败（账号风控不动连续 failure_count，避免冷却结束后误禁用）
                entry.total_failure_count += 1;
                tracing::warn!(
                    "凭据 #{} 触发账号级风控，冷却 {} 秒",
                    id,
                    cooldown.as_secs()
                );
            }

            let throttled_now = Instant::now();
            entries
                .iter()
                .filter(|e| {
                    !e.disabled
                        && !e
                            .throttled_until
                            .map(|t| t > throttled_now)
                            .unwrap_or(false)
                })
                .count()
        }
    }

    /// 手动解除指定凭据的临时冷却（Admin API）
    ///
    /// 即使冷却尚未到期也立即清除，让该凭据重新参与调度。
    pub fn clear_throttle(&self, id: u64) -> anyhow::Result<()> {
        let mut entries = self.entries.lock();
        let entry = entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
        entry.throttled_until = None;
        tracing::info!("凭据 #{} 风控冷却已被手动解除", id);
        Ok(())
    }

    /// 以"额度已用尽"为原因禁用凭据（Admin 一键超额功能）
    ///
    /// 与手动禁用不同，原因记录为 `QuotaExceeded`，便于自愈逻辑识别。
    pub fn disable_quota_exceeded(&self, id: u64) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::QuotaExceeded);
        }
        self.persist_credentials()?;
        Ok(())
    }

    /// 设置凭据优先级（Admin API）
    ///
    /// 修改优先级后会立即按新优先级重新选择当前凭据。
    /// 即使持久化失败，内存中的优先级和当前凭据选择也会生效。
    pub fn set_priority(&self, id: u64, priority: u32) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.credentials.priority = priority;
        }
        // 立即按新优先级重新选择当前凭据（无论持久化是否成功）
        self.select_highest_priority();
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 重置凭据失败计数并重新启用（Admin API）
    pub fn reset_and_enable(&self, id: u64) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            if entry.disabled_reason == Some(DisabledReason::InvalidConfig) {
                anyhow::bail!("凭据 #{} 因配置无效被禁用，请修正配置后重启服务", id);
            }
            entry.failure_count = 0;
            entry.total_failure_count = 0;
            entry.refresh_failure_count = 0;
            entry.disabled = false;
            entry.disabled_reason = None;
            entry.throttled_until = None;
        }
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    pub fn reset_success_count(&self, id: Option<u64>) -> anyhow::Result<u32> {
        let mut count = 0u32;
        {
            let mut entries = self.entries.lock();
            match id {
                Some(target_id) => {
                    let entry = entries
                        .iter_mut()
                        .find(|e| e.id == target_id)
                        .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", target_id))?;
                    entry.success_count = 0;
                    count = 1;
                }
                None => {
                    for entry in entries.iter_mut() {
                        entry.success_count = 0;
                        count += 1;
                    }
                }
            }
        }
        self.save_stats();
        Ok(count)
    }

    /// 解析并回填 Enterprise / IdC 账号的真实 profileArn。
    ///
    /// 流式端点（`generateAssistantResponse`）强制要求 profileArn：不带 → 400
    /// `profileArn is required`。Enterprise / IdC 账号若带 BuilderID 占位符会因
    /// token 身份不匹配触发 403，真实 profileArn 只能通过 `ListAvailableProfiles` 获取。
    ///
    /// 行为：
    /// - API Key 凭据 / 已有真实（非占位符）profileArn → 直接返回，不发起网络请求；
    /// - 否则调用上游 `ListAvailableProfiles`，命中真实 ARN 时写回凭据并持久化；
    /// - 上游无 profile（如纯 BuilderID 账号）→ 返回 `None`，由调用方回退到占位符。
    ///
    /// 返回应当用于本次请求的 profileArn（`Some` 表示真实 ARN）。
    pub async fn resolve_profile_arn_for(
        &self,
        id: u64,
        token: &str,
    ) -> anyhow::Result<Option<String>> {
        use crate::kiro::model::credentials::is_placeholder_profile_arn;

        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据没有 profileArn 概念
        if credentials.is_api_key_credential() {
            return Ok(None);
        }

        // 已有真实 ARN（含 Social 共享 ARN）→ 直接用，无需查询
        if let Some(arn) = credentials.profile_arn.as_deref() {
            if !is_placeholder_profile_arn(arn) {
                return Ok(Some(arn.to_string()));
            }
        }

        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        let profiles =
            list_available_profiles(&credentials, &self.config, token, effective_proxy.as_ref())
                .await?;

        let Some(arn) = profiles.first_arn().map(|s| s.to_string()) else {
            // 无 Enterprise profile（如纯 BuilderID 账号）：保持占位符回退逻辑
            return Ok(None);
        };

        // 写回真实 ARN 并持久化
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.credentials.profile_arn = Some(arn.clone());
            }
        }
        if let Err(e) = self.persist_credentials() {
            tracing::warn!("profileArn 回填后持久化失败（不影响本次请求）: {}", e);
        }
        tracing::info!("凭据 #{} 已解析并回填真实 profileArn: {}", id, arn);

        Ok(Some(arn))
    }

    /// 获取指定凭据的使用额度（Admin API）
    pub async fn get_usage_limits_for(&self, id: u64) -> anyhow::Result<UsageLimitsResponse> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据直接使用 kiro_api_key，无需刷新
        let token = if credentials.is_api_key_credential() {
            credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?
        } else {
            // 检查是否需要刷新 token
            let needs_refresh =
                is_token_expired(&credentials) || is_token_expiring_soon(&credentials);

            if needs_refresh {
                let _guard = self.refresh_lock.lock().await;
                let current_creds = {
                    let entries = self.entries.lock();
                    entries
                        .iter()
                        .find(|e| e.id == id)
                        .map(|e| e.credentials.clone())
                        .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
                };

                if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                    let global_proxy = self.proxy.lock().clone();
                    let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
                    let new_creds =
                        refresh_token(&current_creds, &self.config, effective_proxy.as_ref())
                            .await?;
                    {
                        let mut entries = self.entries.lock();
                        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                            entry.credentials = new_creds.clone();
                        }
                    }
                    // 持久化失败只记录警告，不影响本次请求
                    if let Err(e) = self.persist_credentials() {
                        tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                    }
                    new_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
                } else {
                    current_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
                }
            } else {
                credentials
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
            }
        };

        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        let usage_limits =
            get_usage_limits(&credentials, &self.config, &token, effective_proxy.as_ref()).await?;

        // 更新订阅等级到凭据（仅在发生变化时持久化）
        if let Some(subscription_title) = usage_limits.subscription_title() {
            let changed = {
                let mut entries = self.entries.lock();
                if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                    let old_title = entry.credentials.subscription_title.clone();
                    if old_title.as_deref() != Some(subscription_title) {
                        entry.credentials.subscription_title = Some(subscription_title.to_string());
                        tracing::info!(
                            "凭据 #{} 订阅等级已更新: {:?} -> {}",
                            id,
                            old_title,
                            subscription_title
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if changed {
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("订阅等级更新后持久化失败（不影响本次请求）: {}", e);
                }
            }
        }

        // 回填邮箱：仅在凭据尚无邮箱、且上游返回了邮箱时写入
        if let Some(email) = usage_limits.email() {
            let changed = {
                let mut entries = self.entries.lock();
                if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                    let is_empty = entry
                        .credentials
                        .email
                        .as_deref()
                        .map(|s| s.is_empty())
                        .unwrap_or(true);
                    if is_empty {
                        entry.credentials.email = Some(email.to_string());
                        tracing::info!("凭据 #{} 邮箱已回填: {}", id, email);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if changed {
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("邮箱回填后持久化失败（不影响本次请求）: {}", e);
                }
            }
        }

        Ok(usage_limits)
    }

    /// 为只读型上游查询准备有效 token 与最新凭据快照
    ///
    /// 复用 [`Self::get_usage_limits_for`] 的 token 准备流程：API Key 凭据直接用
    /// kiroApiKey；OAuth 凭据按需在 `refresh_lock` 内刷新并持久化。返回的凭据是
    /// 刷新后重新读取的最新快照，调用方据此构造请求。
    async fn prepare_request_token(&self, id: u64) -> anyhow::Result<(String, KiroCredentials)> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据直接使用 kiro_api_key，无需刷新
        let token = if credentials.is_api_key_credential() {
            credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?
        } else if is_token_expired(&credentials) || is_token_expiring_soon(&credentials) {
            let _guard = self.refresh_lock.lock().await;
            let current_creds = {
                let entries = self.entries.lock();
                entries
                    .iter()
                    .find(|e| e.id == id)
                    .map(|e| e.credentials.clone())
                    .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
            };

            if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                let global_proxy = self.proxy.lock().clone();
                let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
                let new_creds =
                    refresh_token(&current_creds, &self.config, effective_proxy.as_ref()).await?;
                {
                    let mut entries = self.entries.lock();
                    if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                        entry.credentials = new_creds.clone();
                    }
                }
                // 持久化失败只记录警告，不影响本次请求
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                }
                new_creds
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
            } else {
                current_creds
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
            }
        } else {
            credentials
                .access_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
        };

        // 重新读取最新凭据（刷新可能改写了 access_token 之外的字段）
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        Ok((token, credentials))
    }

    /// 获取指定凭据当前可用的模型列表（Admin API）
    ///
    /// 按需实时查询上游 `ListAvailableModels`，不做缓存。
    pub async fn get_available_models_for(
        &self,
        id: u64,
    ) -> anyhow::Result<ListAvailableModelsResponse> {
        let (token, credentials) = self.prepare_request_token(id).await?;
        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        get_available_models(&credentials, &self.config, &token, effective_proxy.as_ref()).await
    }

    /// 设置用户偏好（开启/关闭超额）— Admin API
    ///
    /// 与 `get_usage_limits_for` 类似的 token 准备流程，最后调用上游
    /// `setUserPreference` 接口写入新的 `overageStatus`。
    pub async fn set_user_preference_for(
        &self,
        id: u64,
        overage_status: &str,
    ) -> anyhow::Result<()> {
        // 仅接受 "ENABLED" / "DISABLED"，其它值早 fail
        if overage_status != "ENABLED" && overage_status != "DISABLED" {
            anyhow::bail!("overageStatus 必须是 ENABLED 或 DISABLED");
        }

        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据：直接当 Bearer 用
        let token = if credentials.is_api_key_credential() {
            credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?
        } else {
            // 复用与 get_usage_limits_for 完全相同的过期检查与刷新逻辑
            let needs_refresh =
                is_token_expired(&credentials) || is_token_expiring_soon(&credentials);

            if needs_refresh {
                let _guard = self.refresh_lock.lock().await;
                let current_creds = {
                    let entries = self.entries.lock();
                    entries
                        .iter()
                        .find(|e| e.id == id)
                        .map(|e| e.credentials.clone())
                        .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
                };

                if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                    let global_proxy = self.proxy.lock().clone();
                    let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
                    let new_creds =
                        refresh_token(&current_creds, &self.config, effective_proxy.as_ref())
                            .await?;
                    {
                        let mut entries = self.entries.lock();
                        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                            entry.credentials = new_creds.clone();
                        }
                    }
                    if let Err(e) = self.persist_credentials() {
                        tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                    }
                    new_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
                } else {
                    current_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
                }
            } else {
                credentials
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
            }
        };

        // 重新读取最新的凭据快照（refresh 可能已修改 access_token 之外的字段）
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        set_user_preference(
            &credentials,
            &self.config,
            &token,
            effective_proxy.as_ref(),
            overage_status,
        )
        .await
    }

    /// 添加新凭据（Admin API）
    ///
    /// # 流程
    /// 1. 验证凭据基本字段（API Key: kiroApiKey 不为空; OAuth: refreshToken 不为空）
    /// 2. 基于 kiroApiKey 或 refreshToken 的 SHA-256 哈希检测重复
    /// 3. OAuth: 尝试刷新 Token 验证凭据有效性; API Key: 跳过
    /// 4. 分配新 ID（当前最大 ID + 1）
    /// 5. 添加到 entries 列表
    /// 6. 持久化到配置文件
    ///
    /// # 返回
    /// - `Ok(u64)` - 新凭据 ID
    /// - `Err(_)` - 验证失败或添加失败
    pub async fn add_credential(&self, new_cred: KiroCredentials) -> anyhow::Result<u64> {
        // 1. 基本验证
        if new_cred.is_api_key_credential() {
            let api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            if api_key.is_empty() {
                anyhow::bail!("kiroApiKey 为空");
            }
        } else {
            validate_refresh_token(&new_cred)?;
        }

        // 2. 基于哈希检测重复
        if new_cred.is_api_key_credential() {
            let new_api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 kiroApiKey"))?;
            let new_api_key_hash = sha256_hex(new_api_key);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .kiro_api_key
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_api_key_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（kiroApiKey 重复）");
            }
        } else {
            let new_refresh_token = new_cred
                .refresh_token
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;
            let new_refresh_token_hash = sha256_hex(new_refresh_token);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .refresh_token
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_refresh_token_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（refreshToken 重复）");
            }
        }

        // 3. 验证凭据有效性（API Key 无需网络刷新）
        let mut validated_cred = if new_cred.is_api_key_credential() {
            new_cred.clone()
        } else {
            let global_proxy = self.proxy.lock().clone();
            let effective_proxy = new_cred.effective_proxy(global_proxy.as_ref());
            refresh_token(&new_cred, &self.config, effective_proxy.as_ref()).await?
        };

        // 4. 分配新 ID
        let new_id = {
            let entries = self.entries.lock();
            entries.iter().map(|e| e.id).max().unwrap_or(0) + 1
        };

        // 5. 设置 ID 并保留用户输入的元数据
        validated_cred.id = Some(new_id);
        validated_cred.priority = new_cred.priority;
        validated_cred.auth_method = new_cred.auth_method.map(|m| {
            if m.eq_ignore_ascii_case("builder-id") || m.eq_ignore_ascii_case("iam") {
                "idc".to_string()
            } else {
                m
            }
        });
        if new_cred.profile_arn.is_some() {
            validated_cred.profile_arn = new_cred.profile_arn;
        }
        validated_cred.provider = new_cred.provider;
        validated_cred.fill_default_profile_arn();
        validated_cred.client_id = new_cred.client_id;
        validated_cred.client_secret = new_cred.client_secret;
        validated_cred.region = new_cred.region;
        validated_cred.auth_region = new_cred.auth_region;
        validated_cred.api_region = new_cred.api_region;
        validated_cred.machine_id = new_cred.machine_id;
        validated_cred.email = new_cred.email;
        validated_cred.proxy_url = new_cred.proxy_url;
        validated_cred.proxy_username = new_cred.proxy_username;
        validated_cred.proxy_password = new_cred.proxy_password;
        validated_cred.kiro_api_key = new_cred.kiro_api_key;

        {
            let mut entries = self.entries.lock();
            entries.push(CredentialEntry {
                id: new_id,
                credentials: validated_cred,
                failure_count: 0,
                total_failure_count: 0,
                refresh_failure_count: 0,
                disabled: false,
                disabled_reason: None,
                success_count: 0,
                last_used_at: None,
                throttled_until: None,
            });
        }

        // 6. 升级为多凭据格式（确保后续 token rotation 能写盘）并持久化
        self.is_multiple_format.store(true, Ordering::Relaxed);
        self.persist_credentials()?;

        tracing::info!("成功添加凭据 #{}", new_id);
        Ok(new_id)
    }

    /// 更新凭据的可编辑字段（Admin API）
    ///
    /// 支持更新 email、proxy_url、proxy_username、proxy_password。
    /// 传 `None` 表示不修改该字段，传 `Some("")` 表示清除该字段。
    pub fn update_credential(
        &self,
        id: u64,
        email: Option<Option<String>>,
        proxy_url: Option<Option<String>>,
        proxy_username: Option<Option<String>>,
        proxy_password: Option<Option<String>>,
        groups: Option<Vec<String>>,
        source_channel: Option<Option<String>>,
    ) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            if let Some(v) = email {
                entry.credentials.email = v.filter(|s| !s.is_empty());
            }
            if let Some(v) = proxy_url {
                entry.credentials.proxy_url = v.filter(|s| !s.is_empty());
            }
            if let Some(v) = proxy_username {
                entry.credentials.proxy_username = v.filter(|s| !s.is_empty());
            }
            if let Some(v) = proxy_password {
                entry.credentials.proxy_password = v.filter(|s| !s.is_empty());
            }
            if let Some(g) = groups {
                entry.credentials.groups =
                    g.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            if let Some(v) = source_channel {
                entry.credentials.source_channel =
                    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            }
        }
        self.persist_credentials()?;
        Ok(())
    }

    /// 列出所有凭据当前引用的分组名（去重排序）。
    /// 用于启动迁移到 GroupManager 注册表，以及前端的引用计数显示。
    pub fn list_credential_groups(&self) -> Vec<String> {
        let entries = self.entries.lock();
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in entries.iter() {
            for g in &e.credentials.groups {
                if !g.is_empty() {
                    set.insert(g.clone());
                }
            }
        }
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        list
    }

    /// 统计指定分组被多少个凭据引用（用于分组管理页 / 删除前提示）。
    pub fn count_credentials_with_group(&self, group: &str) -> usize {
        let entries = self.entries.lock();
        entries
            .iter()
            .filter(|e| e.credentials.groups.iter().any(|g| g == group))
            .count()
    }

    /// 把所有凭据 `groups` 字段中等于 `old` 的元素改为 `new`（分组改名级联用）。
    /// 已经显式带 `new` 的凭据不会重复添加。返回受影响的凭据数。
    pub fn rename_credential_group(&self, old: &str, new: &str) -> anyhow::Result<usize> {
        let mut affected = 0usize;
        {
            let mut entries = self.entries.lock();
            for entry in entries.iter_mut() {
                let groups = &mut entry.credentials.groups;
                let mut hit = false;
                let mut already_has_new = false;
                for g in groups.iter() {
                    if g == old {
                        hit = true;
                    }
                    if g == new {
                        already_has_new = true;
                    }
                }
                if hit {
                    if already_has_new {
                        // old 和 new 共存：只去掉 old，避免重复
                        groups.retain(|g| g != old);
                    } else {
                        for g in groups.iter_mut() {
                            if g == old {
                                *g = new.to_string();
                            }
                        }
                    }
                    affected += 1;
                }
            }
        }
        if affected > 0 {
            self.persist_credentials()?;
        }
        Ok(affected)
    }

    /// 把 `name` 这个分组从所有凭据的 `groups` 字段中移除（强删分组级联用）。
    /// 返回受影响的凭据数。
    pub fn remove_credential_group(&self, name: &str) -> anyhow::Result<usize> {
        let mut affected = 0usize;
        {
            let mut entries = self.entries.lock();
            for entry in entries.iter_mut() {
                let before = entry.credentials.groups.len();
                entry.credentials.groups.retain(|g| g != name);
                if entry.credentials.groups.len() != before {
                    affected += 1;
                }
            }
        }
        if affected > 0 {
            self.persist_credentials()?;
        }
        Ok(affected)
    }

    /// 删除凭据（Admin API）
    ///
    /// # 前置条件
    /// - 凭据必须已禁用（disabled = true）
    ///
    /// # 行为
    /// 1. 验证凭据存在
    /// 2. 验证凭据已禁用
    /// 3. 从 entries 移除
    /// 4. 如果删除的是当前凭据，切换到优先级最高的可用凭据
    /// 5. 如果删除后没有凭据，将 current_id 重置为 0
    /// 6. 持久化到文件
    ///
    /// # 返回
    /// - `Ok(())` - 删除成功
    /// - `Err(_)` - 凭据不存在或持久化失败
    pub fn delete_credential(&self, id: u64) -> anyhow::Result<()> {
        let was_current = {
            let mut entries = self.entries.lock();

            // 查找凭据
            let _entry = entries
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            // 记录是否是当前凭据
            let current_id = *self.current_id.lock();
            let was_current = current_id == id;

            // 删除凭据
            entries.retain(|e| e.id != id);

            was_current
        };

        // 如果删除的是当前凭据，切换到优先级最高的可用凭据
        if was_current {
            self.select_highest_priority();
        }

        // 如果删除后没有任何凭据，将 current_id 重置为 0（与初始化行为保持一致）
        {
            let entries = self.entries.lock();
            if entries.is_empty() {
                let mut current_id = self.current_id.lock();
                *current_id = 0;
                tracing::info!("所有凭据已删除，current_id 已重置为 0");
            }
        }

        // 持久化更改
        self.persist_credentials()?;

        // 立即回写统计数据，清除已删除凭据的残留条目
        self.save_stats();

        tracing::info!("已删除凭据 #{}", id);
        Ok(())
    }

    /// 更新指定凭据的 refreshToken（Admin API）
    ///
    /// # 前置条件
    /// - 凭据必须已禁用（disabled = true），防止意外覆盖正在使用的 Token
    ///
    /// # 行为
    /// 1. 验证凭据存在且已禁用
    /// 2. 验证新 refreshToken 格式
    /// 3. 更新 refreshToken
    /// 4. 重置 refresh_failure_count（保持 disabled 状态，让用户手动启用）
    /// 5. 持久化到文件
    pub fn update_refresh_token(
        &self,
        id: u64,
        new_refresh_token: String,
        new_access_token: Option<String>,
        new_expires_at: Option<String>,
    ) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();

            // 用索引定位，避免两次线性扫描和后续 unwrap
            let idx = entries
                .iter()
                .position(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            if !entries[idx].disabled {
                anyhow::bail!(
                    "只能为已禁用的凭据更新 refreshToken（请先禁用凭据 #{}）",
                    id
                );
            }

            // 验证新 refreshToken 格式
            let tmp_creds = KiroCredentials {
                refresh_token: Some(new_refresh_token.clone()),
                ..entries[idx].credentials.clone()
            };
            validate_refresh_token(&tmp_creds)?;

            // 检查是否与现有其他凭据重复
            let new_hash = sha256_hex(&new_refresh_token);
            let duplicate = entries.iter().enumerate().any(|(i, e)| {
                i != idx
                    && e.credentials
                        .refresh_token
                        .as_ref()
                        .map(|t| sha256_hex(t) == new_hash)
                        .unwrap_or(false)
            });
            if duplicate {
                anyhow::bail!("refreshToken 与其他凭据重复");
            }

            let entry = &mut entries[idx];
            entry.credentials.refresh_token = Some(new_refresh_token);
            // 若调用方提供了 accessToken（来自导入/导出），则直接保留，无需立即调认证服务器
            // 否则清空，下次使用时系统会自动刷新
            entry.credentials.access_token = new_access_token;
            entry.credentials.expires_at = new_expires_at;
            entry.refresh_failure_count = 0;
        }
        self.persist_credentials()?;
        tracing::info!("凭据 #{} refreshToken 已更新", id);
        Ok(())
    }

    /// 强制刷新指定凭据的 Token（Admin API）
    ///
    /// 无条件调用上游 API 重新获取 access token，不检查是否过期。
    /// 适用于排查问题、Token 异常但未过期、主动更新凭据状态等场景。
    pub async fn force_refresh_token_for(&self, id: u64) -> anyhow::Result<()> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // 获取刷新锁防止并发刷新
        let _guard = self.refresh_lock.lock().await;

        // 无条件调用 refresh_token
        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        let new_creds = refresh_token(&credentials, &self.config, effective_proxy.as_ref()).await?;

        // 更新 entries 中对应凭据
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.credentials = new_creds;
                entry.refresh_failure_count = 0;
            }
        }

        // 持久化
        if let Err(e) = self.persist_credentials() {
            tracing::warn!("强制刷新 Token 后持久化失败: {}", e);
        }

        tracing::info!("凭据 #{} Token 已强制刷新", id);
        Ok(())
    }

    /// 获取负载均衡模式（Admin API）
    pub fn get_load_balancing_mode(&self) -> String {
        self.load_balancing_mode.lock().clone()
    }

    fn persist_load_balancing_mode(&self, mode: &str) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，负载均衡模式仅在当前进程生效: {}", mode);
                return Ok(());
            }
        };

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.load_balancing_mode = mode.to_string();
        config
            .save()
            .with_context(|| format!("持久化负载均衡模式失败: {}", config_path.display()))?;

        Ok(())
    }

    /// 设置负载均衡模式（Admin API）
    pub fn set_load_balancing_mode(&self, mode: String) -> anyhow::Result<()> {
        // 验证模式值
        if mode != "priority" && mode != "balanced" {
            anyhow::bail!("无效的负载均衡模式: {}", mode);
        }

        let previous_mode = self.get_load_balancing_mode();
        if previous_mode == mode {
            return Ok(());
        }

        *self.load_balancing_mode.lock() = mode.clone();

        if let Err(err) = self.persist_load_balancing_mode(&mode) {
            *self.load_balancing_mode.lock() = previous_mode;
            return Err(err);
        }

        tracing::info!("负载均衡模式已设置为: {}", mode);
        Ok(())
    }

    /// 获取账号级风控故障转移配置（Admin API）
    pub fn get_account_throttle_failover(&self) -> bool {
        self.account_throttle_failover.load(Ordering::Relaxed)
    }

    /// 获取账号级风控冷却时长秒数（Admin API）
    pub fn get_account_throttle_cooldown_secs(&self) -> u64 {
        self.account_throttle_cooldown_secs.load(Ordering::Relaxed)
    }

    /// 设置账号级风控故障转移配置（Admin API）
    ///
    /// 任一参数传 `None` 表示不修改该字段。
    pub fn set_account_throttle_config(
        &self,
        failover: Option<bool>,
        cooldown_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        if let Some(secs) = cooldown_secs {
            // 限定一个合理范围：1 秒到 24 小时
            if !(1..=86_400).contains(&secs) {
                anyhow::bail!("冷却时长必须在 1..=86400 秒内: {}", secs);
            }
        }

        let prev_failover = self.get_account_throttle_failover();
        let prev_cooldown = self.get_account_throttle_cooldown_secs();
        let new_failover = failover.unwrap_or(prev_failover);
        let new_cooldown = cooldown_secs.unwrap_or(prev_cooldown);

        if new_failover == prev_failover && new_cooldown == prev_cooldown {
            return Ok(());
        }

        self.account_throttle_failover
            .store(new_failover, Ordering::Relaxed);
        self.account_throttle_cooldown_secs
            .store(new_cooldown, Ordering::Relaxed);

        if let Err(err) = self.persist_account_throttle_config(new_failover, new_cooldown) {
            // 回滚内存值
            self.account_throttle_failover
                .store(prev_failover, Ordering::Relaxed);
            self.account_throttle_cooldown_secs
                .store(prev_cooldown, Ordering::Relaxed);
            return Err(err);
        }

        tracing::info!(
            "账号级风控配置已更新: failover={}, cooldown_secs={}",
            new_failover,
            new_cooldown
        );
        Ok(())
    }

    fn persist_account_throttle_config(
        &self,
        failover: bool,
        cooldown_secs: u64,
    ) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，账号级风控配置仅在当前进程生效");
                return Ok(());
            }
        };

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.account_throttle_failover = failover;
        config.account_throttle_cooldown_secs = cooldown_secs;
        config
            .save()
            .with_context(|| format!("持久化账号级风控配置失败: {}", config_path.display()))?;

        Ok(())
    }
}

impl Drop for MultiTokenManager {
    fn drop(&mut self) {
        if self.stats_dirty.load(Ordering::Relaxed) {
            self.save_stats();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_token_expired_with_expired_token() {
        let mut credentials = KiroCredentials::default();
        credentials.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        assert!(is_token_expired(&credentials));
    }

    // ── B1: 个人 Builder ID profileArn 解析「确定性不支持 vs 瞬态错」区分 ──
    #[test]
    fn definitive_unsupported_true_on_403_forbidden() {
        // 纯个人 Builder ID 上游返回 403 → 确定性不支持（重试无意义）
        assert!(is_definitive_profile_unsupported(
            reqwest::StatusCode::FORBIDDEN,
            r#"{"message":"AWS Builder ID is not supported for this operation.","reason":null}"#,
        ));
    }

    #[test]
    fn definitive_unsupported_true_on_not_supported_body_any_status() {
        // body 明确说「不支持」即使状态码非 403 也算确定性
        assert!(is_definitive_profile_unsupported(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"message":"This operation is not supported for this credential type."}"#,
        ));
    }

    #[test]
    fn definitive_unsupported_false_on_transient_5xx() {
        // 5xx 服务端瞬态错 → 不是确定性，应继续重试（不标已尝试）
        assert!(!is_definitive_profile_unsupported(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"message":"internal error"}"#,
        ));
        assert!(!is_definitive_profile_unsupported(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "",
        ));
    }

    #[test]
    fn definitive_unsupported_false_on_429_throttle() {
        // 429 限流是瞬态，不该被当成「确定性不支持」而永久回退占位符
        assert!(!is_definitive_profile_unsupported(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            r#"{"message":"Too many requests"}"#,
        ));
    }

    #[test]
    fn test_is_token_expired_with_valid_token() {
        let mut credentials = KiroCredentials::default();
        let future = Utc::now() + Duration::hours(1);
        credentials.expires_at = Some(future.to_rfc3339());
        assert!(!is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_within_5_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(3);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_no_expires_at() {
        let credentials = KiroCredentials::default();
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_within_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(8);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_beyond_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(15);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(!is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_validate_refresh_token_missing() {
        let credentials = KiroCredentials::default();
        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_refresh_token_valid() {
        let mut credentials = KiroCredentials::default();
        credentials.refresh_token = Some("a".repeat(150));
        let result = validate_refresh_token(&credentials);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sha256_hex() {
        let result = sha256_hex("test");
        assert_eq!(
            result,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_api_key_credential() {
        let config = Config::default();
        let mut credentials = KiroCredentials::default();
        credentials.kiro_api_key = Some("ksk_test_key_123".to_string());
        credentials.auth_method = Some("api_key".to_string());

        let result = refresh_token(&credentials, &config, None).await;

        assert!(result.is_err(), "API Key 凭据应被 refresh_token 拒绝");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("API Key 凭据不支持刷新"),
            "期望错误消息包含 'API Key 凭据不支持刷新'，实际: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_refresh_token() {
        let config = Config::default();

        let mut existing = KiroCredentials::default();
        existing.refresh_token = Some("a".repeat(150));

        let manager = MultiTokenManager::new(config, vec![existing], None, None, false).unwrap();

        let mut duplicate = KiroCredentials::default();
        duplicate.refresh_token = Some("a".repeat(150));

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("凭据已存在"));
    }

    #[tokio::test]
    async fn test_add_credential_api_key_success() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut api_key_cred = KiroCredentials::default();
        api_key_cred.kiro_api_key = Some("ksk_test_key_123".to_string());
        api_key_cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        let id = result.unwrap();
        assert!(id > 0);
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_api_key() {
        let config = Config::default();

        let mut existing = KiroCredentials::default();
        existing.kiro_api_key = Some("ksk_existing_key".to_string());
        existing.auth_method = Some("api_key".to_string());

        let manager = MultiTokenManager::new(config, vec![existing], None, None, false).unwrap();

        let mut duplicate = KiroCredentials::default();
        duplicate.kiro_api_key = Some("ksk_existing_key".to_string());
        duplicate.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("kiroApiKey 重复")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_empty_rejected() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some(String::new());
        cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("kiroApiKey 为空")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_missing_key_rejected() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("api_key".to_string());
        // kiro_api_key is None

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("缺少 kiroApiKey")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_and_oauth_coexist() {
        let config = Config::default();

        let mut oauth_cred = KiroCredentials::default();
        oauth_cred.refresh_token = Some("a".repeat(150));

        let manager = MultiTokenManager::new(config, vec![oauth_cred], None, None, false).unwrap();

        let mut api_key_cred = KiroCredentials::default();
        api_key_cred.kiro_api_key = Some("ksk_new_key".to_string());
        api_key_cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    // MultiTokenManager 测试

    #[test]
    fn test_multi_token_manager_new() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.priority = 0;
        let mut cred2 = KiroCredentials::default();
        cred2.priority = 1;

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    #[test]
    fn test_multi_token_manager_empty_credentials() {
        let config = Config::default();
        let result = MultiTokenManager::new(config, vec![], None, None, false);
        // 支持 0 个凭据启动（可通过管理面板添加）
        assert!(result.is_ok());
        let manager = result.unwrap();
        assert_eq!(manager.total_count(), 0);
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_duplicate_ids() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.id = Some(1);
        let mut cred2 = KiroCredentials::default();
        cred2.id = Some(1); // 重复 ID

        let result = MultiTokenManager::new(config, vec![cred1, cred2], None, None, false);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("重复的凭据 ID"),
            "错误消息应包含 '重复的凭据 ID'，实际: {}",
            err_msg
        );
    }

    #[test]
    fn test_multi_token_manager_api_key_missing_kiro_api_key_auto_disabled() {
        let config = Config::default();

        // auth_method=api_key 但缺少 kiro_api_key → 应被自动禁用
        let mut bad_cred = KiroCredentials::default();
        bad_cred.auth_method = Some("api_key".to_string());
        // kiro_api_key 保持 None

        let mut good_cred = KiroCredentials::default();
        good_cred.refresh_token = Some("valid_token".to_string());

        let manager =
            MultiTokenManager::new(config, vec![bad_cred, good_cred], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 1); // bad_cred 被禁用，只剩 1 个可用
    }

    #[test]
    fn test_multi_token_manager_api_key_with_kiro_api_key_not_disabled() {
        let config = Config::default();

        // auth_method=api_key 且有 kiro_api_key → 不应被禁用
        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("api_key".to_string());
        cred.kiro_api_key = Some("ksk_test123".to_string());

        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_report_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        // 连续失败 MAX_FAILURES_PER_CREDENTIAL 次才禁用（用常量，跟阈值联动）
        let n = MAX_FAILURES_PER_CREDENTIAL;

        // ID 1：前 n-1 次失败不禁用
        for _ in 0..(n - 1) {
            assert!(manager.report_failure(1));
        }
        assert_eq!(manager.available_count(), 2);

        // 第 n 次失败禁用第一个凭据
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 1);

        // ID 2：再失败 n 次，最后一次返回 false（全部禁用）
        for _ in 0..(n - 1) {
            assert!(manager.report_failure(2));
        }
        assert!(!manager.report_failure(2));
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_report_success() {
        let config = Config::default();
        let cred = KiroCredentials::default();

        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();

        // 失败两次（使用 ID 1）
        manager.report_failure(1);
        manager.report_failure(1);

        // 成功后重置计数（使用 ID 1）
        manager.report_success(1);

        // 再失败两次不会禁用
        manager.report_failure(1);
        manager.report_failure(1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_switch_to_next() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.refresh_token = Some("token1".to_string());
        let mut cred2 = KiroCredentials::default();
        cred2.refresh_token = Some("token2".to_string());

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        let initial_id = manager.snapshot().current_id;

        // 切换到下一个
        assert!(manager.switch_to_next());
        assert_ne!(manager.snapshot().current_id, initial_id);
    }

    #[test]
    fn test_set_load_balancing_mode_persists_to_config_file() {
        let config_path =
            std::env::temp_dir().join(format!("kiro-load-balancing-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&config_path, r#"{"loadBalancingMode":"priority"}"#).unwrap();

        let config = Config::load(&config_path).unwrap();
        let manager =
            MultiTokenManager::new(config, vec![KiroCredentials::default()], None, None, false)
                .unwrap();

        manager
            .set_load_balancing_mode("balanced".to_string())
            .unwrap();

        let persisted = Config::load(&config_path).unwrap();
        assert_eq!(persisted.load_balancing_mode, "balanced");
        assert_eq!(manager.get_load_balancing_mode(), "balanced");

        std::fs::remove_file(&config_path).unwrap();
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_auto_recovers_all_disabled() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.access_token = Some("t1".to_string());
        cred1.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());
        let mut cred2 = KiroCredentials::default();
        cred2.access_token = Some("t2".to_string());
        cred2.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(1);
        }
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(2);
        }

        assert_eq!(manager.available_count(), 0);

        // 应触发自愈：重置失败计数并重新启用，避免必须重启进程
        let ctx = manager.acquire_context(None, None, None).await.unwrap();
        assert!(ctx.token == "t1" || ctx.token == "t2");
        assert_eq!(manager.available_count(), 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_balanced_retries_until_bad_credential_disabled()
     {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut bad_cred = KiroCredentials::default();
        bad_cred.priority = 0;
        bad_cred.refresh_token = Some("bad".to_string());

        let mut good_cred = KiroCredentials::default();
        good_cred.priority = 1;
        good_cred.access_token = Some("good-token".to_string());
        good_cred.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![bad_cred, good_cred], None, None, false).unwrap();

        let ctx = manager.acquire_context(None, None, None).await.unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "good-token");
    }

    #[test]
    fn test_multi_token_manager_report_refresh_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        assert_eq!(manager.available_count(), 2);
        for _ in 0..(MAX_FAILURES_PER_CREDENTIAL - 1) {
            assert!(manager.report_refresh_failure(1));
        }
        assert_eq!(manager.available_count(), 2);

        assert!(manager.report_refresh_failure(1));
        assert_eq!(manager.available_count(), 1);

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled);
        assert_eq!(first.refresh_failure_count, MAX_FAILURES_PER_CREDENTIAL);
        assert_eq!(snapshot.current_id, 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_refresh_failure_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_refresh_failure(1);
            manager.report_refresh_failure(2);
        }
        assert_eq!(manager.available_count(), 0);

        let err = manager
            .acquire_context(None, None, None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
    }

    #[test]
    fn test_multi_token_manager_report_quota_exhausted() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        assert_eq!(manager.available_count(), 2);
        assert!(manager.report_quota_exhausted(1));
        assert_eq!(manager.available_count(), 1);

        // 再禁用第二个后，无可用凭据
        assert!(!manager.report_quota_exhausted(2));
        assert_eq!(manager.available_count(), 0);
    }

    #[tokio::test]
    async fn test_multi_token_manager_quota_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        manager.report_quota_exhausted(1);
        manager.report_quota_exhausted(2);
        assert_eq!(manager.available_count(), 0);

        let err = manager
            .acquire_context(None, None, None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
        assert_eq!(manager.available_count(), 0);
    }

    // ============ 凭据级 Region 优先级测试 ============

    #[test]
    fn test_credential_region_priority_uses_credential_auth_region() {
        // 凭据配置了 auth_region 时，应使用凭据的 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("eu-west-1".to_string());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-west-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_credential_region() {
        // 凭据未配置 auth_region 但配置了 region 时，应回退到凭据.region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.region = Some("eu-central-1".to_string());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-central-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_config() {
        // 凭据未配置 auth_region 和 region 时，应回退到 config
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials::default();
        assert!(credentials.auth_region.is_none());
        assert!(credentials.region.is_none());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn test_multiple_credentials_use_respective_regions() {
        // 多凭据场景下，不同凭据使用各自的 auth_region
        let mut config = Config::default();
        config.region = "ap-northeast-1".to_string();

        let mut cred1 = KiroCredentials::default();
        cred1.auth_region = Some("us-east-1".to_string());

        let mut cred2 = KiroCredentials::default();
        cred2.region = Some("eu-west-1".to_string());

        let cred3 = KiroCredentials::default(); // 无 region，使用 config

        assert_eq!(cred1.effective_auth_region(&config), "us-east-1");
        assert_eq!(cred2.effective_auth_region(&config), "eu-west-1");
        assert_eq!(cred3.effective_auth_region(&config), "ap-northeast-1");
    }

    #[test]
    fn test_idc_oidc_endpoint_uses_credential_auth_region() {
        // 验证 IdC OIDC endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("eu-central-1".to_string());

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);

        assert_eq!(refresh_url, "https://oidc.eu-central-1.amazonaws.com/token");
    }

    #[test]
    fn test_social_refresh_endpoint_uses_credential_auth_region() {
        // 验证 Social refresh endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("ap-southeast-1".to_string());

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);

        assert_eq!(
            refresh_url,
            "https://prod.ap-southeast-1.auth.desktop.kiro.dev/refreshToken"
        );
    }

    #[test]
    fn test_api_call_uses_effective_api_region() {
        // 验证 API 调用使用 effective_api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.region = Some("eu-west-1".to_string());

        // 凭据.region 不参与 api_region 回退链
        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.us-west-2.amazonaws.com");
    }

    #[test]
    fn test_api_call_uses_credential_api_region() {
        // 凭据配置了 api_region 时，API 调用应使用凭据的 api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.api_region = Some("eu-central-1".to_string());

        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.eu-central-1.amazonaws.com");
    }

    #[test]
    fn test_rest_api_region_candidates_us_default() {
        // 非 EU 区域 → 主端点 us-east-1，回退 eu-central-1
        assert_eq!(
            rest_api_region_candidates("us-east-1"),
            ["us-east-1", "eu-central-1"]
        );
        assert_eq!(
            rest_api_region_candidates("us-east-2"),
            ["us-east-1", "eu-central-1"]
        );
        assert_eq!(
            rest_api_region_candidates("ap-southeast-1"),
            ["us-east-1", "eu-central-1"]
        );
    }

    #[test]
    fn test_rest_api_region_candidates_eu() {
        // EU 区域 → 主端点 eu-central-1，回退 us-east-1
        assert_eq!(
            rest_api_region_candidates("eu-central-1"),
            ["eu-central-1", "us-east-1"]
        );
        assert_eq!(
            rest_api_region_candidates("eu-west-1"),
            ["eu-central-1", "us-east-1"]
        );
        assert_eq!(
            rest_api_region_candidates("eu-north-1"),
            ["eu-central-1", "us-east-1"]
        );
    }

    #[test]
    fn test_rest_api_region_candidates_uses_credential_auth_region() {
        // Enterprise/IdC 账号导入时仅带 SSO region 字段（无 api_region），
        // effective_auth_region 会回退到 credential.region，进而选对端点。
        let config = Config::default(); // 默认 region = us-east-1

        let mut eu_cred = KiroCredentials::default();
        eu_cred.region = Some("eu-west-1".to_string());
        let sso_region = eu_cred.effective_auth_region(&config);
        assert_eq!(
            rest_api_region_candidates(sso_region),
            ["eu-central-1", "us-east-1"]
        );

        // 未配置任何 region 的凭据回退到 config 默认 us-east-1
        let plain_cred = KiroCredentials::default();
        let sso_region = plain_cred.effective_auth_region(&config);
        assert_eq!(
            rest_api_region_candidates(sso_region),
            ["us-east-1", "eu-central-1"]
        );
    }

    #[test]
    fn test_credential_region_empty_string_treated_as_set() {
        // 空字符串 auth_region 被视为已设置（虽然不推荐，但行为应一致）
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("".to_string());

        let region = credentials.effective_auth_region(&config);
        // 空字符串被视为已设置，不会回退到 config
        assert_eq!(region, "");
    }

    #[test]
    fn test_auth_and_api_region_independent() {
        // auth_region 和 api_region 互不影响
        let mut config = Config::default();
        config.region = "default".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("auth-only".to_string());
        credentials.api_region = Some("api-only".to_string());

        assert_eq!(credentials.effective_auth_region(&config), "auth-only");
        assert_eq!(credentials.effective_api_region(&config), "api-only");
    }

    // ── is_multiple_format 自动升级 ──────────────────────────────────────────

    fn tmp_creds_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kiro_test_{}.json", name));
        p
    }

    /// 单凭据格式（is_multiple_format=false）启动时自动迁移为数组格式，
    /// 迁移后 persist_credentials 能正确写盘，token rotation 不再丢失。
    #[test]
    fn test_single_format_auto_migrates_to_multiple_on_startup() {
        let path = tmp_creds_path("single_migrate");
        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some("ksk_test_migrate_key".to_string());
        cred.auth_method = Some("api_key".to_string());
        let single_json = serde_json::to_string(&cred).unwrap();
        std::fs::write(&path, &single_json).unwrap();

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(path.clone()),
            false,
        )
        .unwrap();

        assert!(
            manager.is_multiple_format.load(Ordering::Relaxed),
            "单凭据格式应在启动时自动升级为 true"
        );

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.trim_start().starts_with('['),
            "迁移后文件应为数组格式，实际: {}",
            &content[..content.len().min(50)]
        );

        let _ = std::fs::remove_file(&path);
    }

    /// 空凭据列表时不触发迁移
    #[test]
    fn test_empty_credentials_no_migration() {
        let path = tmp_creds_path("empty_no_migrate");
        std::fs::write(&path, "{}").unwrap();

        let manager =
            MultiTokenManager::new(Config::default(), vec![], None, Some(path.clone()), false)
                .unwrap();

        assert!(
            !manager.is_multiple_format.load(Ordering::Relaxed),
            "无凭据时不应触发格式升级"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// add_credential 后 is_multiple_format 必须升级为 true，文件写为数组格式
    #[tokio::test(flavor = "multi_thread")]
    async fn test_add_credential_upgrades_multiple_format() {
        let path = tmp_creds_path("add_cred_upgrade");
        std::fs::write(&path, "[]").unwrap();

        let manager =
            MultiTokenManager::new(Config::default(), vec![], None, Some(path.clone()), false)
                .unwrap();

        assert!(!manager.is_multiple_format.load(Ordering::Relaxed));

        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some("ksk_test_upgrade_key".to_string());
        cred.auth_method = Some("api_key".to_string());

        manager.add_credential(cred).await.unwrap();

        assert!(
            manager.is_multiple_format.load(Ordering::Relaxed),
            "add_credential 后 is_multiple_format 应升级为 true"
        );

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.trim_start().starts_with('['),
            "add_credential 后文件应为数组格式"
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── try_reload_credential_from_file ─────────────────────────────────────

    /// 文件中有新 refreshToken 时，reload 返回 true 并更新内存凭据
    #[test]
    fn test_reload_from_file_succeeds_when_token_rotated() {
        let path = tmp_creds_path("reload_rotated");

        // 初始 token
        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.refresh_token = Some("original_token_aaaa".repeat(10));
        let initial_json = serde_json::to_vec_pretty(&[&cred]).unwrap();
        std::fs::write(&path, &initial_json).unwrap();

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(path.clone()),
            true,
        )
        .unwrap();

        // 模拟 IDE rotation：文件写入新 token
        let mut updated_cred = KiroCredentials::default();
        updated_cred.id = Some(1);
        updated_cred.refresh_token = Some("rotated_token_bbbb".repeat(10));
        updated_cred.access_token = Some("new_access".to_string());
        let updated_json = serde_json::to_vec_pretty(&[&updated_cred]).unwrap();
        std::fs::write(&path, &updated_json).unwrap();

        let reloaded = manager.try_reload_credential_from_file(1);
        assert!(reloaded, "文件中有新 token，reload 应返回 true");

        let snapshot = manager.snapshot();
        let entry = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(!entry.disabled, "reload 后凭据应重新启用");
        assert_eq!(entry.failure_count, 0);

        let _ = std::fs::remove_file(&path);
    }

    /// 文件 token 与内存相同时，reload 返回 false（无更新可用）
    #[test]
    fn test_reload_from_file_returns_false_when_token_unchanged() {
        let path = tmp_creds_path("reload_unchanged");

        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.refresh_token = Some("same_token".repeat(15));
        let json = serde_json::to_vec_pretty(&[&cred]).unwrap();
        std::fs::write(&path, &json).unwrap();

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(path.clone()),
            true,
        )
        .unwrap();

        let reloaded = manager.try_reload_credential_from_file(1);
        assert!(!reloaded, "token 未变化，reload 应返回 false");

        let _ = std::fs::remove_file(&path);
    }

    /// 未配置 credentials_path 时，reload 返回 false
    #[test]
    fn test_reload_from_file_returns_false_without_path() {
        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.refresh_token = Some("some_token".repeat(15));

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            None, // 无文件路径
            false,
        )
        .unwrap();

        let reloaded = manager.try_reload_credential_from_file(1);
        assert!(!reloaded, "无 credentials_path 时应返回 false");
    }

    /// 单凭据文件无 ID 字段时，通过单凭据规则匹配
    #[test]
    fn test_reload_from_file_single_credential_no_id() {
        let path = tmp_creds_path("reload_single_no_id");

        // 初始：无 ID 字段
        let mut cred = KiroCredentials::default();
        cred.refresh_token = Some("original_no_id".repeat(10));
        let initial_json = serde_json::to_vec_pretty(&[&cred]).unwrap();
        std::fs::write(&path, &initial_json).unwrap();

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(path.clone()),
            true,
        )
        .unwrap();

        // 文件更新为新 token（无 ID）
        let mut updated = KiroCredentials::default();
        updated.refresh_token = Some("rotated_no_id".repeat(10));
        let updated_json = serde_json::to_vec_pretty(&[&updated]).unwrap();
        std::fs::write(&path, &updated_json).unwrap();

        // 获取实际 ID（manager 自动分配）
        let actual_id = manager.snapshot().entries[0].id;
        let reloaded = manager.try_reload_credential_from_file(actual_id);
        assert!(reloaded, "单凭据无 ID 时仍应能匹配并 reload");

        let _ = std::fs::remove_file(&path);
    }

    // ===== 账号分组隔离回归测试 =====

    /// 构造一个带 token、属于指定分组的可用凭据
    fn grouped_cred(token: &str, groups: &[&str]) -> KiroCredentials {
        let mut c = KiroCredentials::default();
        c.access_token = Some(token.to_string());
        c.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());
        c.groups = groups.iter().map(|s| s.to_string()).collect();
        c
    }

    #[test]
    fn test_group_matches_helper() {
        // 未绑定分组(None)匹配任何账号
        assert!(group_matches(&[], None));
        assert!(group_matches(&["g1".to_string()], None));
        // 绑定分组时只匹配 groups 含该名的账号
        assert!(group_matches(&["g1".to_string(), "g2".to_string()], Some("g1")));
        assert!(!group_matches(&["g2".to_string()], Some("g1")));
        assert!(!group_matches(&[], Some("g1")));
    }

    #[test]
    fn test_select_next_credential_filters_by_group() {
        // A∈g1, B∈g2, C∈无分组
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![
                grouped_cred("a", &["g1"]),
                grouped_cred("b", &["g2"]),
                grouped_cred("c", &[]),
            ],
            None,
            None,
            false,
        )
        .unwrap();

        // g1 只能选到 A(id=1)
        let g1 = manager.select_next_credential(None, Some("g1"), None);
        assert_eq!(g1.map(|(id, _)| id), Some(1));
        // g2 只能选到 B(id=2)
        let g2 = manager.select_next_credential(None, Some("g2"), None);
        assert_eq!(g2.map(|(id, _)| id), Some(2));
        // 不存在的分组 → 无可用账号
        assert!(manager.select_next_credential(None, Some("nope"), None).is_none());
        // 未绑定分组(None) → 可选到账号
        assert!(manager.select_next_credential(None, None, None).is_some());
    }

    #[test]
    fn test_total_count_in_group() {
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![
                grouped_cred("a", &["g1"]),
                grouped_cred("b", &["g1", "g2"]),
                grouped_cred("c", &[]),
            ],
            None,
            None,
            false,
        )
        .unwrap();

        assert_eq!(manager.total_count_in_group(Some("g1")), 2); // A,B
        assert_eq!(manager.total_count_in_group(Some("g2")), 1); // B
        assert_eq!(manager.total_count_in_group(None), 3); // 全部
        assert_eq!(manager.total_count_in_group(Some("none")), 0);
    }

    #[test]
    fn test_balanced_mode_independent_per_group() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        // g1: A(id1),B(id2)；g2: C(id3)
        let manager = MultiTokenManager::new(
            config,
            vec![
                grouped_cred("a", &["g1"]),
                grouped_cred("b", &["g1"]),
                grouped_cred("c", &["g2"]),
            ],
            None,
            None,
            false,
        )
        .unwrap();

        // 让 A(id1) 承载较多请求（RPM 升高）→ balanced 应转向负载更低的 B(id2)
        manager.note_request(1);
        manager.note_request(1);
        let pick = manager.select_next_credential(None, Some("g1"), None);
        assert_eq!(pick.map(|(id, _)| id), Some(2), "balanced 应在 g1 内选 RPM 最低的 B");
        // g2 不受 g1 负载影响，仍只会选到 C(id3)
        let pick_g2 = manager.select_next_credential(None, Some("g2"), None);
        assert_eq!(pick_g2.map(|(id, _)| id), Some(3));
    }

    #[tokio::test]
    async fn test_acquire_context_strict_isolation_fails_when_group_empty() {
        // g1 只有一个账号 A(id1)，禁用后绑定 g1 的请求应直接失败，不回退到 g2/无分组
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![
                grouped_cred("a", &["g1"]),
                grouped_cred("b", &["g2"]),
                grouped_cred("c", &[]),
            ],
            None,
            None,
            false,
        )
        .unwrap();

        // 正常情况下 g1 能拿到 context
        assert!(manager.acquire_context(None, Some("g1"), None).await.is_ok());

        // 手动禁用 g1 内唯一账号 A(id1)
        manager.set_disabled(1, true).unwrap();

        // 严格隔离：g1 无可用账号 → Err，且不会选到 B/C
        let res = manager.acquire_context(None, Some("g1"), None).await;
        assert!(res.is_err(), "g1 内全部账号禁用后应失败，不回退到其他分组");

        // 但 g2 仍可用
        assert!(manager.acquire_context(None, Some("g2"), None).await.is_ok());
    }

    // ===== 多号 + session affinity 单测 =====

    /// 构造一个开启多号 affinity 的双号 manager（两个直连号，无分组）。
    fn affinity_manager(mut config: Config) -> MultiTokenManager {
        config.adaptive_limit.multi_account.enabled = true;
        MultiTokenManager::new(
            config,
            vec![grouped_cred("t1", &[]), grouped_cred("t2", &[])],
            None,
            None,
            false,
        )
        .unwrap()
    }

    // RPM 计数器：累计 + 按号隔离 + 未知号为 0。
    #[test]
    fn test_rpm_counter_counts_and_isolates() {
        let manager = affinity_manager(Config::default());
        assert_eq!(manager.rpm(1), 0);
        manager.note_request(1);
        manager.note_request(1);
        manager.note_request(2);
        assert_eq!(manager.rpm(1), 2);
        assert_eq!(manager.rpm(2), 1);
        assert_eq!(manager.rpm(999), 0, "未知号 RPM 应为 0");
    }

    // 无 session_key（None / 空串）：不绑定，直接选号，且不写 affinity 映射。
    #[test]
    fn test_affinity_no_session_key_load_select() {
        let manager = affinity_manager(Config::default());
        let p = manager.select_with_affinity(None, None, None).unwrap();
        assert!(p.0 == 1 || p.0 == 2);
        assert!(
            manager.affinity.lock().is_empty(),
            "无 session 不应建立绑定"
        );
        let p_empty = manager.select_with_affinity(None, None, Some("")).unwrap();
        assert!(p_empty.0 == 1 || p_empty.0 == 2);
        assert!(
            manager.affinity.lock().is_empty(),
            "空 session 不应建立绑定"
        );
    }

    // 新会话落号后黏定：同一 session 反复选号都黏同一个号。
    #[test]
    fn test_affinity_new_session_binds_and_sticks() {
        let manager = affinity_manager(Config::default());
        let p1 = manager
            .select_with_affinity(None, None, Some("sess-A"))
            .unwrap();
        let p2 = manager
            .select_with_affinity(None, None, Some("sess-A"))
            .unwrap();
        assert_eq!(p1.0, p2.0, "同一会话应黏定同一号");
        assert_eq!(
            manager.affinity.lock().get("sess-A").map(|b| b.credential_id),
            Some(p1.0)
        );
    }

    // H3 回归（并发串号竞态）：多个同会话请求并发选号，必须全部收敛到同一个号。
    // 旧实现里 NewBind 无条件覆盖绑定，pick_from_pool 期间不持锁，两请求各 pick 不同号
    // → 同会话串号(封号高危)。check-and-adopt 修复后：提交时锁内 re-check 采纳已有绑定。
    #[tokio::test]
    async fn test_concurrent_same_session_converges_to_one_account() {
        let manager = std::sync::Arc::new(affinity_manager(Config::default()));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let m = manager.clone();
            handles.push(tokio::spawn(async move {
                m.select_with_affinity(None, None, Some("sess-RACE")).map(|p| p.0)
            }));
        }
        let mut ids = std::collections::HashSet::new();
        for h in handles {
            if let Ok(Some(id)) = h.await {
                ids.insert(id);
            }
        }
        let bound = manager.affinity.lock().get("sess-RACE").map(|b| b.credential_id);
        assert!(bound.is_some(), "并发后会话应有绑定");
        assert_eq!(
            ids.len(),
            1,
            "同会话并发选号必须收敛到同一个号，实际落到 {ids:?}（串号=封号高危）"
        );
    }

    // M2 回归：所有号都 OPEN 熔断时，选号不应返回 None（导致 acquire_context bail），
    // 而应退到 cooldown 最短的号——保证「有号可用」，由 limiter 自行排队/退避。
    #[tokio::test]
    async fn test_all_open_falls_back_to_shortest_cooldown() {
        let mut config = Config::default();
        config.adaptive_limit.circuit_breaker.open_429_threshold = 1;
        config.adaptive_limit.user_cooldown_base_secs = 30;
        let manager = affinity_manager(config);
        for id in [1u64, 2u64] {
            let lim = manager
                .limiters()
                .for_scope(&ThrottleScope::UserCredential(id));
            for _ in 0..3 {
                lim.on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                    .await;
            }
        }
        let pick = manager.select_with_affinity(None, None, Some("sess-AO"));
        assert!(
            pick.is_some(),
            "全 OPEN 时应退到 cooldown 最短号，而非返回 None 导致整体 bail"
        );
    }

    // 两个不同新会话按最低负载分流到不同号；同会话再来仍黏原号。
    #[tokio::test]
    async fn test_affinity_new_sessions_distribute_by_load() {
        let manager = affinity_manager(Config::default());
        let c1 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        let c2 = manager
            .acquire_context(None, None, Some("sess-B"))
            .await
            .unwrap();
        assert_ne!(c1.id, c2.id, "两个新会话应按最低负载分到不同号");
        let c1b = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        assert_eq!(c1b.id, c1.id, "同一会话应黏回原号");
    }

    // Task 7 回归（#19 满载不迁给 #18 根治）：负载再平衡按「真实利用率」而非会话数。
    // 构造：原号 t1 满载(高 429 + rate 贴 safe_hi=高利用率)，目标 t2 空闲(低利用率)，
    // 即便 t1 的会话数不比 t2 多，也必须把会话迁到 t2。
    #[tokio::test]
    async fn test_rebalance_by_utilization_not_session_count() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_debounce_secs = 0; // 不防抖，便于断言
        config.adaptive_limit.multi_account.rebalance_utilization_gap = 0.3;
        let manager = affinity_manager(config);
        // 先把 sess-X 绑到 t1(id=1)。
        let c = manager.acquire_context(None, None, Some("sess-X")).await.unwrap();
        let busy = c.id;
        let idle = if busy == 1 { 2 } else { 1 };
        // 让 busy 号「满载」：撞几次 429 → rate 降、429 率拉高 → 利用率高。
        let busy_lim = manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(busy));
        for _ in 0..3 {
            busy_lim
                .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                .await;
        }
        // idle 号保持干净（无 429）→ 利用率低。
        // 选号：sess-X 仍黏 busy，但 busy 利用率远高于 idle → 应触发利用率再平衡迁到 idle。
        // 注意 busy 撞 3 次可能进 OPEN；OPEN 会走「强制切号」路径而非 rebalance。
        // 为隔离测 rebalance 路径，这里直接调 rebalance_target 验证它按利用率选 idle。
        let available: Vec<_> = manager
            .available_credentials(None, None)
            .into_iter()
            .collect();
        let target = manager.rebalance_target(
            &available,
            busy,
            &manager.config.adaptive_limit.multi_account,
        );
        assert!(
            target.is_some(),
            "busy 号利用率高、idle 号有余量 → 应触发利用率再平衡"
        );
        assert_eq!(
            target.unwrap().0,
            idle,
            "应把会话迁到利用率最低的 idle 号 {idle}"
        );
    }

    // P2-b 核心反假绿：调用门 rebalance_signal_enabled 必须「util_gap>0 或 min_gap>0」任一即开。
    // 旧调用门只看 `rebalance_min_gap > 0`，min_gap=0 时整段 short-circuit → 连 rebalance_target 都不调
    // → util 信号被绑死永远摸不到（#19 满载不迁 #18 的雷）。这里直接对纯函数断言四种组合，钉死布尔逻辑。
    #[test]
    fn test_rebalance_signal_enabled_combinations() {
        let mut ma = crate::model::config::MultiAccountConfig::default();
        // ① 只有 util 信号（min_gap=0）：必须启用——这正是旧代码漏掉的情形。
        ma.rebalance_min_gap = 0;
        ma.rebalance_utilization_gap = 0.3;
        assert!(
            MultiTokenManager::rebalance_signal_enabled(&ma),
            "min_gap=0 但 util_gap>0 必须启用再平衡（旧 bug：被 min_gap 绑死）"
        );
        // ② 只有会话数信号（util_gap=0）：必须启用（fallback 仍可用）。
        ma.rebalance_min_gap = 2;
        ma.rebalance_utilization_gap = 0.0;
        assert!(
            MultiTokenManager::rebalance_signal_enabled(&ma),
            "util_gap=0 但 min_gap>0 必须启用再平衡（会话数 fallback）"
        );
        // ③ 两个信号都开：启用。
        ma.rebalance_min_gap = 2;
        ma.rebalance_utilization_gap = 0.3;
        assert!(MultiTokenManager::rebalance_signal_enabled(&ma));
        // ④ 两个信号都关：彻底关闭。
        ma.rebalance_min_gap = 0;
        ma.rebalance_utilization_gap = 0.0;
        assert!(
            !MultiTokenManager::rebalance_signal_enabled(&ma),
            "两个信号都为 0 时必须完全关闭被动再平衡"
        );
    }

    // P2-b 补充：min_gap=0 + util_gap>0 时，rebalance_target 内部 util 分支仍能选中有余量的 idle 号
    // （证明开门后里面真能干活，会话数 fallback 因 min_gap=0 提前 return，所以命中只可能来自 util 分支）。
    #[tokio::test]
    async fn test_rebalance_target_util_picks_idle_when_min_gap_zero() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        config.adaptive_limit.multi_account.rebalance_min_gap = 0; // 会话数 fallback 关
        config.adaptive_limit.multi_account.rebalance_utilization_gap = 0.3; // 只留 util
        let manager = affinity_manager(config);
        let c = manager.acquire_context(None, None, Some("sess-X")).await.unwrap();
        let busy = c.id;
        let idle = if busy == 1 { 2 } else { 1 };
        let busy_lim = manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(busy));
        for _ in 0..3 {
            busy_lim
                .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                .await;
        }
        let available: Vec<_> = manager
            .available_credentials(None, None)
            .into_iter()
            .collect();
        let target = manager.rebalance_target(
            &available,
            busy,
            &manager.config.adaptive_limit.multi_account,
        );
        assert!(
            target.is_some(),
            "min_gap=0 但 util_gap>0：util 分支应选中有余量的号（会话数 fallback 已因 min_gap=0 退出）"
        );
        assert_eq!(target.unwrap().0, idle, "应按利用率选最闲的 idle 号 {idle}");
    }

    // 原号冷却短于阈值：继续黏原号（由 limiter 自行等待，不切号）。
    #[tokio::test]
    async fn test_affinity_sticks_when_cooldown_short() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_threshold_secs = 100; // 阈值很大
        config.adaptive_limit.user_cooldown_base_secs = 2; // 冷却 ~2s << 100s
        let manager = affinity_manager(config);
        let c1 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(c1.id))
            .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
            .await;
        let c2 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        assert_eq!(c2.id, c1.id, "冷却短于阈值应继续黏原号");
    }

    // 原号冷却久于阈值且不在防抖窗口：切到另一个号。
    #[tokio::test]
    async fn test_affinity_switches_when_bound_account_deeply_cooled() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_threshold_secs = 1; // 冷却 >1s 即切
        config.adaptive_limit.multi_account.switch_debounce_secs = 0; // 不防抖
        config.adaptive_limit.user_cooldown_base_secs = 10; // 撞一次冷却 ~10s
        let manager = affinity_manager(config);
        let c1 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(c1.id))
            .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
            .await;
        let c2 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        assert_ne!(c2.id, c1.id, "原号冷却过久应切到另一个号");
    }

    // 切号防抖：冷却虽久，但仍在 switch_debounce 窗口内 → 不切号。
    #[tokio::test]
    async fn test_affinity_switch_debounced() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_threshold_secs = 1;
        config.adaptive_limit.multi_account.switch_debounce_secs = 3600; // 长防抖
        config.adaptive_limit.user_cooldown_base_secs = 10;
        let manager = affinity_manager(config);
        let c1 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(c1.id))
            .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
            .await;
        // 模拟「刚切过号」：last_switch_at = now，落在防抖窗口内。
        {
            let mut aff = manager.affinity.lock();
            if let Some(b) = aff.get_mut("sess-A") {
                b.last_switch_at = Some(Utc::now());
            }
        }
        let c2 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        assert_eq!(c2.id, c1.id, "防抖窗口内即便冷却过久也不应切号");
    }

    // TTL 过期：陈旧绑定被当作新会话重新落号（不黏旧号）。
    #[test]
    fn test_affinity_ttl_expired_rebinds() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.affinity_ttl_secs = 60;
        let manager = affinity_manager(config);
        // 手动插入一条 2 小时前的过期绑定，指向 id2。
        {
            let mut aff = manager.affinity.lock();
            aff.insert(
                "sess-old".to_string(),
                AffinityBinding {
                    credential_id: 2,
                    bound_at: Utc::now() - Duration::hours(2),
                    last_seen: Utc::now() - Duration::hours(2),
                    last_switch_at: None,
                    priority: 0,
                },
            );
        }
        // 过期 → 视为新会话 → 落最低负载（两号 RPM 均 0 → 平局取 id1）。
        let pick = manager
            .select_with_affinity(None, None, Some("sess-old"))
            .unwrap();
        assert_eq!(pick.0, 1, "过期绑定应被当作新会话重新落号");
        // 绑定被刷新为新号，last_seen 也被刷新。
        let b = manager.affinity.lock().get("sess-old").cloned().unwrap();
        assert_eq!(b.credential_id, 1);
        assert!((Utc::now() - b.last_seen) < Duration::minutes(1));
    }

    // 原号被禁用（不可用）→ 强制切到可用号。
    #[tokio::test]
    async fn test_affinity_force_switch_when_bound_disabled() {
        let manager = affinity_manager(Config::default());
        let c1 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        manager.set_disabled(c1.id, true).unwrap();
        let c2 = manager
            .acquire_context(None, None, Some("sess-A"))
            .await
            .unwrap();
        assert_ne!(c2.id, c1.id, "原号禁用后应强制切到另一个可用号");
    }

    // 手动 pin 覆盖 affinity 选号。
    #[test]
    fn test_pin_overrides_affinity_selection() {
        let manager = affinity_manager(Config::default());
        let natural = manager
            .select_with_affinity(None, None, Some("sess-pin"))
            .unwrap();
        manager.pin_session("sess-pin", if natural.0 == 1 { 2 } else { 1 });
        let pinned = manager
            .select_with_affinity(None, None, Some("sess-pin"))
            .unwrap();
        assert_ne!(pinned.0, natural.0, "pin 应覆盖已有 affinity 绑定");
        assert_eq!(
            pinned.0,
            if natural.0 == 1 { 2 } else { 1 },
            "应返回 pin 指定的号"
        );
    }

    // pin 目标不可用时 soft fallback 到正常 affinity。
    #[tokio::test]
    async fn test_pin_unavailable_falls_back_to_normal() {
        let manager = affinity_manager(Config::default());
        manager.pin_session("sess-fallback", 2);
        manager.set_disabled(2, true).unwrap();
        let pick = manager
            .select_with_affinity(None, None, Some("sess-fallback"))
            .unwrap();
        assert_eq!(pick.0, 1, "pin 目标禁用后应回退到可用号");
    }

    // 高优先级新会话优先选无冷却号。
    #[tokio::test]
    async fn test_high_priority_new_session_prefers_healthy_account() {
        let mut config = Config::default();
        config.adaptive_limit.user_cooldown_base_secs = 30;
        let manager = affinity_manager(config);
        manager.set_session_priority("sess-vip", 10);
        manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(1))
            .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
            .await;
        let pick = manager
            .select_with_affinity(None, None, Some("sess-vip"))
            .unwrap();
        assert_eq!(pick.0, 2, "高优先级新会话应避开冷却中的号");
    }
}

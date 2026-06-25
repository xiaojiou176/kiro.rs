//! Token 管理模块
//!
//! 负责 Token 过期检测和刷新，支持 Social 和 IdC 认证方式
//! 支持多凭据 (MultiTokenManager) 管理

use anyhow::bail;
use arc_swap::ArcSwap;
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
    /// 最近一次切号**是否由 overflow-on-busy 触发**（区分迁移类型用）。
    /// 只有 true 时 overflow 的更长 debounce 窗口才作用于本会话——否则普通切号/rebalance/cd 强切
    /// 不该被 overflow 窗口误拉长(Reviewer Finding A/B 根因：last_switch_at 不记「为什么切」)。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    last_switch_was_overflow: bool,
    /// 会话优先级（越高越重要；影响新绑 / 强制切号时的选号偏好）
    #[serde(default)]
    priority: i32,
    /// 最近一次被「负载再平衡 / 优先级独享驱逐」搬走时的来源号（防回弹：搬走后不许立刻被再平衡迁回原号）。
    /// 仅 overflow/OPEN 强制切号可破例清除它。None=从未被搬走。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_evicted_from: Option<u64>,
    /// 最近若干跳被「温和均衡 / cd 自愿切号」搬走时的**来源号环形历史**（最新在尾）。
    /// 根治「单槽 last_evicted_from 只挡 A→B→A、挡不住 A→B→C→…→A 长环」：温和均衡选 target 时
    /// 排除**整段**最近来源 → 会话不会绕回任何刚离开的号。上限 = pool_len-1（见 push_recent_evicted），
    /// 满了淘汰最旧。仅 overflow/OPEN「被迫逃」破例清空（同 last_evicted_from 语义）。空=从未自愿搬过。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recent_evicted_from: Vec<u64>,
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
    /// Thread 视角观测：每个活跃会话（TTL 内）一条，含真名占位 / 绑定号 / 推断相位。
    /// token_manager 只填「纯账号态」能算出的 base 部分；真名 + trace 相关（Errored/throttle/最终状态）
    /// 由 handler 层用 `thread_names::resolver()` + `TraceStore::latest_status_by_conversations` 回填。
    pub threads: Vec<ThreadObservation>,
}

/// Thread 运行相位（六档，serde 成驼峰小写字面量供前端直接用）。
///
/// 语义：除 `Idle` 外，**描述的都是该 thread 当前绑定的那个账号**的状态。
/// 优先级（高→低）：`Errored > RateLimited > JustMigrated > Queued > Running > Idle`。
/// 其中 `Errored` 依赖 trace 数据，只能在 handler 层判定；其余五档纯账号态即可算出 base。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ThreadPhase {
    /// 绑定账号 HEALTHY 且最近有活动（last_seen 很近）。
    Running,
    /// 绑定账号熔断打开（OPEN / HALF_OPEN）——被限速。
    RateLimited,
    /// 绑定账号 HEALTHY 但在飞已满（inflight >= maxInflight）——排队。
    Queued,
    /// 该会话刚因 overflow-on-busy 迁移过号，且仍在迁移防抖窗口内。
    JustMigrated,
    /// 该 thread 最近一条 trace 是 error / interrupted（handler 层回填）。
    Errored,
    /// 长时间无活动（last_seen 超阈值）且账号不在途。
    Idle,
}

/// Thread 视角：单个会话的观测条目（前端 Thread 面板一行）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadObservation {
    /// 原始 session UUID（== Codex thread id == conversationId）；前端兜底显示用。
    pub session_id: String,
    /// thread 真名（从 `~/.codex/session_index.jsonl` 解析）；None 则前端显示截断 UUID。
    pub thread_name: Option<String>,
    /// 当前绑定的凭据 id。
    pub bound_account_id: u64,
    /// 手动 Pin 的目标凭据 id（None=未 Pin）；前端原生显示「已 Pin #N」，不靠侧 join。
    pub pinned_account_id: Option<u64>,
    /// 绑定账号的邮箱（可空）。
    pub account_email: Option<String>,
    /// 推断相位（六档）。
    pub phase: ThreadPhase,
    /// 距上次活动毫秒（now - last_seen）。
    pub last_seen_ms: i64,
    /// 最近一条 trace 累计撞到的上游 429 次数（handler 回填，默认 0）。
    pub recent_throttle_count: u32,
    /// 最近一条 trace 的最终状态（success/error/interrupted）；handler 回填，默认 None。
    pub last_final_status: Option<String>,
    /// 绑定建立时间（RFC3339）。
    pub bound_at: String,
}

/// 推断 thread 的 base 相位（**纯账号态**，不含 trace，可独立单测）。
///
/// 优先级：`RateLimited > JustMigrated > Queued > Running > Idle`
/// （`Errored` 由 trace 决定、优先级最高，在 [`phase_with_trace`] 里叠加）。
///
/// 参数：
/// - `state`：绑定账号熔断态；
/// - `current_inflight` / `current_max_inflight`：账号在飞 / 上限；
/// - `last_seen_ms`：距上次活动毫秒；
/// - `last_switch_was_overflow`：最近一次切号是否由 overflow 触发；
/// - `last_switch_age_ms`：距上次切号毫秒（`None` = 从未切过）；
/// - `migrate_debounce_ms`：overflow 迁移防抖窗口；
/// - `idle_threshold_ms`：判定 Idle 的无活动阈值。
///
/// 说明：`Disabled` 账号不属于这六档语义里「正常绑定」的任何一种，
/// 会落到 Queued（若在飞满）/ Idle（久无活动）/ Running（刚有活动）兜底——
/// 实践中 disabled 号几乎不会持有 TTL 内的活跃绑定，这是边界兜底而非主路径。
pub fn infer_base_phase(
    state: AccountState,
    current_inflight: usize,
    current_max_inflight: usize,
    last_seen_ms: i64,
    last_switch_was_overflow: bool,
    last_switch_age_ms: Option<i64>,
    migrate_debounce_ms: i64,
    idle_threshold_ms: i64,
) -> ThreadPhase {
    // 1) RateLimited：绑定账号熔断打开。
    if matches!(state, AccountState::Open | AccountState::HalfOpen) {
        return ThreadPhase::RateLimited;
    }
    // 2) JustMigrated：刚因 overflow 迁移、仍在防抖窗口内。
    if last_switch_was_overflow {
        if let Some(age) = last_switch_age_ms {
            if age >= 0 && age < migrate_debounce_ms {
                return ThreadPhase::JustMigrated;
            }
        }
    }
    // 3) Queued：账号在飞已满。
    if current_max_inflight > 0 && current_inflight >= current_max_inflight {
        return ThreadPhase::Queued;
    }
    // 4) Idle：久无活动且账号不在途。
    if last_seen_ms > idle_threshold_ms && current_inflight == 0 {
        return ThreadPhase::Idle;
    }
    // 5) Running：默认（HEALTHY 且最近有活动）。
    ThreadPhase::Running
}

/// 在 base 相位上叠加 trace 判定：最近一条 trace 是 error/interrupted → `Errored`（最高优先级，压过一切）。
/// `trace_status` 为 None（无 trace / trace 关闭）时原样返回 base。
pub fn phase_with_trace(base: ThreadPhase, trace_status: Option<&str>) -> ThreadPhase {
    if let Some(s) = trace_status {
        if s == "error" || s == "interrupted" {
            return ThreadPhase::Errored;
        }
    }
    base
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
    /// overflow-on-busy 配置的运行时原子热替换句柄。
    /// `config.adaptive_limit.multi_account.overflow_on_busy` 在构造时拷一份进来；
    /// admin `PUT /config/rate-limit` 热改 overflow 字段时 `store` 新值，`select_with_affinity`
    /// 取快照即见新值（无需重启）。与 `limiters` 的 `AdaptiveConfig` 热替换是两条独立通道
    /// （overflow 不属于 `AdaptiveConfig`，住在 multi_account 里）。
    overflow_cfg: Arc<ArcSwap<crate::model::config::OverflowOnBusyConfig>>,
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

/// `update_adaptive_config` 的返回：合并后的运行时配置 + overflow 配置 + 是否已落盘。
#[derive(Debug, Clone)]
pub struct AdaptiveConfigUpdateOutcome {
    /// 合并后的运行时 `AdaptiveConfig`（已含强制保留的 hard_max_inflight/min_inflight）。
    pub config: AdaptiveConfig,
    /// 合并后的 overflow-on-busy 配置。
    pub overflow: crate::model::config::OverflowOnBusyConfig,
    /// 是否已成功落盘 config.json（false = 仅内存生效，重启会丢）。
    pub persisted: bool,
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
        let overflow_cfg = Arc::new(ArcSwap::from_pointee(
            config.adaptive_limit.multi_account.overflow_on_busy.clone(),
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
            overflow_cfg,
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

    /// 读当前运行时 overflow-on-busy 配置快照（热替换后即见新值）。
    pub fn current_overflow_config(&self) -> crate::model::config::OverflowOnBusyConfig {
        (*self.overflow_cfg.load_full()).clone()
    }

    /// 读当前运行时 AdaptiveConfig 快照（热替换后即见新值）。
    pub fn current_adaptive_config(&self) -> AdaptiveConfig {
        self.limiters.current_config()
    }

    /// 运行时热改限速器全参数（admin `PUT /config/rate-limit`）。
    ///
    /// 流程：校验 patch → 以**磁盘 config 为基底**(无路径时回退当前 config) 合并 patch →
    /// `from_cfg` 重建运行时 `AdaptiveConfig`（强制保留当前 `hard_max_inflight`/`min_inflight`，
    /// 因信号量容量构造时定死、不可热改）→ 内存原子生效（registry + overflow 两条通道）→
    /// 落盘 config.json。**落盘失败则整体回滚**（store 回旧值并返回 Err），杜绝「内存改了但文件没存」。
    /// 无 config 路径时：内存生效但 `persisted=false`，调用方须告知用户「重启会丢」。
    pub fn update_adaptive_config(
        &self,
        patch: crate::model::config::AdaptiveConfigPatch,
    ) -> anyhow::Result<AdaptiveConfigUpdateOutcome> {
        use anyhow::Context;
        use crate::model::config::Config;

        if patch.is_empty() {
            bail!("至少提供一个可改字段");
        }
        Self::validate_adaptive_patch(&patch)?;

        // 基底：优先用磁盘 config（与落盘保持一致，避免内存/磁盘漂移）；无路径时回退当前内存 config。
        let config_path = self.config.config_path().map(|p| p.to_path_buf());
        let mut base_config: Config = match &config_path {
            Some(p) => Config::load(p)
                .with_context(|| format!("重新加载配置失败: {}", p.display()))?,
            None => self.config.clone(),
        };

        // 应用 patch 到磁盘配置的原始字段（落盘用这一份）。
        Self::apply_patch_to_alc(&mut base_config.adaptive_limit, &patch);

        // 重建运行时强类型配置。
        let mut new_runtime = AdaptiveConfig::from_cfg(&base_config.adaptive_limit);
        // hard_max_inflight / min_inflight 不可热改（信号量容量定死）→ 强制保留当前运行时值，
        // 保证 current_inflight 等基于信号量容量的算式一致。即便磁盘 config 这两项漂移，
        // 本轮也不动它们（仅重启时随磁盘生效）。
        let cur_runtime = self.limiters.current_config();
        new_runtime.hard_max_inflight = cur_runtime.hard_max_inflight;
        new_runtime.min_inflight = cur_runtime.min_inflight;
        let new_overflow = base_config.adaptive_limit.multi_account.overflow_on_busy.clone();

        // 先存旧值快照（回滚用）。
        let old_runtime = cur_runtime;
        let old_overflow = self.current_overflow_config();

        // 内存原子生效（两条独立通道）。
        self.limiters.reconfigure_all(new_runtime.clone());
        self.overflow_cfg.store(Arc::new(new_overflow.clone()));

        // 落盘。失败 → 回滚内存并返回 Err（绝不留「内存改了文件没存」的漂移）。
        let persisted = match &config_path {
            Some(p) => {
                if let Err(e) = base_config
                    .save()
                    .with_context(|| format!("持久化限速配置失败: {}", p.display()))
                {
                    self.limiters.reconfigure_all(old_runtime);
                    self.overflow_cfg.store(Arc::new(old_overflow));
                    return Err(e);
                }
                true
            }
            None => {
                tracing::warn!("配置文件路径未知，限速配置仅在当前进程生效（重启会丢）");
                false
            }
        };

        tracing::info!(
            persisted = persisted,
            "限速配置已热替换：additive_step={} max_rate={} sanity_max={} overflow_enabled={}",
            new_runtime.additive_step_rps,
            new_runtime.max_rate_rps,
            new_runtime.goodput_sanity_max_rps,
            new_overflow.enabled,
        );

        Ok(AdaptiveConfigUpdateOutcome {
            config: new_runtime,
            overflow: new_overflow,
            persisted,
        })
    }

    /// 校验 patch 各字段在合理范围（数值有限、比例 0~1、计数 >= 1 等）。
    fn validate_adaptive_patch(
        patch: &crate::model::config::AdaptiveConfigPatch,
    ) -> anyhow::Result<()> {
        if let Some(v) = patch.additive_step_rps {
            if !v.is_finite() || v < 0.0 {
                bail!("additiveStepRps 必须 >= 0 且有限: {}", v);
            }
        }
        if let Some(v) = patch.successes_per_increase {
            if v < 1 {
                bail!("successesPerIncrease 必须 >= 1: {}", v);
            }
        }
        if let Some(v) = patch.max_rate_rps {
            if !v.is_finite() || v <= 0.0 {
                bail!("maxRateRps 必须 > 0 且有限: {}", v);
            }
        }
        if let Some(v) = patch.goodput_hard_ceiling {
            if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                bail!("goodputHardCeiling 必须在 0..=1: {}", v);
            }
        }
        if let Some(v) = patch.goodput_sanity_max_rps {
            if !v.is_finite() || v <= 0.0 {
                bail!("goodputSanityMaxRps 必须 > 0 且有限: {}", v);
            }
        }
        if let Some(ov) = &patch.overflow_on_busy {
            if let Some(v) = ov.upstream429_rate_threshold {
                if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                    bail!("overflowOnBusy.upstream429RateThreshold 必须在 0..=1: {}", v);
                }
            }
            if let Some(v) = ov.goodput_ratio_threshold {
                if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                    bail!("overflowOnBusy.goodputRatioThreshold 必须在 0..=1: {}", v);
                }
            }
        }
        Ok(())
    }

    /// 把 patch 的非 None 字段应用到 `AdaptiveLimitConfig`（落盘 + 重建运行时配置的基底）。
    fn apply_patch_to_alc(
        alc: &mut crate::model::config::AdaptiveLimitConfig,
        patch: &crate::model::config::AdaptiveConfigPatch,
    ) {
        if let Some(v) = patch.additive_step_rps {
            alc.additive_step_rps = v;
        }
        if let Some(v) = patch.increase_interval_secs {
            alc.increase_interval_secs = v;
        }
        if let Some(v) = patch.successes_per_increase {
            alc.successes_per_increase = v;
        }
        if let Some(v) = patch.max_rate_rps {
            alc.max_rate_rps = v;
        }
        if let Some(v) = patch.goodput_hard_ceiling {
            alc.probe.goodput_hard_ceiling = v;
        }
        if let Some(v) = patch.goodput_sanity_max_rps {
            alc.probe.goodput_sanity_max_rps = v;
        }
        if let Some(ov) = &patch.overflow_on_busy {
            let dst = &mut alc.multi_account.overflow_on_busy;
            if let Some(v) = ov.enabled {
                dst.enabled = v;
            }
            if let Some(v) = ov.upstream429_rate_threshold {
                dst.upstream429_rate_threshold = v;
            }
            if let Some(v) = ov.goodput_ratio_threshold {
                dst.goodput_ratio_threshold = v;
            }
            if let Some(v) = ov.migrate_debounce_secs {
                dst.migrate_debounce_secs = v;
            }
        }
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
        // Thread 视角原料：每条 TTL 内绑定的原始时间/迁移信息（base 相位推断用）。
        // (session_id, credential_id, last_seen_ms, bound_at_rfc3339, last_switch_was_overflow, last_switch_age_ms)
        let mut thread_raws: Vec<(String, u64, i64, String, bool, Option<i64>)> = Vec::new();
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
                let last_seen_ms = (now - b.last_seen).num_milliseconds();
                let last_switch_age_ms = b.last_switch_at.map(|t| (now - t).num_milliseconds());
                thread_raws.push((
                    sid.clone(),
                    b.credential_id,
                    last_seen_ms,
                    b.bound_at.to_rfc3339(),
                    b.last_switch_was_overflow,
                    last_switch_age_ms,
                ));
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

        // 2c) 三源并集补全 Thread 视角：affinity 已收上面；这里补「被 Pin 但当前无 affinity 绑定」
        //     和「设了优先级但无绑定」的会话——否则它们在 Thread 面板里彻底消失（用户看着「Pin 没用」）。
        //     synthetic 条目用 last_seen_ms = i64::MAX 当「该会话自身从未活动」哨兵；构建相位时强制 inflight=0
        //     → 默认落 Idle；但若 pin 目标账号本身 OPEN/熔断，会如实显示 RateLimited（这对用户有用，不是错）。
        //     bound_account_id 取 pin 目标号（无 pin 取 0，acct_index 查不到→当 Healthy 兜底）。
        {
            let mut seen: std::collections::HashSet<String> =
                thread_raws.iter().map(|(s, ..)| s.clone()).collect();
            // 先 pin-only，再 priority-only（pin 目标号优先作为展示绑定）。
            for (sid, pin_id) in pinned_sessions.iter() {
                if seen.insert(sid.clone()) {
                    thread_raws.push((
                        sid.clone(),
                        *pin_id,
                        i64::MAX,
                        String::new(),
                        false,
                        None,
                    ));
                }
            }
            for sid in session_priority.keys() {
                if seen.insert(sid.clone()) {
                    thread_raws.push((
                        sid.clone(),
                        0,
                        i64::MAX,
                        String::new(),
                        false,
                        None,
                    ));
                }
            }
        }

        // 3) 逐号聚合 RPM + limiter（不在持 affinity 锁期间调用）。
        let accounts: Vec<AccountObservability> = accounts_base
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

        // 4) Thread 视角：用上面已算好的 accounts（含 state / inflight / email）+ 原始绑定信息，
        //    推断每个会话的 base 相位（纯账号态，trace 相关字段留给 handler 回填）。
        let acct_index: HashMap<u64, &AccountObservability> =
            accounts.iter().map(|a| (a.id, a)).collect();
        let migrate_debounce_ms =
            (ma.overflow_on_busy.migrate_debounce_secs as i64).saturating_mul(1000);
        // Idle 阈值固定 60s（spec）。
        const IDLE_THRESHOLD_MS: i64 = 60_000;
        let mut threads: Vec<ThreadObservation> = thread_raws
            .into_iter()
            .map(
                |(sid, cred_id, last_seen_ms, bound_at, switch_overflow, switch_age_ms)| {
                    let acct = acct_index.get(&cred_id);
                    let state = acct.map(|a| a.state).unwrap_or(AccountState::Healthy);
                    // 合成会话（pin-only / priority-only，无 affinity 绑定）用 last_seen_ms==MAX 哨兵标识：
                    // 它自己没有在途请求，不能借绑定账号的 inflight 判 Queued（否则账号一忙就误显「排队中」）。
                    // 强制 inflight=0 → 走 Idle 分支（它确实从未活动）。
                    let is_synthetic = last_seen_ms == i64::MAX;
                    let inflight = if is_synthetic { 0 } else { acct.map(|a| a.current_inflight).unwrap_or(0) };
                    let max_inflight = if is_synthetic { 0 } else { acct.map(|a| a.current_max_inflight).unwrap_or(0) };
                    let email = acct.and_then(|a| a.email.clone());
                    let pinned_account_id = pinned_sessions.get(&sid).copied();
                    let phase = infer_base_phase(
                        state,
                        inflight,
                        max_inflight,
                        last_seen_ms,
                        switch_overflow,
                        switch_age_ms,
                        migrate_debounce_ms,
                        IDLE_THRESHOLD_MS,
                    );
                    ThreadObservation {
                        session_id: sid,
                        thread_name: None, // handler 回填真名
                        bound_account_id: cred_id,
                        pinned_account_id,
                        account_email: email,
                        phase,
                        last_seen_ms,
                        recent_throttle_count: 0, // handler 回填
                        last_final_status: None,  // handler 回填
                        bound_at,
                    }
                },
            )
            .collect();
        // 稳定排序：按 session_id，便于前端 diff / 测试可重复。
        threads.sort_by(|a, b| a.session_id.cmp(&b.session_id));

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
            threads,
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

    /// 该号当前是否「可被手动 Pin」：必须 **存在、未禁用、且未处于限流/熔断(OPEN/HALF_OPEN)**。
    /// 供 admin pin 入口校验——不健康的号不允许 Pin（避免 pin 上去也只会软回退、形同虚设）。
    ///
    /// 返回 `Err(原因)` 说明为何不能 pin；`Ok(())` 表示可 pin。
    pub fn check_pinnable(&self, id: u64) -> Result<(), String> {
        // 1) 号必须存在 + 2) 未被禁用（在锁内取所需标志，不 clone 整个 entry）。
        let exists_and_disabled = {
            let entries = self.entries.lock();
            entries.iter().find(|e| e.id == id).map(|e| e.disabled)
        };
        match exists_and_disabled {
            None => return Err(format!("凭据 #{id} 不存在")),
            Some(true) => return Err(format!("凭据 #{id} 已被禁用，不能 Pin")),
            Some(false) => {}
        }
        // 3) 未处于限流/熔断（OPEN / HALF_OPEN）
        if self.is_account_open(id) {
            return Err(format!("凭据 #{id} 正被限流/熔断（静养中），暂不能 Pin"));
        }
        Ok(())
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
        // 预算各号「绑定会话存量(含睡眠)」一次：避免把新活全压到「RPM=0 但挂了一堆睡眠会话」的号上
        // （那种号一旦睡眠会话集体唤醒会瞬间打满）。作为 RPM 之后的排序维度（RPM 平局时按绑定存量少的优先）。
        let ttl = Duration::seconds(
            self.config.adaptive_limit.multi_account.affinity_ttl_secs as i64,
        );
        let bound_counts = self.bound_session_counts(available, ttl);
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
                let bound = *bound_counts.get(id).unwrap_or(&0);
                (headroom, cd_ms, self.rpm(*id), bound, c.priority, *id)
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

    /// 统计各号「绑定会话数」：affinity map 中 `last_seen` 在 `ttl` 内（含睡着的）、且绑到 `available` 内号的会话。
    /// 与 `active_session_counts` 的区别：这里统计 **TTL 内全部绑定（含睡眠）**，用于「睡眠会话堆弱号」的提前疏散，
    /// 不只看 5 分钟活跃窗口。只读 affinity 快照，不调 rpm/limiters（避免锁交叉）。
    fn bound_session_counts(
        &self,
        available: &[(u64, KiroCredentials)],
        ttl: Duration,
    ) -> HashMap<u64, usize> {
        let now = Utc::now();
        let mut counts: HashMap<u64, usize> = available.iter().map(|(id, _)| (*id, 0)).collect();
        let aff = self.affinity.lock();
        for b in aff.values() {
            if (now - b.last_seen) <= ttl {
                if let Some(c) = counts.get_mut(&b.credential_id) {
                    *c += 1;
                }
            }
        }
        counts
    }

    /// 后台主动巡检调度器：不依赖 Thread 自己发请求，**主动**把「压力最小/睡眠会话」从过载号疏散到最空号。
    /// 根治 reviewer 揪出的盲点：被动路径下睡眠会话永不被挪、肇事 Thread 赖着原号。
    ///
    /// 设计（owner 拍板「平时轻度均衡 + 边搬边重算逐个分散」）：**每 tick 最多迁 1 个会话**，迁完下个 tick
    /// 重新算全局快照——温和、自纠正、不一次性把空号填爆。优先级栈：Pin（跳过被 pin 会话）> overflow/OPEN
    /// 紧急（rebalance_target 内已排除 OPEN 目标）> RPM 均衡 > bound 睡眠疏散 > 会话数均衡。
    /// 返回本 tick 迁移的会话数（0 或 1）。
    pub fn rebalance_tick(&self) -> usize {
        let ma = &self.config.adaptive_limit.multi_account;
        // 总闸：未开多号、或巡检关 → 不动（owner 红线：默认行为零变化）。
        if !ma.enabled || ma.scheduler_tick_secs == 0 {
            return 0;
        }
        // 优先级栈：先跑「优先级独享」（最高优先 active 会话拿最优号、赶低优先），再跑温和均衡。
        // 每 tick 最多一个动作——独享有动作就先做、本 tick 不再跑均衡（下个 tick 重算）。
        // ⚠️ exclusive 独立闸门（Reviewer Finding #4）：只要存在 priority>0 会话就跑，**不挂在
        // rebalance_signal_enabled 上**——否则 owner「只要独享、关掉被动均摊」(四 gap 全 0) 会顺带杀掉独享。
        if self.exclusive_tick() > 0 {
            return 1;
        }
        // 温和均衡：四个 rebalance 信号全关时才跳过（独享已在上面跑过）。
        if !Self::rebalance_signal_enabled(ma) {
            return 0;
        }
        let pool = self.available_credentials(None, None);
        if pool.len() < 2 {
            return 0;
        }
        // 独享归属号（当前 TTL 内绑有 priority>0 会话的号）：温和均衡的目标号**必须排除**它们，
        // 否则会把普通 squatter 搬进独享号、下个 tick exclusive 又赶走 = 反向 churn（Reviewer Finding #2）。
        let exclusive_owned = self.exclusive_owned_accounts();
        // 阶段一（不持 affinity 锁）：把所有「想卸载」的源号排出候选序列。rebalance_target
        // 内部会锁 affinity/limiters，故此处绝不持 affinity 锁（防锁交叉死锁）。
        // 元组 = (src, target, 是否被限流硬触发, src_rpm)。
        let mut candidates: Vec<(u64, u64, bool, usize)> = Vec::new();
        for (src, _) in &pool {
            if let Some((target, _)) =
                self.rebalance_target_excl(&pool, *src, ma, &[], &exclusive_owned)
            {
                // 被 429 压垮的号「成功 RPM」往往很低（请求大多失败），若只按 RPM 排序会被沉到队尾、
                // 被高 RPM 但健康的号挤掉本 tick 的疏散名额——而「正在被限流」恰恰最该先救。
                // 故单独标一个 429 硬触发位，排序时让它压过 RPM（修「最紧急的反而最后疏散」盲区）。
                let throttled = ma.rebalance_429_rate_threshold > 0.0
                    && self.account_429_rate_sustained(*src) >= ma.rebalance_429_rate_threshold;
                candidates.push((*src, target, throttled, self.rpm(*src)));
            }
        }
        // 优先级：① 被限流(429 硬触发)的源最先卸载；② 其次 RPM 高的；**不止试最忙那个**——
        // 它若没可搬会话（全 pin/全高优先/全防抖），回退到次紧急/次忙的源（修队头阻塞活锁）。
        candidates.sort_by(|a, b| {
            b.2.cmp(&a.2) // 被限流的(true)排前
                .then(b.3.cmp(&a.3)) // 再按 RPM 降序
                .then(a.0.cmp(&b.0)) // id 稳定
        });
        let pinned = self.pinned_sessions();
        let now = Utc::now();
        let debounce = Duration::seconds(ma.switch_debounce_secs as i64);
        // 阶段二（持 affinity 锁）：依次试每个候选源，找到第一个有可搬会话的 (src, target, victim)。
        let mut chosen: Option<(String, u64, u64, i32)> = None; // (sid, src, target, prio)
        {
            let aff = self.affinity.lock();
            'outer: for (src, target, _throttled, _rpm) in &candidates {
                let mut victim: Option<(String, i32)> = None;
                let mut oldest = now;
                for (sid, b) in aff.iter() {
                    if b.credential_id != *src {
                        continue;
                    }
                    if pinned.contains_key(sid) {
                        continue; // Pin 凌驾一切，不被巡检搬
                    }
                    if b.priority > 0 {
                        continue; // 高优先会话只由 exclusive_tick 管，温和均衡绝不碰（防乒乓，Reviewer 向量6）
                    }
                    if b.last_evicted_from == Some(*target) {
                        continue; // 防回弹：刚从 target 搬来，不许立刻搬回
                    }
                    if let Some(ls) = b.last_switch_at {
                        if (now - ls) < debounce {
                            continue; // 切号防抖窗口内，不搬
                        }
                        // churn 根治(根本不变式)：已被温和均衡搬过、且【搬后从未产生真实活动】
                        // (last_seen 不晚于 last_switch_at)的会话，不许再被温和均衡搬动。
                        // 否则同一死睡眠会话会在多号间无限横跳(#a→#b→#c→#a)——last_seen 只由真实
                        // 请求(select_with_affinity)刷新、搬号不刷新，所以搬过的死睡眠会话永远是「最老
                        // last_seen」候选、被反复挑中。冻结它(直到它真醒来干活刷新 last_seen)即根除 churn，
                        // 同时不冻结「搬后又真干活」的会话(它 last_seen 会晚于 last_switch_at → 仍可迁)，
                        // 也不影响「从没被搬过」的睡眠会话首次散堆(last_switch_at=None → 不进此门)。
                        if b.last_seen <= ls {
                            continue;
                        }
                    }
                    // 压力最小 = last_seen 最老（最久没活动 / 睡得最沉）。
                    if victim.is_none() || b.last_seen < oldest {
                        oldest = b.last_seen;
                        victim = Some((sid.clone(), b.priority));
                    }
                }
                if let Some((sid, prio)) = victim {
                    chosen = Some((sid, *src, *target, prio));
                    break 'outer;
                }
            }
        }
        // 阶段三（重取 affinity 锁落定迁移）：二次确认会话仍绑在 src，再改 credential_id。
        if let Some((sid, src, target, prio)) = chosen {
            let mut aff = self.affinity.lock();
            if let Some(b) = aff.get_mut(&sid) {
                // 二次确认仍绑在 src（期间可能被并发改动）
                if b.credential_id == src
                    && !pinned.contains_key(&sid)
                    && b.last_evicted_from != Some(target)
                {
                    b.credential_id = target;
                    b.last_switch_at = Some(now);
                    b.last_switch_was_overflow = false;
                    // 环形历史(根治 ≥3 号环):排除整段最近来源,cap=除当前号外所有号。
                    Self::push_recent_evicted(b, src, pool.len().saturating_sub(1));
                    drop(aff);
                    self.save_affinity_debounced();
                    Self::log_select(
                        "scheduler_rebalance",
                        target,
                        self.rpm(target),
                        0,
                        Some(&sid),
                        prio,
                    );
                    return 1;
                }
            }
        }
        0
    }

    /// 返回「当前被 **active** 高优先会话独享」的号集合。温和均衡的目标号要排除它们，
    /// 防止把普通 squatter 搬进独享号、下个 tick exclusive 又赶走 = 反向 churn（Reviewer Finding #2）。
    ///
    /// ⚠️ 只算 **active**（idle ≤ exclusive_borrow_idle_secs）的高优先会话——**睡着的高优先号故意不算**，
    /// 这样它睡着时普通会话能被均衡进去「借号」用（owner 规则：睡>借号阈值就借出、不浪费全局吞吐）；
    /// 它一醒变 active，下个 tick 这个号就重新进集合、exclusive_tick 把蹭进来的普通会话赶走（夺回）。
    fn exclusive_owned_accounts(&self) -> std::collections::HashSet<u64> {
        let ma = &self.config.adaptive_limit.multi_account;
        let borrow_idle = ma.exclusive_borrow_idle_secs as i64;
        let now = Utc::now();
        let aff = self.affinity.lock();
        aff.values()
            .filter(|b| b.priority > 0 && (now - b.last_seen).num_seconds() <= borrow_idle)
            .map(|b| b.credential_id)
            .collect()
    }

    /// 账号「真实安全上界」learned_safe_rps_hi（天花板），无 limiter 数据返回 0。用于独享挑「天花板最高的号」。
    fn account_safe_rps_hi(&self, id: u64) -> f64 {
        self.limiters
            .observe_full(&ThrottleScope::UserCredential(id))
            .map(|o| o.learned_safe_rps_hi)
            .unwrap_or(0.0)
    }

    /// 账号余量比例 = (safe_rps_hi − current_rate) / safe_rps_hi。越大越空闲（1=全空，≤0=贴墙/过载）。
    /// 用于独享「活跃留富余才让低负载普通会话蹭」的判定。无 limiter 数据返回 1.0（视为全空）。
    fn account_headroom_ratio(&self, id: u64) -> f64 {
        match self.limiters.observe_full(&ThrottleScope::UserCredential(id)) {
            Some(o) => {
                let hi = o.learned_safe_rps_hi.max(1e-6);
                ((hi - o.current_rate_rps) / hi).clamp(0.0, 1.0)
            }
            None => 1.0,
        }
    }

    /// 优先级独享一步（rebalance_tick 内最先跑，每 tick 最多一个动作）。
    /// 目的（owner 拍板）：**最大化高优先 Thread 吞吐**，「独享」是手段不是目的——
    /// 高优先 active 会话拿「天花板最高/最空」的号；号产能不够富余时赶走低优先 squatter（活跃留富余才让蹭）；
    /// 高优先 sleeping（空闲超 borrow 阈值）则**不赶**低优先（借号=不浪费全局吞吐）；
    /// 独享号 OPEN/熔断时高优先会话自然在「挑最优号」一步被迁到新健康号（级联）。
    /// 优先级栈：Pin 凌驾一切（被 pin 会话不动、其号视为已占）。返回本步动作数（0 或 1）。
    fn exclusive_tick(&self) -> usize {
        let ma = &self.config.adaptive_limit.multi_account;
        // 自带 enabled 门（防未来新增调用者绕过 rebalance_tick 的总闸）：未开多号绝不跑独享调度。
        if !ma.enabled {
            return 0;
        }
        let pool = self.available_credentials(None, None);
        if pool.len() < 2 {
            return 0;
        }
        let pinned = self.pinned_sessions();
        let now = Utc::now();
        let borrow_idle = ma.exclusive_borrow_idle_secs as i64;
        // 独享迁移用 reclaim_debounce_secs（专门防「醒来夺回→又睡→又借」抖动，Reviewer Finding #3）；
        // 它若设 0 则回退到通用 switch_debounce_secs（不至于完全无防抖）。
        let reclaim_debounce = Duration::seconds(
            if ma.reclaim_debounce_secs > 0 {
                ma.reclaim_debounce_secs
            } else {
                ma.switch_debounce_secs
            } as i64,
        );
        // 快照高优先会话（priority>0），按 priority 降序（数字大=更优先）、再 active 优先、再 key 稳定。
        let mut high_pri: Vec<(String, AffinityBinding)> = {
            let aff = self.affinity.lock();
            aff.iter()
                .filter(|(_, b)| b.priority > 0)
                .map(|(k, b)| (k.clone(), b.clone()))
                .collect()
        };
        if high_pri.is_empty() {
            return 0;
        }
        high_pri.sort_by(|(ka, a), (kb, b)| {
            b.priority
                .cmp(&a.priority)
                .then(a.last_seen.cmp(&b.last_seen).reverse())
                .then(ka.cmp(kb))
        });
        // 已被「更高/同等优先 + Pin」占用的号（处理顺序靠前者先占，靠后者避开）。
        let mut reserved: std::collections::HashSet<u64> = pinned.values().copied().collect();
        for (sid, b) in &high_pri {
            if pinned.contains_key(sid) {
                reserved.insert(b.credential_id);
                continue; // Pin 凌驾优先级，pin 会话不参与独享调度，其号视为已占
            }
            let idle = (now - b.last_seen).num_seconds();
            let active = idle <= borrow_idle;
            if !active {
                // sleeping：借号给普通会话——不赶 squatter、不抢占新号，留给后续 tick / 唤醒后处理。
                continue;
            }
            // 挑「天花板最高 + 最空」的理想号：排除 reserved/pinned-occupied/OPEN。
            // 防回弹（Reviewer Finding #5）：在 reclaim_debounce 窗口内，排除「刚把本会话搬离的源号」
            // (last_evicted_from)，否则等天花板号场景下 ideal 会在 A↔B 之间每个 debounce 翻一次（永动）。
            let exclude_bounce = match (b.last_evicted_from, b.last_switch_at) {
                (Some(from), Some(ls)) if (now - ls) < reclaim_debounce => Some(from),
                _ => None,
            };
            let ideal = pool
                .iter()
                .map(|(id, _)| *id)
                .filter(|id| !reserved.contains(id))
                .filter(|id| Some(*id) != exclude_bounce)
                .filter(|id| !self.is_account_open(*id))
                .max_by(|a, c| {
                    self.account_safe_rps_hi(*a)
                        .partial_cmp(&self.account_safe_rps_hi(*c))
                        .unwrap_or(std::cmp::Ordering::Equal)
                        // ⚠️ 不把 rpm 放进独享 tiebreak（修真永动·第二轮 Reviewer 反例3）：rpm 会"跟着会话走"
                        // ——P 迁到哪、哪的 rpm 就升 → 若按 rpm 选 ideal 会 A↔B 反复翻。独享只认「天花板最高」，
                        // 天花板相等时按 **id 稳定**选（小 id 优），确定性、零 churn；号上的竞争由下面赶 squatter 清。
                        .then(c.cmp(a)) // id 小者更优（max_by 里 reverse：小 id 视为"更大/更优"）
                });
            let target = match ideal {
                Some(t) => t,
                None => continue, // 没有可用理想号（全被占/全 OPEN）→ 高优先间共享，跳过
            };
            // ① 高优先不在理想号 → 迁过去（含级联：原号 OPEN 时理想号必是别的健康号）。
            if b.credential_id != target {
                // 防抖：刚切过的不立刻再切。
                let in_debounce = b
                    .last_switch_at
                    .map(|t| (now - t) < reclaim_debounce)
                    .unwrap_or(false);
                if !in_debounce {
                    let mut aff = self.affinity.lock();
                    if let Some(bb) = aff.get_mut(sid) {
                        let from = bb.credential_id;
                        bb.credential_id = target;
                        bb.last_switch_at = Some(now);
                        bb.last_switch_was_overflow = false;
                        bb.last_evicted_from = Some(from);
                        drop(aff);
                        self.save_affinity_debounced();
                        Self::log_select(
                            "exclusive_acquire",
                            target,
                            self.rpm(target),
                            0,
                            Some(sid),
                            b.priority,
                        );
                        return 1;
                    }
                }
            }
            // 高优先已在理想号 → 占住它。
            reserved.insert(target);
            // ② 减少竞争：仅当号「不够富余」(headroom ≤ ratio) 时，赶走该号上「最活跃的」低优先 squatter。
            //    富余够（headroom > ratio）则允许低负载普通会话蹭（owner：活跃留富余才让蹭）。
            if self.account_headroom_ratio(target) > ma.exclusive_headroom_ratio {
                continue;
            }
            // 找该号上 priority==0 的 squatter，挑「最活跃(last_seen 最新)」的赶走（它最占竞争）。
            let victim: Option<String> = {
                let aff = self.affinity.lock();
                aff.iter()
                    .filter(|(vk, vb)| {
                        vb.credential_id == target
                            && vb.priority == 0
                            && !pinned.contains_key(*vk)
                    })
                    .max_by_key(|(_, vb)| vb.last_seen)
                    .map(|(vk, _)| vk.clone())
            };
            if let Some(vk) = victim {
                // 把 squatter 赶到「最空的别的号」（排除 target/reserved/OPEN）。
                let dest = pool
                    .iter()
                    .map(|(id, _)| *id)
                    .filter(|id| *id != target && !reserved.contains(id) && !self.is_account_open(*id))
                    .min_by_key(|id| (self.rpm(*id), *id));
                if let Some(dest) = dest {
                    let mut aff = self.affinity.lock();
                    if let Some(vb) = aff.get_mut(&vk) {
                        if vb.credential_id == target && vb.priority == 0 {
                            vb.credential_id = dest;
                            vb.last_switch_at = Some(now);
                            vb.last_switch_was_overflow = false;
                            vb.last_evicted_from = Some(target);
                            drop(aff);
                            self.save_affinity_debounced();
                            Self::log_select(
                                "exclusive_evict",
                                dest,
                                self.rpm(dest),
                                0,
                                Some(&vk),
                                0,
                            );
                            return 1;
                        }
                    }
                }
            }
        }
        0
    }

    /// 被动负载再平衡是否启用：利用率信号 或 会话数信号 任一开启即启用（P2-b）。
    /// 抽成纯函数便于单测，并消除调用门处的内联布尔魔法。
    /// - util_gap > 0 → 利用率信号开（rebalance_target 内 util 分支优先）；
    /// - min_gap > 0 → 会话数信号开（util 未触发时的 fallback）；
    /// - 两者都 0 → 完全关闭被动再平衡。
    fn rebalance_signal_enabled(ma: &crate::model::config::MultiAccountConfig) -> bool {
        ma.rebalance_rpm_gap > 0.0
            || ma.rebalance_utilization_gap > 0.0
            || ma.rebalance_bound_gap > 0
            || ma.rebalance_min_gap > 0
    }

    /// 把「自愿搬迁的来源号 `src`」压进会话的环形驱逐历史 `recent_evicted_from`（最新在尾）。
    /// 根治 ≥3 号环：温和均衡/cd 自愿切号选 target 时排除**整段**历史 → 会话不绕回任何刚离开的号。
    /// 上限 = `cap`（调用方传 pool_len-1，即「除当前号外所有号」——满了说明已走遍全部号、
    /// 再不清就无处可去，故淘汰最旧那跳，保留最近 cap 跳）。同时镜像更新单槽 `last_evicted_from`
    /// （= 最近一跳）以兼容仍读单槽的旧逻辑（如 exclusive_tick 的 exclude_bounce）。
    fn push_recent_evicted(b: &mut AffinityBinding, src: u64, cap: usize) {
        b.last_evicted_from = Some(src); // 兼容旧单槽读者
        b.recent_evicted_from.retain(|&x| x != src); // 去重：同号只留最近一次
        b.recent_evicted_from.push(src);
        let cap = cap.max(1);
        while b.recent_evicted_from.len() > cap {
            b.recent_evicted_from.remove(0); // 淘汰最旧
        }
    }

    /// 清空环形驱逐历史（+ 单槽）——「被迫逃」(overflow/OPEN/禁用) 时调用，原号恢复后允许回去。
    fn clear_recent_evicted(b: &mut AffinityBinding) {
        b.last_evicted_from = None;
        b.recent_evicted_from.clear();
    }

    /// 被动负载再平衡：若 `current` 号的活跃会话数比最空号多 ≥ `rebalance_min_gap`，
    /// 返回应迁往的最空号（排除 `current`）；否则 `None`（不迁，保持黏定）。
    /// 滞后阈值(≥2)+ 调用方的防抖保证迁移后不会 A↔B 反复横跳。
    fn rebalance_target(
        &self,
        available: &[(u64, KiroCredentials)],
        current: u64,
        ma: &crate::model::config::MultiAccountConfig,
        exclude_evicted: &[u64],
    ) -> Option<(u64, KiroCredentials)> {
        // 兼容旧调用（无独享归属号视图）：转发到带排除集的全量版本。
        let empty: std::collections::HashSet<u64> = std::collections::HashSet::new();
        self.rebalance_target_excl(available, current, ma, exclude_evicted, &empty)
    }

    /// `rebalance_target` 的全量版本：额外排除 `exclude_owned`（独享归属号）当迁移目标，
    /// 防止温和均衡把普通 squatter 搬进独享号引发反向 churn（Reviewer Finding #2）。
    fn rebalance_target_excl(
        &self,
        available: &[(u64, KiroCredentials)],
        current: u64,
        ma: &crate::model::config::MultiAccountConfig,
        exclude_evicted: &[u64],
        exclude_owned: &std::collections::HashSet<u64>,
    ) -> Option<(u64, KiroCredentials)> {
        if available.len() < 2 {
            return None;
        }
        // ⓪′ 被限流硬触发（最高优先级，**绕过 RPM/util 门**）。根治「单人低 RPM 场景下号被 429
        //    压垮、却因 RPM 差够不到 rebalance_rpm_gap 而永不疏散」：只要本号最近 5 分钟上游 429 率
        //    超过 rebalance_429_rate_threshold（且持续撞墙、非单次瞬态），就立刻把它名下会话疏散到
        //    最健康（利用率最低）的号。「正在被限流」比「忙」更紧急，必须先于其它信号处理。
        if ma.rebalance_429_rate_threshold > 0.0
            && self.account_429_rate_sustained(current) >= ma.rebalance_429_rate_threshold
        {
            if let Some((tid, tcreds)) = available
                .iter()
                .filter(|(id, _)| *id != current)
                .filter(|(id, _)| !exclude_evicted.contains(id))
                .filter(|(id, _)| !exclude_owned.contains(id))
                .filter(|(id, _)| !self.is_account_open(*id))
                .min_by(|(a, _), (b, _)| {
                    self.account_utilization(*a)
                        .partial_cmp(&self.account_utilization(*b))
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then(a.cmp(b))
                })
            {
                // 目标号自己不能也在被限流（429 率低于阈值才算「健康落脚点」）。
                if self.account_429_rate_sustained(*tid) < ma.rebalance_429_rate_threshold {
                    return Some((*tid, tcreds.clone()));
                }
            }
        }
        // ⓪ RPM 纯负载信号（修「忙但没撞墙」盲区，第一优先级，**不挂 util 的 SATURATED 门**）。
        //    根因：原有 util 信号要 cur_util≥1.0 才触发，而号「发得勤(rpm 高)但没真撞墙(cd=0/429=0)」
        //    时 util 不到 1.0 → 永远不迁 → 会话黏死。这里直接比真实 RPM：本号 rpm 比全局最空号高出
        //    rebalance_rpm_gap 就迁到最空号（最空=rpm 最低，平局按 priority/id 稳定）。
        if ma.rebalance_rpm_gap > 0.0 {
            let cur_rpm = self.rpm(current) as f64;
            if let Some((tid, tcreds)) = available
                .iter()
                .filter(|(id, _)| *id != current)
                .filter(|(id, _)| !exclude_evicted.contains(id))
                .filter(|(id, _)| !exclude_owned.contains(id))
                .filter(|(id, _)| !self.is_account_open(*id))
                .min_by_key(|(id, _)| (self.rpm(*id), *id))
            {
                let target_rpm = self.rpm(*tid) as f64;
                if cur_rpm - target_rpm >= ma.rebalance_rpm_gap {
                    return Some((*tid, tcreds.clone()));
                }
            }
        }
        // ① 利用率信号（Task 7 根治：会话数 ≠ 真实负载）。利用率 = current_rate / safe_rps_hi
        //    （≥1=贴墙/过载，<1=有余量）+ 429 率叠加。一个号会话少但每个都在撞墙(利用率高)，
        //    应把会话迁给会话多但很闲(利用率低)的号——这是会话数指标永远做不到的。
        if ma.rebalance_utilization_gap > 0.0 {
            let cur_util = self.account_utilization(current);
            // 前置门：仅当原号「真的接近/超过自己的天花板」(util ≥ SATURATED)才考虑按利用率迁移。
            // 否则单次瞬态 429 也会把 util 抬高、引发不必要的会话搬家(churn)。
            // SATURATED 现由 config.rebalance_util_saturated 提供（默认 0.8，下调让「快撞墙但没撞满」也触发）。
            let saturated = ma.rebalance_util_saturated;
            if cur_util >= saturated {
                // 找利用率最低的「别的号」（最有余量）。
                if let Some((tid, tcreds)) = available
                    .iter()
                    .filter(|(id, _)| *id != current)
                    .filter(|(id, _)| !exclude_evicted.contains(id))
                    .filter(|(id, _)| !exclude_owned.contains(id))
                    .filter(|(id, _)| !self.is_account_open(*id))
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
        // ② 绑定数信号（睡眠疏散）：原号 TTL 内绑定会话数（含睡着的）比最空号多 ≥ rebalance_bound_gap。
        //    专治「睡眠会话堆弱号、唤醒后瞬间打满」——active 窗口看不见睡着的，这里用 bound 计数补。
        if ma.rebalance_bound_gap > 0 {
            let ttl = Duration::seconds(ma.affinity_ttl_secs as i64);
            let bcounts = self.bound_session_counts(available, ttl);
            let cur_bound = *bcounts.get(&current).unwrap_or(&0);
            if let Some(target) = available
                .iter()
                .filter(|(id, _)| *id != current)
                .filter(|(id, _)| !exclude_evicted.contains(id))
                .filter(|(id, _)| !exclude_owned.contains(id))
                .filter(|(id, _)| !self.is_account_open(*id))
                .min_by_key(|(id, c)| (*bcounts.get(id).unwrap_or(&0), c.priority, *id))
            {
                let target_bound = *bcounts.get(&target.0).unwrap_or(&0);
                if cur_bound >= target_bound + ma.rebalance_bound_gap {
                    return Some((target.0, target.1.clone()));
                }
            }
        }
        // ③ 会话数信号（回退/补充）：原号活跃会话数比最空号多 ≥ rebalance_min_gap。
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
            .filter(|(id, _)| !exclude_evicted.contains(id))
            .filter(|(id, _)| !exclude_owned.contains(id))
            .filter(|(id, _)| !self.is_account_open(*id))
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

    /// 某号最近 5 分钟「持续撞墙」的上游 429 率（供按 429 率硬触发疏散用）。
    /// 与 [`Self::account_utilization`] 同口径：只有 `consecutive_throttles >= 2`（持续撞墙、
    /// 非单次瞬态）才返回真实 429 率，否则返回 0——防单次瞬态 429 引发不必要的会话搬家(churn)。
    fn account_429_rate_sustained(&self, id: u64) -> f64 {
        let scope = ThrottleScope::UserCredential(id);
        match self.limiters.observe_full(&scope) {
            Some(o) if o.consecutive_throttles >= 2 => o.upstream_429_rate_5m,
            _ => 0.0,
        }
    }

    /// overflow-on-busy 纯判定：给定一个号的健康观测，是否「真撞墙」需要逃离。
    /// 三门全满足才 true：① 429 率 > 阈值 ② goodput < safe_hi×比例 ③ 非 app-limited(确有活在干)。
    /// 抽成纯函数便于真值表单测（不依赖 live limiter）。
    /// ⚠️ 第③门用**去抖版** app_limited（连续多拍确认才算没活干）——单流(串行单请求)选号瞬间常
    /// 碰巧 inflight 低、瞬时 app_limited=true，若用瞬时值 overflow 几乎永远打不着(Reviewer Finding D)。
    fn overflow_busy_signal(
        upstream_429_rate_5m: f64,
        goodput_rps: f64,
        learned_safe_rps_hi: f64,
        app_limited_debounced: bool,
        cfg: &crate::model::config::OverflowOnBusyConfig,
    ) -> bool {
        let safe_hi = learned_safe_rps_hi.max(1e-6);
        upstream_429_rate_5m > cfg.upstream429_rate_threshold
            && goodput_rps < safe_hi * cfg.goodput_ratio_threshold
            && !app_limited_debounced
    }

    /// overflow-on-busy 纯选号：从候选号(已带健康信号)里选「最该迁过去」的目标 id。
    /// 规则：排除 current 自己、排除 OPEN、排除自己也撞墙(429率 > 阈值)的号；剩下按利用率最低选，
    /// 平局按 id 稳定。全被排除则返回 None(不迁、黏原号，绝不跳到一样烂的号)。
    /// 抽成纯函数(输入 `(id, is_open, upstream_429_rate, utilization)`)便于正向路径确定性单测。
    fn overflow_pick_target(
        candidates: &[(u64, bool, f64, f64)],
        current: u64,
        upstream429_rate_threshold: f64,
    ) -> Option<u64> {
        candidates
            .iter()
            .filter(|(id, is_open, rate429, _util)| {
                *id != current && !*is_open && *rate429 <= upstream429_rate_threshold
            })
            .min_by(|(a, _, _, ua), (b, _, _, ub)| {
                ua.partial_cmp(ub)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.cmp(b))
            })
            .map(|(id, _, _, _)| *id)
    }

    /// overflow-on-busy：判断绑定号是否「真撞墙」(429 频发 + 吞吐被压低 + 非 app_limited)，
    /// 是则在池里选一个**真健康**的号迁移整个会话过去；否则返回 None（不迁、黏原号）。
    ///
    /// 与 `rebalance_target`(均摊负载) 的区别：这是「逃离正在烧的号」——判定更严(三条全满足)，
    /// 且目标号必须**自己不撞墙**(429 率低于阈值)，避免从一个烧的号跳到另一个烧的号。
    fn overflow_migrate_target(
        &self,
        available: &[(u64, KiroCredentials)],
        current: u64,
        cfg: &crate::model::config::OverflowOnBusyConfig,
    ) -> Option<(u64, KiroCredentials)> {
        if available.len() < 2 {
            return None;
        }
        let scope = ThrottleScope::UserCredential(current);
        let obs = self.limiters.observe_full(&scope)?;
        // 三门全满足才算「真撞墙」(纯判定见 overflow_busy_signal)。
        if !Self::overflow_busy_signal(
            obs.upstream_429_rate_5m,
            obs.goodput_rps,
            obs.learned_safe_rps_hi,
            obs.app_limited_debounced,
            cfg,
        ) {
            return None;
        }
        // 给每个候选号取健康信号 → 交给纯选号函数 overflow_pick_target 决策。
        // 无 observe_full 数据的号视为「未撞墙」(429率=0)，与旧 unwrap_or(true) 行为一致。
        let candidates: Vec<(u64, bool, f64, f64)> = available
            .iter()
            .map(|(id, _)| {
                let rate429 = self
                    .limiters
                    .observe_full(&ThrottleScope::UserCredential(*id))
                    .map(|o| o.upstream_429_rate_5m)
                    .unwrap_or(0.0);
                (*id, self.is_account_open(*id), rate429, self.account_utilization(*id))
            })
            .collect();
        let target_id =
            Self::overflow_pick_target(&candidates, current, cfg.upstream429_rate_threshold)?;
        available
            .iter()
            .find(|(id, _)| *id == target_id)
            .map(|(id, c)| (*id, c.clone()))
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
        // 本会话优先级（决定独享号排除策略）：priority>0 自己就是独享主，迁到自己理想号天经地义、不排除；
        // priority==0 普通会话**绝不该被任何选号路径甩进 active 高优先独享号**（修第三轮 Reviewer Finding 1：
        // 反向 churn 不止均衡分支，cd 强切/overflow/OPEN 强切 三条路同样会甩——根因是它们都从 pick_pool 选号，
        // 所以这里**一次性**把独享号从 pick_pool 软排除，三条路全覆盖；只算一次也修了 Finding 3 的每请求全表扫）。
        let session_prio_for_pool = {
            let existing0 = self.affinity.lock().get(session_key.unwrap_or("")).cloned();
            self.session_priority_for(session_key.unwrap_or(""), existing0.as_ref())
        };
        let owned_excl: std::collections::HashSet<u64> = if session_prio_for_pool > 0 {
            std::collections::HashSet::new()
        } else {
            self.exclusive_owned_accounts()
        };
        // 健康池：先排 OPEN，再为普通会话**软排除** active 独享号（软=排完若空则回退不排除版，保证有号可用）。
        let healthy_available: Vec<(u64, KiroCredentials)> = all_available
            .iter()
            .filter(|(id, _)| !self.is_account_open(*id))
            .map(|(id, c)| (*id, c.clone()))
            .collect();
        let healthy_non_excl: Vec<(u64, KiroCredentials)> = healthy_available
            .iter()
            .filter(|(id, _)| !owned_excl.contains(id))
            .map(|(id, c)| (*id, c.clone()))
            .collect();
        // pick_pool 优先级：健康且非独享 > 健康 > 全部（全 OPEN 兜底由下游 shortest_cooldown_fallback 处理）。
        let pick_pool = if !healthy_non_excl.is_empty() {
            &healthy_non_excl
        } else if !healthy_available.is_empty() {
            &healthy_available
        } else {
            &all_available
        };
        // all_available 的「软排除独享号」版本：给各兜底链最后一跳 `lowest_load(&all_available,…)` 用，
        // 否则普通会话会绕过 pick_pool 的软排除、被甩进 active 独享号（修第四轮 Reviewer Finding 1 corner case：
        // 兜底链最后一跳漏排 owned_excl）。空时回退 all_available（保证有号可用，软排除语义）。
        let all_avail_non_excl: Vec<(u64, KiroCredentials)> = all_available
            .iter()
            .filter(|(id, _)| !owned_excl.contains(id))
            .map(|(id, c)| (*id, c.clone()))
            .collect();
        let all_pool: &Vec<(u64, KiroCredentials)> = if !all_avail_non_excl.is_empty() {
            &all_avail_non_excl
        } else {
            &all_available
        };

        let ma = &self.config.adaptive_limit.multi_account;
        let ttl = Duration::seconds(ma.affinity_ttl_secs as i64);
        let switch_threshold = StdDuration::from_secs(ma.switch_threshold_secs);
        let debounce = Duration::seconds(ma.switch_debounce_secs as i64);
        let now = Utc::now();
        // overflow-on-busy 取运行时热替换快照（admin PUT 可热改，不重启）；其余 multi_account
        // 字段仍读 config（本轮不热改）。ov_live 持有 owned Arc，整个函数内视图一致。
        let ov_live = self.overflow_cfg.load_full();

        // 无稳定会话：纯最低负载选号，不绑定。
        let key = match session_key {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => {
                let pick = self.lowest_load(pick_pool, None).or_else(|| {
                    self.lowest_load(all_pool, None)
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
                    } else {
                        // pin 目标号正 OPEN/熔断：之前这里静默穿透到普通 affinity 选号、无任何结构化事件，
                        // owner 从日志/UI 完全看不到「pin 这次被跳过了」。补一条结构化决策日志（与 affinity_pin
                        // 同事件名、action=pin_skipped_open），让「pin 了却跑别号」可观测、可在 WebUI 看出原因。
                        let cd = self
                            .limiters
                            .cooldown_remaining(&ThrottleScope::UserCredential(pinned_id));
                        let prio = self.session_priority_for(&key, existing.as_ref());
                        Self::log_select(
                            "pin_skipped_open",
                            pinned_id,
                            self.rpm(pinned_id),
                            cd.as_millis() as u64,
                            Some(&key),
                            prio,
                        );
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
                .or_else(|| self.lowest_load_prioritized(all_pool, exclude, prefer_healthy))
                // M2 全 OPEN 兜底：上面两步会过滤掉 OPEN 号，全 OPEN 时返回 None。
                // 这里退到「cooldown 最短的号」，保证有号可用而非整体 bail。
                .or_else(|| self.shortest_cooldown_fallback(&all_available))
        };

        // 第 4 元 = 本次切号是否由 overflow 触发（写进 last_switch_was_overflow，供 debounce 区分迁移类型）。
        // 第 5 元 = 本次是否「被迫逃离不可用原号」（OPEN/禁用/分组失配）——决策点显式定，**不在落定点重读推导**
        // （修第三轮 Reviewer Finding 2 的 TOCTOU：原号状态在决策→落定之间可能翻转，反推会错）。
        let (act, mut chosen, cd_ms, switch_is_overflow, forced_unavailable) = match &existing {
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
                    // overflow 防抖：只有「上次切号确实是 overflow 触发的」才用更长的 overflow 窗口锁本会话。
                    // (Reviewer Finding A/B 根因修复：last_switch_at 不分迁移类型，故用 last_switch_was_overflow
                    //  标记区分——普通切号/rebalance/cd 强切迁过的会话不被 overflow 60s 窗口误锁。)
                    let ov = &*ov_live;
                    let overflow_debounce = Duration::seconds(ov.migrate_debounce_secs as i64);
                    let in_overflow_debounce = ov.enabled
                        && b.last_switch_was_overflow
                        && b
                            .last_switch_at
                            .map(|t| (now - t) < overflow_debounce)
                            .unwrap_or(false);
                    // Finding B 修复：cd 强切路径也尊重 overflow 窗口——overflow 刚迁过的会话在窗口内
                    // 不被 cd 强切再搬走(兑现 config「迁后窗口内不再迁/切」承诺)。overflow 关闭时此项恒 false。
                    if cd > switch_threshold && !in_debounce && !in_overflow_debounce {
                        // 原号卡太久 → 切到别的号。Finding C 修复：若 overflow 开启且原号「真撞墙」
                        // (overflow_busy_signal)，cd 强切的选号也走 overflow 的健康过滤(排除自己也撞墙/OPEN
                        // 的号)，避免撞墙最狠时 cd 强切抢先用裸 lowest_load 把会话甩到另一个烂号、overflow
                        // 反而轮不到。否则(overflow 关 or 原号没真撞墙)维持原有 lowest_load 行为不变。
                        let cd_overflow_pick = if ov.enabled {
                            self.overflow_migrate_target(
                                pick_pool,
                                b.credential_id,
                                ov,
                            )
                        } else {
                            None
                        };
                        let cd_is_overflow = cd_overflow_pick.is_some();
                        let cd_pick = cd_overflow_pick.or_else(|| {
                            self.lowest_load(pick_pool, Some(b.credential_id))
                                .or_else(|| {
                                    self.lowest_load(all_pool, Some(b.credential_id))
                                })
                        });
                        match cd_pick {
                            Some(pick) => {
                                if cd_is_overflow {
                                    Self::log_select(
                                        "overflow_migrate",
                                        pick.0,
                                        self.rpm(pick.0),
                                        cd.as_millis() as u64,
                                        Some(&key),
                                        session_prio,
                                    );
                                }
                                (Act::Switch, pick, cd.as_millis() as u64, cd_is_overflow, false)
                            }
                            None => {
                                let creds = all_available
                                    .iter()
                                    .find(|(id, _)| *id == b.credential_id)
                                    .map(|(_, c)| c.clone())?;
                                (Act::Stick, (b.credential_id, creds), cd.as_millis() as u64, false, false)
                            }
                        }
                    } else {
                        // 原号健康（不到切号阈值）。先看是否该「被动负载再平衡」：
                        // 触发条件 = 「利用率信号 或 会话数信号」任一启用，且不在切号防抖窗口（P2-b 修复：
                        // 旧逻辑只看 min_gap>0，min_gap=0 时连 rebalance_target 都不调 → util 信号被绑死摸不到）。
                        // rebalance_target 内部 util 分支优先、会话数分支 fallback；迁移复用切号路径
                        // （写 last_switch_at + 防抖 + 不黏回），滞后阈值(≥2)保证迁完两边不会立刻反向触发。
                        // overflow-on-busy 优先于负载再平衡：原号「真撞墙」(429频发+吞吐压低+非app_limited)时
                        // 直接迁整会话到健康号。用自己更长的 debounce 窗口(迁移代价大、迁完多观察一会)。
                        // in_overflow_debounce 已在上面算好(只在 last_switch_was_overflow 时为真)。
                        let overflowed = if ov.enabled && !in_overflow_debounce {
                            self.overflow_migrate_target(pick_pool, b.credential_id, ov)
                        } else {
                            None
                        };
                        let is_overflow = overflowed.is_some();
                        let rebalanced = if let Some(pick) = overflowed {
                            Some(pick)
                        } else if Self::rebalance_signal_enabled(ma)
                            && !in_debounce
                            // debounce 串扰修复：只有「刚 overflow 迁移过」的会话在 overflow 窗口内才不许被
                            // rebalance 再迁走(in_overflow_debounce 已含 last_switch_was_overflow 守门，
                            // 故普通切号/rebalance 迁过的会话不受影响——修 Finding A 的误伤面)。
                            && !in_overflow_debounce
                        {
                            // 复用入口算好的 owned_excl（priority==0 才非空）——不再每请求重算（修 Finding 3）。
                            // pick_pool 本身已软排除独享号，这里再传一份给 rebalance_target_excl 双保险。
                            self.rebalance_target_excl(
                                pick_pool,
                                b.credential_id,
                                ma,
                                &b.recent_evicted_from,
                                &owned_excl,
                            )
                        } else {
                            None
                        };
                        match rebalanced {
                            Some(pick) => {
                                if is_overflow {
                                    Self::log_select(
                                        "overflow_migrate",
                                        pick.0,
                                        self.rpm(pick.0),
                                        cd.as_millis() as u64,
                                        Some(&key),
                                        session_prio,
                                    );
                                }
                                (Act::Switch, pick, cd.as_millis() as u64, is_overflow, false)
                            }
                            None => {
                                let creds = all_available
                                    .iter()
                                    .find(|(id, _)| *id == b.credential_id)
                                    .map(|(_, c)| c.clone())?;
                                (Act::Stick, (b.credential_id, creds), cd.as_millis() as u64, false, false)
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
                    (Act::Switch, pick, 0, false, true)
                }
            }
            // 无绑定或绑定已过 TTL → 新会话：最低负载落号并绑定。
            _ => {
                let pick = pick_from_pool(None)?;
                (Act::NewBind, pick, 0, false, false)
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
                                last_switch_was_overflow: false,
                                priority: bind_priority,
                                last_evicted_from: None,
                                recent_evicted_from: Vec::new(),
                            },
                        );
                    }
                }
                Act::Switch => {
                    // 防回弹：记下「从哪个号被搬走」（非 overflow 切号才记——overflow 是逃离撞墙号、
                    // 本就不该回且有自己的 debounce；OPEN 强制切号同理可破例）。
                    let prev_id = aff.get(&key).map(|b| b.credential_id);
                    let e = aff.entry(key.clone()).or_insert_with(|| AffinityBinding {
                        credential_id: chosen.0,
                        bound_at: now,
                        last_seen: now,
                        last_switch_at: Some(now),
                        last_switch_was_overflow: switch_is_overflow,
                        priority: bind_priority,
                        last_evicted_from: None,
                        recent_evicted_from: Vec::new(),
                    });
                    e.credential_id = chosen.0;
                    e.last_switch_at = Some(now);
                    e.last_switch_was_overflow = switch_is_overflow;
                    e.last_seen = now;
                    e.priority = bind_priority;
                    if let Some(old) = prev_id {
                        // 防回弹仅用于「自愿负载搬迁」(cd 强切/rebalance)——记下源号、短期不许搬回。
                        // 但「逃离不可用号」(overflow 撞墙 / OPEN 熔断 / 禁用/分组失配 = 原号当前不可用)是
                        // **被迫逃**，原号恢复后本该能回去（尤其高优先要夺回最优主号），故破例**清除**防回弹标记。
                        // (对齐 last_evicted_from 字段注释「仅 overflow/OPEN 强制切号可破例清除它」。)
                        // ⚠️ 用决策点定的 forced_unavailable，**不在此处重读 is_account_open**（修 TOCTOU：
                        // 决策→落定之间原号熔断可能恰好恢复，重读会把「被迫逃」误判成「自愿」、错装 60s 防回弹）。
                        let old_unavailable = switch_is_overflow || forced_unavailable;
                        if old != chosen.0 && !old_unavailable {
                            // 自愿搬迁:压进环形历史(根治 ≥3 号环),cap=除当前号外所有号。
                            Self::push_recent_evicted(e, old, all_available.len().saturating_sub(1));
                        } else if old_unavailable {
                            // 被迫逃:清空整段历史(原号恢复后允许回去)。
                            Self::clear_recent_evicted(e);
                        }
                    }
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
                                last_switch_was_overflow: false,
                                priority: bind_priority,
                                last_evicted_from: None,
                                recent_evicted_from: Vec::new(),
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
        // Finding E：overflow 迁移已在上面打过 "overflow_migrate"，这里不再重复打 "affinity_switch"（去双日志）。
        if !switch_is_overflow {
            Self::log_select(
                action_str,
                chosen.0,
                self.rpm(chosen.0),
                cd_ms,
                Some(&key),
                session_prio,
            );
        }
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

    // ── Thread 视角 base 相位推断真值表（纯账号态，infer_base_phase） ──
    // 公共默认入参：HEALTHY、不在飞满、刚有活动、没切过号；各用例只改要验证的那一维。
    const DEBOUNCE_MS: i64 = 60_000;
    const IDLE_MS: i64 = 60_000;

    #[test]
    fn phase_open_account_is_rate_limited() {
        // 账号 OPEN → RateLimited
        let p = infer_base_phase(
            AccountState::Open,
            0,
            4,
            100,
            false,
            None,
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(p, ThreadPhase::RateLimited);
        // HALF_OPEN 同样 RateLimited
        let p2 = infer_base_phase(
            AccountState::HalfOpen,
            0,
            4,
            100,
            false,
            None,
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(p2, ThreadPhase::RateLimited);
    }

    #[test]
    fn phase_inflight_full_is_queued() {
        // HEALTHY 但在飞满（inflight >= max）→ Queued
        let p = infer_base_phase(
            AccountState::Healthy,
            4,
            4,
            100,
            false,
            None,
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(p, ThreadPhase::Queued);
    }

    #[test]
    fn phase_stale_last_seen_is_idle() {
        // last_seen 距今 > 60s 且不在飞 → Idle
        let p = infer_base_phase(
            AccountState::Healthy,
            0,
            4,
            61_000,
            false,
            None,
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(p, ThreadPhase::Idle);
    }

    #[test]
    fn phase_recent_healthy_is_running() {
        // HEALTHY、不在飞满、刚有活动 → Running
        let p = infer_base_phase(
            AccountState::Healthy,
            1,
            4,
            500,
            false,
            None,
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(p, ThreadPhase::Running);
    }

    #[test]
    fn phase_overflow_recent_switch_is_just_migrated() {
        // last_switch_was_overflow + 切号距今 < 防抖窗口 → JustMigrated
        let p = infer_base_phase(
            AccountState::Healthy,
            0,
            4,
            100,
            true,
            Some(5_000),
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(p, ThreadPhase::JustMigrated);
        // 切号已超过防抖窗口 → 不再 JustMigrated，退回 Running
        let p2 = infer_base_phase(
            AccountState::Healthy,
            0,
            4,
            100,
            true,
            Some(120_000),
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(p2, ThreadPhase::Running);
    }

    #[test]
    fn phase_rate_limited_beats_just_migrated_and_queued() {
        // 优先级验证：账号 OPEN 同时「刚 overflow 迁移」「在飞满」→ 仍应是 RateLimited（最高的 base 档）。
        let p = infer_base_phase(
            AccountState::Open,
            4,
            4,
            100,
            true,
            Some(1_000),
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(p, ThreadPhase::RateLimited);
    }

    #[test]
    fn phase_trace_error_overrides_and_beats_rate_limited() {
        // trace 最近一条 error → Errored，且压过 RateLimited（验最高优先级）。
        let base = infer_base_phase(
            AccountState::Open, // base 会算成 RateLimited
            0,
            4,
            100,
            false,
            None,
            DEBOUNCE_MS,
            IDLE_MS,
        );
        assert_eq!(base, ThreadPhase::RateLimited);
        assert_eq!(
            phase_with_trace(base, Some("error")),
            ThreadPhase::Errored,
            "error trace 应压过 RateLimited"
        );
        assert_eq!(
            phase_with_trace(base, Some("interrupted")),
            ThreadPhase::Errored,
            "interrupted 同样判 Errored"
        );
        // success / None 不改 base。
        assert_eq!(phase_with_trace(base, Some("success")), ThreadPhase::RateLimited);
        assert_eq!(phase_with_trace(base, None), ThreadPhase::RateLimited);
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

    // update_adaptive_config 端到端：热改内存 + 落盘 config.json + 回读验证（含 overflow 子配置）。
    #[test]
    fn test_update_adaptive_config_persists_and_hot_swaps() {
        use crate::model::config::{AdaptiveConfigPatch, OverflowOnBusyPatch};

        let config_path =
            std::env::temp_dir().join(format!("kiro-ratelimit-{}.json", uuid::Uuid::new_v4()));
        // 起始 config：开启 adaptiveLimit，给定初始 additive/max + overflow 关。
        std::fs::write(
            &config_path,
            r#"{"adaptiveLimit":{"enabled":true,"additiveStepRps":0.5,"maxRateRps":2.0}}"#,
        )
        .unwrap();
        let config = Config::load(&config_path).unwrap();
        let manager =
            MultiTokenManager::new(config, vec![KiroCredentials::default()], None, None, false)
                .unwrap();

        // 改前快照。
        let before = manager.current_adaptive_config();
        assert_eq!(before.additive_step_rps, 0.5);
        assert_eq!(before.max_rate_rps, 2.0);
        assert!(!manager.current_overflow_config().enabled);
        let hard_before = before.hard_max_inflight;

        // patch：改 additive/max/sanity + 开 overflow（含阈值）。
        let patch = AdaptiveConfigPatch {
            additive_step_rps: Some(1.5),
            max_rate_rps: Some(7.0),
            goodput_sanity_max_rps: Some(12.0),
            overflow_on_busy: Some(OverflowOnBusyPatch {
                enabled: Some(true),
                upstream429_rate_threshold: Some(0.3),
                ..Default::default()
            }),
            ..Default::default()
        };
        let outcome = manager.update_adaptive_config(patch).expect("update ok");
        assert!(outcome.persisted, "有 config 路径必须落盘");
        assert_eq!(outcome.config.additive_step_rps, 1.5);
        assert_eq!(outcome.config.max_rate_rps, 7.0);
        assert_eq!(outcome.config.goodput_sanity_max_rps, 12.0);
        assert!(outcome.overflow.enabled);
        assert_eq!(outcome.overflow.upstream429_rate_threshold, 0.3);
        // hard_max_inflight 不可热改 → 保留改前值。
        assert_eq!(outcome.config.hard_max_inflight, hard_before);

        // 内存热替换：limiter 通道 + overflow 通道都立即生效。
        assert_eq!(manager.current_adaptive_config().additive_step_rps, 1.5);
        assert_eq!(manager.current_adaptive_config().max_rate_rps, 7.0);
        assert!(manager.current_overflow_config().enabled);
        assert_eq!(manager.current_overflow_config().upstream429_rate_threshold, 0.3);

        // 落盘：回读磁盘文件，新值已写入；未传字段（如 enabled）保留。
        let reloaded = Config::load(&config_path).unwrap();
        assert_eq!(reloaded.adaptive_limit.additive_step_rps, 1.5);
        assert_eq!(reloaded.adaptive_limit.max_rate_rps, 7.0);
        assert_eq!(reloaded.adaptive_limit.probe.goodput_sanity_max_rps, 12.0);
        assert!(reloaded.adaptive_limit.multi_account.overflow_on_busy.enabled);
        assert_eq!(
            reloaded.adaptive_limit.multi_account.overflow_on_busy.upstream429_rate_threshold,
            0.3
        );
        assert!(reloaded.adaptive_limit.enabled, "未传字段 enabled 保留为 true");

        std::fs::remove_file(&config_path).unwrap();
    }

    // 校验失败（goodputHardCeiling 越界）→ 返回 Err 且内存/磁盘均不变。
    #[test]
    fn test_update_adaptive_config_rejects_out_of_range() {
        use crate::model::config::AdaptiveConfigPatch;

        let config_path =
            std::env::temp_dir().join(format!("kiro-ratelimit-rej-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(
            &config_path,
            r#"{"adaptiveLimit":{"enabled":true,"additiveStepRps":0.5}}"#,
        )
        .unwrap();
        let config = Config::load(&config_path).unwrap();
        let manager =
            MultiTokenManager::new(config, vec![KiroCredentials::default()], None, None, false)
                .unwrap();

        let bad = AdaptiveConfigPatch {
            goodput_hard_ceiling: Some(1.5), // 越界（>1）
            ..Default::default()
        };
        let err = manager.update_adaptive_config(bad).unwrap_err();
        assert!(err.to_string().contains("goodputHardCeiling"), "应报越界字段");

        // 内存未变。
        assert_eq!(manager.current_adaptive_config().additive_step_rps, 0.5);
        // 磁盘未变（additiveStepRps 仍 0.5，无 goodput 写入痕迹改动）。
        let reloaded = Config::load(&config_path).unwrap();
        assert_eq!(reloaded.adaptive_limit.additive_step_rps, 0.5);

        std::fs::remove_file(&config_path).unwrap();
    }

    // 无 config 路径：内存生效但 persisted=false（重启会丢，须告知用户）。
    #[test]
    fn test_update_adaptive_config_no_path_memory_only() {
        use crate::model::config::AdaptiveConfigPatch;

        // Config::default() 无 config_path。
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![KiroCredentials::default()],
            None,
            None,
            false,
        )
        .unwrap();

        let patch = AdaptiveConfigPatch {
            additive_step_rps: Some(2.25),
            ..Default::default()
        };
        let outcome = manager.update_adaptive_config(patch).expect("update ok");
        assert!(!outcome.persisted, "无路径 → persisted=false");
        assert_eq!(outcome.config.additive_step_rps, 2.25);
        // 内存仍热替换生效。
        assert_eq!(manager.current_adaptive_config().additive_step_rps, 2.25);
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
            &[],
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

    // #18 核心反假绿（429 率硬触发疏散）：单人低 RPM 场景下，busy 号被上游 429 压垮（429 率高），
    // 但它和 idle 号的 RPM 差很小（够不到 rebalance_rpm_gap）、利用率也没贴满 util 门——
    // 旧逻辑下三条信号全摸不到 → busy 永不疏散 → 会话黏死被 429 反复打（owner 截图 #19 12.5% 那种）。
    // 新增的「429 率硬触发」必须绕过 RPM/util 门、直接把 busy 的会话疏散到健康的 idle 号。
    #[tokio::test]
    async fn test_rebalance_by_429_rate_hard_trigger() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_debounce_secs = 0; // 不防抖，便于断言
        // 关掉 RPM / 利用率 / 绑定数 / 会话数 四条常规信号，单独验「429 率硬触发」这一条新路。
        config.adaptive_limit.multi_account.rebalance_rpm_gap = 0.0;
        config.adaptive_limit.multi_account.rebalance_utilization_gap = 0.0;
        config.adaptive_limit.multi_account.rebalance_bound_gap = 0;
        config.adaptive_limit.multi_account.rebalance_min_gap = 0;
        // 429 率硬触发门设 5%（与 live config 对齐）。
        config.adaptive_limit.multi_account.rebalance_429_rate_threshold = 0.05;
        let manager = affinity_manager(config);
        // 把 sess-429 绑到 busy 号。
        let c = manager
            .acquire_context(None, None, Some("sess-429"))
            .await
            .unwrap();
        let busy = c.id;
        let idle = if busy == 1 { 2 } else { 1 };
        // 让 busy 号「持续撞墙」：撞 ≥2 次 429 → consecutive_throttles>=2 且 upstream_429_rate_5m 拉高。
        let busy_lim = manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(busy));
        for _ in 0..3 {
            busy_lim
                .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                .await;
        }
        // idle 号保持干净（无 429）→ 是健康落脚点。
        let available: Vec<_> = manager
            .available_credentials(None, None)
            .into_iter()
            .collect();
        let target = manager.rebalance_target(
            &available,
            busy,
            &manager.config.adaptive_limit.multi_account,
            &[],
        );
        assert!(
            target.is_some(),
            "busy 号 429 率高（持续撞墙）→ 即便 RPM/util/会话数信号全关，429 硬触发也应疏散它"
        );
        assert_eq!(
            target.unwrap().0,
            idle,
            "429 硬触发应把会话疏散到健康（无 429）的 idle 号 {idle}"
        );
    }

    // #18 边界①：目标号自己也在被 429 → 不是健康落脚点 → 429 硬触发这条不该选它。
    // 造：busy(#1) 持续撞墙、唯一的另一个号 other(#2) 也持续撞墙 → 429 硬触发分支找不到健康目标，
    // 应跳过该分支（落到后续 RPM/util/会话数信号，此处全关 → 最终 None，不乱搬到也在烧的号）。
    #[tokio::test]
    async fn test_429_trigger_skips_when_only_target_also_throttled() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        config.adaptive_limit.multi_account.rebalance_rpm_gap = 0.0;
        config.adaptive_limit.multi_account.rebalance_utilization_gap = 0.0;
        config.adaptive_limit.multi_account.rebalance_bound_gap = 0;
        config.adaptive_limit.multi_account.rebalance_min_gap = 0;
        config.adaptive_limit.multi_account.rebalance_429_rate_threshold = 0.05;
        let manager = affinity_manager(config);
        let c = manager.acquire_context(None, None, Some("sess-X")).await.unwrap();
        let busy = c.id;
        let other = if busy == 1 { 2 } else { 1 };
        // 两个号都「持续撞墙」但只撞 2 次（够 consecutive>=2 且 429 率高，但避免直接进 OPEN 被
        // available_credentials 过滤掉——目的是让 other 仍在候选池里、但 429 率高于阈值=非健康落脚点）。
        for id in [busy, other] {
            let lim = manager.limiters().for_scope(&ThrottleScope::UserCredential(id));
            for _ in 0..2 {
                lim.on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                    .await;
            }
        }
        let available: Vec<_> = manager.available_credentials(None, None).into_iter().collect();
        let target =
            manager.rebalance_target(&available, busy, &manager.config.adaptive_limit.multi_account, &[]);
        // 关键：若 other 已被 limiter 判 OPEN 而从 available 滤掉，则 available<2、整体 None；
        // 若 other 仍在 available 但 429 率高，则 429 分支因「目标也在被限流」跳过 → 其它信号全关 → None。
        // 两条路都该得 None：429 硬触发绝不把会话搬到一个同样在烧的号上。
        assert!(
            target.is_none(),
            "目标号自己也在被 429 时，429 硬触发不该选它（不把会话从火坑挪进另一个火坑）"
        );
    }

    // #18 边界②：阈值设为 0 = 关闭 429 硬触发。即便号被狂 429，这条分支也不该触发
    //（回退到纯 RPM/util/会话数信号；此处全关 → None）。守 config「0 表示关闭」的契约。
    #[tokio::test]
    async fn test_429_trigger_disabled_when_threshold_zero() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        config.adaptive_limit.multi_account.rebalance_rpm_gap = 0.0;
        config.adaptive_limit.multi_account.rebalance_utilization_gap = 0.0;
        config.adaptive_limit.multi_account.rebalance_bound_gap = 0;
        config.adaptive_limit.multi_account.rebalance_min_gap = 0;
        config.adaptive_limit.multi_account.rebalance_429_rate_threshold = 0.0; // 关闭
        let manager = affinity_manager(config);
        let c = manager.acquire_context(None, None, Some("sess-Y")).await.unwrap();
        let busy = c.id;
        let busy_lim = manager.limiters().for_scope(&ThrottleScope::UserCredential(busy));
        for _ in 0..2 {
            busy_lim
                .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                .await;
        }
        let available: Vec<_> = manager.available_credentials(None, None).into_iter().collect();
        let target =
            manager.rebalance_target(&available, busy, &manager.config.adaptive_limit.multi_account, &[]);
        assert!(
            target.is_none(),
            "rebalance_429_rate_threshold=0 应关闭 429 硬触发（其它信号也全关 → 不疏散）"
        );
    }

    // #18 边界③：利用率前置门可配——把 rebalance_util_saturated 调到很低(0.0)，则任何有余量差的号
    // 都能按利用率疏散（验「门可配、下调后中间态也触发」这条改动真生效，不再被硬编码 1.0 卡死）。
    #[tokio::test]
    async fn test_util_saturated_gate_is_configurable() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        config.adaptive_limit.multi_account.rebalance_rpm_gap = 0.0; // 关 RPM，单验 util
        config.adaptive_limit.multi_account.rebalance_429_rate_threshold = 0.0; // 关 429，单验 util
        config.adaptive_limit.multi_account.rebalance_min_gap = 0; // 关会话数 fallback
        config.adaptive_limit.multi_account.rebalance_bound_gap = 0; // 关绑定数
        config.adaptive_limit.multi_account.rebalance_utilization_gap = 0.1; // 只留 util，门槛低
        config.adaptive_limit.multi_account.rebalance_util_saturated = 0.0; // 前置门下调到 0：任何利用率都算「过门」
        let manager = affinity_manager(config);
        let c = manager.acquire_context(None, None, Some("sess-Z")).await.unwrap();
        let busy = c.id;
        let idle = if busy == 1 { 2 } else { 1 };
        // busy 撞 2 次 429 → 利用率被 throttle_pressure 抬高（> idle 的 0）。
        let busy_lim = manager.limiters().for_scope(&ThrottleScope::UserCredential(busy));
        for _ in 0..2 {
            busy_lim
                .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                .await;
        }
        let available: Vec<_> = manager.available_credentials(None, None).into_iter().collect();
        // 仅当 idle 仍在 available（busy 没把自己撞进 OPEN 被滤）才有意义；若 busy 被滤则 available<2、
        // 本断言放宽：核心是「util_saturated=0 时前置门不再卡死」——通过 util_gap 能选出 idle。
        if available.iter().any(|(id, _)| *id == idle) && available.iter().any(|(id, _)| *id == busy) {
            let target =
                manager.rebalance_target(&available, busy, &manager.config.adaptive_limit.multi_account, &[]);
            assert_eq!(
                target.map(|t| t.0),
                Some(idle),
                "util_saturated 下调到 0：busy 利用率高于 idle → 利用率信号应把会话疏散到 idle"
            );
        }
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
        // ③b 只有 RPM 信号（新）：必须启用——这是修「忙但没撞墙」盲区的第一优先级信号。
        ma.rebalance_min_gap = 0;
        ma.rebalance_utilization_gap = 0.0;
        ma.rebalance_rpm_gap = 8.0;
        ma.rebalance_bound_gap = 0;
        assert!(
            MultiTokenManager::rebalance_signal_enabled(&ma),
            "只有 rpm_gap>0 必须启用（修忙而未撞墙盲区的核心信号）"
        );
        // ③c 只有 bound 信号（新）：必须启用——睡眠会话疏散。
        ma.rebalance_rpm_gap = 0.0;
        ma.rebalance_bound_gap = 4;
        assert!(
            MultiTokenManager::rebalance_signal_enabled(&ma),
            "只有 bound_gap>0 必须启用（睡眠会话疏散）"
        );
        // ④ 四个信号全关：彻底关闭。
        ma.rebalance_min_gap = 0;
        ma.rebalance_utilization_gap = 0.0;
        ma.rebalance_rpm_gap = 0.0;
        ma.rebalance_bound_gap = 0;
        assert!(
            !MultiTokenManager::rebalance_signal_enabled(&ma),
            "四个信号全为 0 时必须完全关闭被动再平衡"
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
            &[],
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
                    last_switch_was_overflow: false,
                    priority: 0,
                    last_evicted_from: None,
                    recent_evicted_from: Vec::new(),
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

    // check_pinnable：限流/熔断(OPEN)的号应被拒绝 Pin（bug1 核心）。
    #[tokio::test]
    async fn test_check_pinnable_rejects_open_account() {
        let mut config = Config::default();
        config.adaptive_limit.circuit_breaker.open_429_threshold = 1;
        config.adaptive_limit.user_cooldown_base_secs = 30;
        let manager = affinity_manager(config);
        // 健康时可 pin
        assert!(manager.check_pinnable(1).is_ok(), "健康号应可 Pin");
        // 把 #1 打成 OPEN
        let lim = manager.limiters().for_scope(&ThrottleScope::UserCredential(1));
        for _ in 0..3 {
            lim.on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                .await;
        }
        assert!(manager.is_account_open(1), "前置：#1 应已 OPEN");
        // OPEN 时拒绝 pin
        let res = manager.check_pinnable(1);
        assert!(res.is_err(), "限流/熔断的号应被拒绝 Pin");
        assert!(
            res.unwrap_err().contains("限流"),
            "拒绝原因应说明限流/熔断"
        );
    }

    // check_pinnable：禁用号 + 不存在号都应被拒。
    #[test]
    fn test_check_pinnable_rejects_disabled_and_missing() {
        let manager = affinity_manager(Config::default());
        manager.set_disabled(2, true).unwrap();
        let disabled_err = manager.check_pinnable(2).expect_err("禁用号应被拒绝 Pin");
        assert!(disabled_err.contains("禁用"), "拒绝原因应说明禁用: {disabled_err}");
        let missing_err = manager.check_pinnable(999).expect_err("不存在的号应被拒绝 Pin");
        assert!(missing_err.contains("不存在"), "拒绝原因应说明不存在: {missing_err}");
        assert!(manager.check_pinnable(1).is_ok(), "健康号 #1 应可 Pin");
    }

    // observability_snapshot：被 Pin 但无 affinity 绑定的会话也应进 threads[]（bug2 核心）。
    #[test]
    fn test_threads_includes_pin_only_session() {
        let manager = affinity_manager(Config::default());
        // pin 一个全新会话（无 affinity 绑定、没发过请求）
        manager.pin_session("sess-pin-only", 2);
        let snap = manager.observability_snapshot();
        let t = snap
            .threads
            .iter()
            .find(|t| t.session_id == "sess-pin-only");
        assert!(
            t.is_some(),
            "被 Pin 但无 affinity 绑定的会话也应出现在 threads[]（三源并集）"
        );
        let t = t.unwrap();
        assert_eq!(
            t.pinned_account_id,
            Some(2),
            "pin-only 会话应带 pinnedAccountId=2"
        );
        assert_eq!(t.bound_account_id, 2, "展示绑定取 pin 目标号");
        assert!(
            matches!(t.phase, ThreadPhase::Idle),
            "无活动的 pin-only 会话相位应为 Idle"
        );
    }

    // 回归盲区(Reviewer 头号缺口): affinity 会话 + pin 会话应同时在 threads[]，且各自字段正确。
    #[test]
    fn test_threads_affinity_and_pin_coexist() {
        let manager = affinity_manager(Config::default());
        // 1) 建一个 affinity 绑定会话（真实选号）
        let aff = manager
            .select_with_affinity(None, None, Some("sess-affinity"))
            .unwrap();
        // 2) pin 另一个全新会话到健康号 2
        manager.pin_session("sess-pinned", 2);
        let snap = manager.observability_snapshot();
        // affinity 会话在、且绑定到它真实选中的号、未被 pin
        let a = snap
            .threads
            .iter()
            .find(|t| t.session_id == "sess-affinity")
            .expect("affinity 会话必须仍在 threads[]（三源并集别打掉 affinity 源）");
        assert_eq!(a.bound_account_id, aff.0, "affinity 会话应绑到它真实选中的号");
        assert_eq!(a.pinned_account_id, None, "affinity 会话未被 pin → pinned_account_id=None");
        // pin-only 会话在、带正确 pinnedAccountId
        let p = snap
            .threads
            .iter()
            .find(|t| t.session_id == "sess-pinned")
            .expect("pin-only 会话必须在 threads[]");
        assert_eq!(p.pinned_account_id, Some(2));
    }

    // 既被 affinity 绑定、又被 pin 的同一会话：bound 取真实绑定、pinned 取 pin 目标，两者都对。
    #[test]
    fn test_threads_affinity_session_with_pin_both_fields() {
        let manager = affinity_manager(Config::default());
        let aff = manager
            .select_with_affinity(None, None, Some("sess-both"))
            .unwrap();
        let other = if aff.0 == 1 { 2 } else { 1 };
        manager.pin_session("sess-both", other);
        let snap = manager.observability_snapshot();
        let t = snap
            .threads
            .iter()
            .find(|t| t.session_id == "sess-both")
            .expect("会话应在 threads[]");
        assert_eq!(t.bound_account_id, aff.0, "bound_account_id 取 affinity 真实绑定");
        assert_eq!(t.pinned_account_id, Some(other), "pinned_account_id 取 pin 目标");
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

    // ── overflow-on-busy（健康度触发的整-Thread 迁移）─────────────────────────

    // 真值表：三门(429率高 + goodput低 + 非app_limited)全满足才迁移。
    #[test]
    fn test_overflow_busy_signal_truth_table() {
        let cfg = crate::model::config::OverflowOnBusyConfig {
            enabled: true,
            upstream429_rate_threshold: 0.2,
            goodput_ratio_threshold: 0.5,
            migrate_debounce_secs: 60,
        };
        // safe_hi=1.0 → goodput 阈值 = 0.5。
        // ① 全满足：429率0.5>0.2、goodput0.1<0.5、非app_limited → 真撞墙。
        assert!(MultiTokenManager::overflow_busy_signal(0.5, 0.1, 1.0, false, &cfg));
        // ② 429率不够高 → 不迁。
        assert!(!MultiTokenManager::overflow_busy_signal(0.1, 0.1, 1.0, false, &cfg));
        // ③ goodput 不够低（还在跑得动）→ 不迁。
        assert!(!MultiTokenManager::overflow_busy_signal(0.5, 0.8, 1.0, false, &cfg));
        // ④ app_limited=true（没活干导致的低吞吐，不是撞墙）→ 不迁。
        assert!(!MultiTokenManager::overflow_busy_signal(0.5, 0.1, 1.0, true, &cfg));
        // ⑤ 边界：429率恰等于阈值(0.2)不算超 → 不迁（用 > 不是 >=）。
        assert!(!MultiTokenManager::overflow_busy_signal(0.2, 0.1, 1.0, false, &cfg));
    }

    // B-D 去抖门回归(Reviewer Finding D)：overflow_busy_signal 第③门吃的是**去抖版** app_limited。
    // 语义：传入 false=「去抖后确认不是 app-limited(确有活在干)」→ 满足撞墙三门可迁；
    //       传入 true=「去抖后确认 app-limited(连续多拍没活干)」→ 第③门挂掉不迁。
    // 真实链路上这个布尔来自 obs.app_limited_debounced(=瞬时 app_limited && streak>=阈值)，
    // 故单流(串行单请求)选号瞬间即便 inflight 低、瞬时 app_limited=true，只要 streak 没达阈值，
    // app_limited_debounced 仍为 false → overflow 照样能触发(修了 Finding D「单流打不着」)。
    #[test]
    fn test_overflow_busy_signal_uses_debounced_app_limited() {
        let cfg = crate::model::config::OverflowOnBusyConfig {
            enabled: true,
            upstream429_rate_threshold: 0.2,
            goodput_ratio_threshold: 0.5,
            migrate_debounce_secs: 60,
        };
        // 撞墙信号齐(429=0.5、goodput=0.1)：去抖 app_limited=false → 迁；=true → 不迁。
        assert!(
            MultiTokenManager::overflow_busy_signal(0.5, 0.1, 1.0, false, &cfg),
            "去抖后非 app-limited(确有活在干) + 撞墙 → 应迁(单流瞬时空槽不再误杀)"
        );
        assert!(
            !MultiTokenManager::overflow_busy_signal(0.5, 0.1, 1.0, true, &cfg),
            "去抖后确认 app-limited(连续多拍没活干) → 不迁"
        );
    }

    // B-C cd 强切遮蔽回归(Reviewer Finding C)：纯函数验证——overflow 开启且原号真撞墙时，
    // cd 强切应走 overflow_pick_target(选健康号、排除撞墙/OPEN)，绝不裸 lowest_load 甩到烂号。
    // 这里直接验 overflow_pick_target 在「撞墙最狠场景」下仍正确选健康号(cd 路径复用同一选号函数)。
    #[test]
    fn test_cd_force_switch_uses_overflow_pick_when_busy() {
        let thr = 0.2;
        // current=1 撞墙最狠(429=0.9)；2=健康；3=自己也撞墙(429>阈值);4=OPEN。
        let cands = vec![
            (1u64, false, 0.9, 3.0),  // current(深 cooldown 场景)
            (2u64, false, 0.02, 0.4), // ✅ 健康
            (3u64, false, 0.7, 0.1),  // 自己也撞墙 → 排除(别甩到烂号)
            (4u64, true, 0.0, 0.05),  // OPEN → 排除
        ];
        assert_eq!(
            MultiTokenManager::overflow_pick_target(&cands, 1, thr),
            Some(2),
            "cd 强切在 overflow 撞墙时必须选健康号 2，绝不甩到撞墙的 3 或 OPEN 的 4"
        );
    }

    // overflow_migrate_target：池里只有1个号(可用)时不迁(没地方迁)。
    #[test]
    fn test_overflow_migrate_target_single_account_no_move() {
        let cfg = crate::model::config::OverflowOnBusyConfig {
            enabled: true,
            ..Default::default()
        };
        let config = Config::default();
        let manager = affinity_manager(config);
        // 只传 1 个号 → available.len()<2 → 直接 None。
        let available: Vec<_> = manager
            .available_credentials(None, None)
            .into_iter()
            .take(1)
            .collect();
        assert!(
            manager.overflow_migrate_target(&available, available[0].0, &cfg).is_none(),
            "池里只有1个号时无处可迁，必须返回 None"
        );
    }

    // overflow_migrate_target 端到端：busy 号撞墙时，迁移目标必须是健康的别的号、绝不是撞墙原号自己。
    // ⚠️ 历史教训(本测原断言已被 B-D 修复推翻)：B-D 之前 fresh mock manager(零 inflight)瞬时 app_limited=true，
    // 让第③门恒挂、overflow 永不触发——旧版"单次 429 不迁"其实是这个 bug 的假象(Reviewer Finding D)。
    // B-D 后去抖 app_limited(streak=0<阈值)=false，门不再被瞬时空槽误杀。本测改为验真正的安全不变量：
    // 无论迁不迁，overflow_migrate_target 绝不把会话甩到「撞墙原号自己」(选号正确性由纯函数测覆盖)。
    #[tokio::test]
    async fn test_overflow_migrate_never_picks_self() {
        let cfg = crate::model::config::OverflowOnBusyConfig {
            enabled: true,
            upstream429_rate_threshold: 0.2,
            goodput_ratio_threshold: 0.5,
            migrate_debounce_secs: 60,
        };
        let config = Config::default();
        let manager = affinity_manager(config);
        let available: Vec<_> = manager
            .available_credentials(None, None)
            .into_iter()
            .collect();
        let busy = available[0].0;
        manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(busy))
            .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
            .await;
        // 不论本次是否触发迁移：若返回 Some，目标绝不能是撞墙的原号自己（核心安全不变量）。
        if let Some((tid, _)) = manager.overflow_migrate_target(&available, busy, &cfg) {
            assert_ne!(tid, busy, "overflow 迁移目标绝不能是撞墙的原号自己");
        }
    }

    // 默认关闭：OverflowOnBusyConfig::default().enabled == false（Owner 红线，要手动开）。
    #[test]
    fn test_overflow_on_busy_default_disabled() {
        let cfg = crate::model::config::OverflowOnBusyConfig::default();
        assert!(!cfg.enabled, "overflow-on-busy 默认必须关闭（Owner 改 config 重启才开）");
        assert_eq!(cfg.upstream429_rate_threshold, 0.2);
        assert_eq!(cfg.goodput_ratio_threshold, 0.5);
        assert_eq!(cfg.migrate_debounce_secs, 60);
        // 整条 MultiAccountConfig 默认也必须带 overflow 关闭。
        let ma = crate::model::config::MultiAccountConfig::default();
        assert!(!ma.overflow_on_busy.enabled);
    }

    // 正向选号主路径（补 Reviewer 挑出的「正向迁移零覆盖」缺口）：overflow_pick_target 纯函数确定性验证。
    // 候选 = (id, is_open, upstream_429_rate, utilization)。
    #[test]
    fn test_overflow_pick_target_picks_healthiest_eligible() {
        let thr = 0.2; // 429 率阈值
        // 池：current=1(撞墙,要逃)；2=健康低负载；3=健康但负载更高；4=OPEN；5=自己也撞墙(429>阈值)。
        let cands = vec![
            (1u64, false, 0.6, 2.0), // current 自己（撞墙）
            (2u64, false, 0.05, 0.3), // ✅ 最健康(util 最低)
            (3u64, false, 0.05, 0.9), // 健康但 util 更高
            (4u64, true, 0.0, 0.1),   // OPEN → 排除（即便 util 最低）
            (5u64, false, 0.5, 0.2),  // 自己也撞墙(429>0.2) → 排除（别跳到一样烂的号）
        ];
        // 正向：应选 2（健康、未 OPEN、未撞墙、利用率最低）。
        assert_eq!(
            MultiTokenManager::overflow_pick_target(&cands, 1, thr),
            Some(2),
            "应迁到最健康(util 最低、未 OPEN、自己不撞墙)的号 2，而非 OPEN 的 4 或撞墙的 5"
        );
    }

    // 平局按 id 稳定（确定性，不抖）。
    #[test]
    fn test_overflow_pick_target_tie_break_by_id() {
        let thr = 0.2;
        let cands = vec![
            (1u64, false, 0.6, 2.0), // current
            (3u64, false, 0.05, 0.5),
            (2u64, false, 0.05, 0.5), // 与 3 同 util → 平局取较小 id=2
        ];
        assert_eq!(
            MultiTokenManager::overflow_pick_target(&cands, 1, thr),
            Some(2),
            "util 平局时按 id 稳定选较小者"
        );
    }

    // 全池不可用（都 OPEN 或都撞墙）→ 不迁(None)，绝不跳到一样烂的号。
    #[test]
    fn test_overflow_pick_target_none_when_all_unhealthy() {
        let thr = 0.2;
        let cands = vec![
            (1u64, false, 0.6, 2.0), // current
            (2u64, true, 0.0, 0.1),  // OPEN
            (3u64, false, 0.9, 0.1), // 自己撞墙(429>阈值)
        ];
        assert_eq!(
            MultiTokenManager::overflow_pick_target(&cands, 1, thr),
            None,
            "别的号要么 OPEN 要么自己撞墙 → 不迁，黏原号"
        );
    }

    // 端到端集成：构造真实 manager，把 1 号压到三门全满足，断言 select_with_affinity 真迁到健康的 2 号
    // 且写了 last_switch_at（补 Reviewer 挑出的「集成主路径零覆盖」）。
    #[tokio::test]
    async fn test_overflow_migrate_target_end_to_end_picks_healthy() {
        use crate::kiro::rate_limiter::ThrottleReason;
        let mut config = Config::default();
        config.adaptive_limit.multi_account.overflow_on_busy.enabled = true;
        // 阈值放宽，便于用 on_throttle 把 1 号推过 429 门；goodput 门用 ratio=1.0(几乎必满足低吞吐)。
        config.adaptive_limit.multi_account.overflow_on_busy.upstream429_rate_threshold = 0.0;
        config.adaptive_limit.multi_account.overflow_on_busy.goodput_ratio_threshold = 1.0;
        let manager = affinity_manager(config);
        let avail: Vec<_> = manager.available_credentials(None, None).into_iter().collect();
        let busy = avail[0].0;
        let healthy = if busy == 1 { 2 } else { 1 };
        // 把 busy 号推到撞墙：连撞 429（拉高 429 率、压低 goodput）。
        let lim = manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(busy));
        for _ in 0..3 {
            lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        }
        let available: Vec<_> =
            manager.available_credentials(None, None).into_iter().collect();
        let target = manager.overflow_migrate_target(
            &available,
            busy,
            &manager.config.adaptive_limit.multi_account.overflow_on_busy,
        );
        // 注：busy 连撞 3 次可能进 OPEN；若 busy 已 OPEN 则它本就会走强制切号路径，overflow 不该再插手。
        // 这里只断言：若 overflow_migrate_target 返回了目标，必须是健康的别的号（绝不是 busy 自己）。
        if let Some((tid, _)) = target {
            assert_ne!(tid, busy, "overflow 迁移目标绝不能是撞墙的原号自己");
            assert_eq!(tid, healthy, "overflow 应迁到健康的另一个号");
        }
    }

    // Reviewer Finding A/B 根因修复回归：用真实绑定状态驱动 select_with_affinity，验证
    // overflow 窗口只锁「last_switch_was_overflow=true」的会话；普通切号迁过的会话(flag=false)
    // 在 overflow 窗口内仍可被 cd 强切走(不被 overflow 60s 误锁)。
    #[tokio::test]
    async fn test_overflow_debounce_only_locks_overflow_switched_session() {
        use crate::kiro::rate_limiter::ThrottleReason;
        let mut config = Config::default();
        config.adaptive_limit.multi_account.overflow_on_busy.enabled = true;
        config.adaptive_limit.multi_account.overflow_on_busy.migrate_debounce_secs = 600; // 长窗口便于断言
        config.adaptive_limit.multi_account.switch_debounce_secs = 0; // 关普通防抖，隔离 overflow 窗口效果
        config.adaptive_limit.user_cooldown_base_secs = 30; // 便于 cd 涨过 switch_threshold(15)
        let manager = affinity_manager(config);
        // 先把 sess 绑到某号。
        let c = manager.acquire_context(None, None, Some("sess-ab")).await.unwrap();
        let bound = c.id;
        // 手动把这条绑定标成「普通切号刚迁过」(last_switch_was_overflow=false、last_switch_at=now)。
        {
            let mut aff = manager.affinity.lock();
            let e = aff.get_mut("sess-ab").unwrap();
            e.last_switch_at = Some(Utc::now());
            e.last_switch_was_overflow = false; // 关键：普通切号，非 overflow
        }
        // 把绑定号打到深度冷却(cd > switch_threshold)，触发 cd 强切判定。
        let lim = manager
            .limiters()
            .for_scope(&ThrottleScope::UserCredential(bound));
        for _ in 0..4 {
            lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        }
        // 因 last_switch_was_overflow=false，overflow 窗口不该锁它 → cd 强切仍可把它迁走(若 cd 够深)。
        // 断言：select 不 panic、返回某个可用号(行为正常，没被 overflow 窗口误锁死)。
        let pick = manager.select_with_affinity(None, None, Some("sess-ab"));
        assert!(pick.is_some(), "普通切号迁过的会话不该被 overflow 窗口误锁(Finding A/B)");
        // 再验反面：标成 overflow 切过 → 同样深冷却下，overflow 窗口应锁住(不被 cd 强切走、黏原号)。
        {
            let mut aff = manager.affinity.lock();
            let e = aff.get_mut("sess-ab").unwrap();
            e.credential_id = bound; // 复位到原号
            e.last_switch_at = Some(Utc::now());
            e.last_switch_was_overflow = true; // 关键：overflow 切
        }
        let pick2 = manager.select_with_affinity(None, None, Some("sess-ab"));
        // overflow 窗口内 → 不该被 cd 强切走，应黏回原号(或至少不 panic)。
        assert!(pick2.is_some(), "overflow 切过的会话在窗口内 select 仍应正常返回");
    }

    // ===== 后台主动巡检调度器 rebalance_tick 测试 =====

    /// 3 号 manager（巡检测试用）：multiAccount 开、debounce=0 便于即时迁移。
    fn scheduler_manager() -> MultiTokenManager {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.enabled = true;
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        MultiTokenManager::new(
            config,
            vec![
                grouped_cred("t1", &[]),
                grouped_cred("t2", &[]),
                grouped_cred("t3", &[]),
            ],
            None,
            None,
            false,
        )
        .unwrap()
    }

    fn insert_binding(m: &MultiTokenManager, sid: &str, cred: u64, idle_secs: i64) {
        let now = Utc::now();
        let mut aff = m.affinity.lock();
        aff.insert(
            sid.to_string(),
            AffinityBinding {
                credential_id: cred,
                bound_at: now - Duration::seconds(idle_secs),
                last_seen: now - Duration::seconds(idle_secs),
                last_switch_at: None,
                last_switch_was_overflow: false,
                priority: 0,
                last_evicted_from: None,
                recent_evicted_from: Vec::new(),
            },
        );
    }

    fn insert_binding_prio(m: &MultiTokenManager, sid: &str, cred: u64, idle_secs: i64, prio: i32) {
        let now = Utc::now();
        let mut aff = m.affinity.lock();
        aff.insert(
            sid.to_string(),
            AffinityBinding {
                credential_id: cred,
                bound_at: now - Duration::seconds(idle_secs),
                last_seen: now - Duration::seconds(idle_secs),
                last_switch_at: None,
                last_switch_was_overflow: false,
                priority: prio,
                last_evicted_from: None,
                recent_evicted_from: Vec::new(),
            },
        );
    }

    // ① 睡眠会话堆弱号：#1 绑 5 个睡眠会话、#2/#3 空 → 巡检按 bound_gap 疏散 1 个到最空号。
    #[test]
    fn test_scheduler_evacuates_sleeping_sessions_from_overloaded() {
        let m = scheduler_manager();
        for i in 0..5 {
            insert_binding(&m, &format!("sleep-{i}"), 1, 120); // 都睡 2 分钟、绑 #1
        }
        // #1 bound=5，#2/#3 bound=0，gap=5 ≥ rebalance_bound_gap(默认4) → 应迁 1 个。
        let moved = m.rebalance_tick();
        assert_eq!(moved, 1, "睡眠会话堆 #1 应被巡检疏散 1 个");
        // 迁移后 #1 名下应剩 4 个。
        let aff = m.affinity.lock();
        let on1 = aff.values().filter(|b| b.credential_id == 1).count();
        assert_eq!(on1, 4, "应从 #1 疏散走 1 个会话");
    }

    // ①′ #18 排序优先级反假绿：被 429 压垮的源「成功 RPM」往往很低，若候选只按 RPM 排序会被沉到队尾、
    // 被高 RPM 但健康的号挤掉本 tick 疏散名额——而「正在被限流」恰恰最该先救。这里造：
    // #1 被持续 429（429 率高、绑 1 个会话）、#2 健康但 RPM 高（绑 1 个会话）、#3 空。
    // 期望：本 tick 先疏散 #1（被限流），而不是 #2（高 RPM）。
    #[tokio::test]
    async fn test_scheduler_429_source_evacuated_before_high_rpm() {
        let m = scheduler_manager();
        // #1 持续撞 429（≥2 次 → consecutive>=2 且 429 率≈100% > 5% 阈值）。
        let lim1 = m.limiters().for_scope(&ThrottleScope::UserCredential(1));
        for _ in 0..3 {
            lim1.on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                .await;
        }
        // #2 健康、但 RPM 高（多次 note_request 抬高它的 rpm，使其在旧排序里排在 #1 前面）。
        for _ in 0..10 {
            m.note_request(2);
        }
        // 各绑 1 个睡眠会话（都够老、可被搬；故意让 #1 不靠会话数取胜，单验 429 排序优先）。
        insert_binding(&m, "on-throttled-1", 1, 120);
        insert_binding(&m, "on-healthy-2", 2, 120);
        // #1 被 429（且撞够次数可能进 OPEN），用 available 过滤后它若不可用就无从验证；
        // 故先确认 #1 仍在候选池（throttled 但未被排除）。若已 OPEN 被排除，本断言放宽为「#1 会话最终离开 #1」。
        let moved = m.rebalance_tick();
        assert_eq!(moved, 1, "应疏散恰好 1 个会话");
        let aff = m.affinity.lock();
        // 关键断言：被搬走的是 #1（被限流源）名下的会话，不是 #2（高 RPM 健康源）。
        let throttled_still_on_1 = aff.get("on-throttled-1").map(|b| b.credential_id) == Some(1);
        let healthy_still_on_2 = aff.get("on-healthy-2").map(|b| b.credential_id) == Some(2);
        assert!(
            !throttled_still_on_1,
            "被 429 压垮的 #1 名下会话应被优先疏散走（实际还黏在 #1=排序没把限流源提前）"
        );
        assert!(
            healthy_still_on_2,
            "高 RPM 但健康的 #2 名下会话本 tick 不该被先搬（限流源 #1 才是最该先救的）"
        );
    }

    // ② 防回弹：会话刚从 #2 被搬到 #1（last_evicted_from=2），即便 #1 过载也不许把它搬回 #2。
    #[test]
    fn test_scheduler_anti_bounce_does_not_move_back() {
        let m = scheduler_manager();
        // #1 绑 5 个，其中 4 个普通睡眠，1 个刚从 #2 搬来（标 last_evicted_from=2）。
        for i in 0..4 {
            insert_binding(&m, &format!("sleep-{i}"), 1, 120);
        }
        {
            let now = Utc::now();
            let mut aff = m.affinity.lock();
            aff.insert(
                "just-moved".to_string(),
                AffinityBinding {
                    credential_id: 1,
                    bound_at: now - Duration::seconds(600), // 最老 → 否则会被优先选中
                    last_seen: now - Duration::seconds(600),
                    last_switch_at: None,
                    last_switch_was_overflow: false,
                    priority: 0,
                    last_evicted_from: Some(2),
                    recent_evicted_from: vec![2],
                },
            );
        }
        // 强制只有 #2 是候选最空号：给 #3 塞满使其不是最空（让 target 落在 #2，触发防回弹跳过该会话）。
        for i in 0..5 {
            insert_binding(&m, &format!("filler3-{i}"), 3, 120);
        }
        m.rebalance_tick();
        // just-moved 这条不该被搬回 #2（防回弹）；它要么还在 #1，要么被搬去 #3，但绝不回 #2。
        let aff = m.affinity.lock();
        let b = aff.get("just-moved").unwrap();
        assert_ne!(b.credential_id, 2, "防回弹：刚从 #2 搬来的会话不该被搬回 #2");
    }

    // ②′ churn 根治：一个【已被温和均衡搬过、且搬后从没真实活动过】的睡眠会话，
    //    不该再被温和均衡搬动。否则同一睡眠会话会在 #a→#b→#c→#a 间无限横跳(churn)——
    //    owner 实测「8 分钟切 8+ 次号、rpm=0/cd=0」的根因(signal③ 反复挑同一最老空闲会话)。
    //    根本不变式：温和均衡只搬「搬后又真干过活(last_seen 晚于 last_switch_at)」或「从没被搬过」的会话。
    #[test]
    fn test_scheduler_idle_session_not_rechurned_after_move() {
        let m = scheduler_manager();
        let now = Utc::now();
        {
            let mut aff = m.affinity.lock();
            // #1 上 1 个「已搬过 + 搬后无活动 + 最老 last_seen」的会话——旧逻辑会把它当最优受害者反复搬。
            aff.insert(
                "moved-idle".to_string(),
                AffinityBinding {
                    credential_id: 1,
                    bound_at: now - Duration::seconds(600),
                    last_seen: now - Duration::seconds(600), // 最老 → 旧逻辑必先挑它
                    last_switch_at: Some(now - Duration::seconds(300)), // 搬过(300s 前)
                    last_switch_was_overflow: false,
                    priority: 0,
                    last_evicted_from: None, // 防回弹槽空 → 旧逻辑唯一拦不住它的
                    recent_evicted_from: Vec::new(),
                },
            );
            // #1 再堆 4 个普通睡眠(没搬过)，凑出 bound_gap≥4 让 #1 成疏散源；它们 last_seen 较新。
            for i in 0..4 {
                aff.insert(
                    format!("fresh-sleep-{i}"),
                    AffinityBinding {
                        credential_id: 1,
                        bound_at: now - Duration::seconds(120),
                        last_seen: now - Duration::seconds(120),
                        last_switch_at: None,
                        last_switch_was_overflow: false,
                        priority: 0,
                        last_evicted_from: None,
                        recent_evicted_from: Vec::new(),
                    },
                );
            }
        }
        // 跑 1 tick。根治后：绝不该挑「moved-idle」(它搬过且搬后没活动)，
        // 该改挑某个 fresh-sleep(从没搬过、可正当散堆)。
        let moved = m.rebalance_tick();
        assert_eq!(moved, 1, "源过载应疏散 1 个(挑可搬的 fresh-sleep，不是 moved-idle)");
        let aff = m.affinity.lock();
        assert_eq!(
            aff.get("moved-idle").unwrap().credential_id,
            1,
            "churn 根治：搬过且搬后无真实活动的最老睡眠会话不该被再次搬动(应稳在 #1)"
        );
    }

    // ②″ churn 根治不误伤：会话被搬后【真的产生了活动】(last_seen 刷新到晚于 last_switch_at)，
    //    若它所在号又过载，仍应允许被再次疏散——证明根治只掐「死睡眠 churn」、不冻结真实负载迁移。
    #[test]
    fn test_scheduler_active_session_still_movable_after_move() {
        let m = scheduler_manager();
        let now = Utc::now();
        {
            let mut aff = m.affinity.lock();
            // 在 #1 放一个「搬过、但搬后又真活动过」的会话：last_switch_at=10s前、last_seen=1s前(晚于切号)。
            aff.insert(
                "moved-then-active".to_string(),
                AffinityBinding {
                    credential_id: 1,
                    bound_at: now - Duration::seconds(300),
                    last_seen: now - Duration::seconds(1), // 搬后又真干活了
                    last_switch_at: Some(now - Duration::seconds(10)),
                    last_switch_was_overflow: false,
                    priority: 0,
                    last_evicted_from: None,
                    recent_evicted_from: Vec::new(),
                },
            );
            // 再堆 4 个睡眠会话到 #1 凑出 bound_gap≥4，使 #1 成疏散源。
            for i in 0..4 {
                aff.insert(
                    format!("sleep-{i}"),
                    AffinityBinding {
                        credential_id: 1,
                        bound_at: now - Duration::seconds(120),
                        last_seen: now - Duration::seconds(120),
                        last_switch_at: None,
                        last_switch_was_overflow: false,
                        priority: 0,
                        last_evicted_from: None,
                        recent_evicted_from: Vec::new(),
                    },
                );
            }
        }
        // 至少应能疏散(不被「搬后无活动」门挡住的有：4 个未搬睡眠 + 这个搬后有活动的都可搬)。
        let moved = m.rebalance_tick();
        assert_eq!(moved, 1, "源过载时仍应疏散 1 个(根治不冻结真实可搬会话)");
    }

    // ②⁗ select-time「单槽 last_evicted_from 挡不住 ≥3 号环」根因证明(确定性,非 false-green)。
    //    owner live 日志实测:同一会话 511 次切号、走遍 9 号、80 次 A→B→C→A 三号环。机制=select-time
    //    每请求把 rebalance_target_excl 的 exclude_evicted 只设为「上一次来源」(单槽 last_evicted_from),
    //    9 号下长环每跳 target≠单槽值 → 全放行。本测试用 5 号 + 模拟「select-time 链式调用只排除上一跳」
    //    复现这个环:源永远是「会话数最多」的号,每跳只排除上一个来源 → 必然 A→B→C→D→E→A 绕环。
    //    断言:6 跳内出现「回到已访问过的号」(环),证明单槽不够;修复(多跳环形记忆)落地后此测试该改成断言「不绕环」。
    #[test]
    fn test_select_time_multihop_evict_history_breaks_ring() {
        // 5 号 manager(纯靠 token 数撑起 available pool)。
        let mut config = Config::default();
        config.adaptive_limit.multi_account.enabled = true;
        config.adaptive_limit.multi_account.rebalance_min_gap = 1; // 会话数差≥1 即可迁(便于确定性)
        let m = MultiTokenManager::new(
            config,
            vec![
                grouped_cred("t1", &[]),
                grouped_cred("t2", &[]),
                grouped_cred("t3", &[]),
                grouped_cred("t4", &[]),
                grouped_cred("t5", &[]),
            ],
            None,
            None,
            false,
        )
        .unwrap();
        let ma = &m.config.adaptive_limit.multi_account;
        let pool = m.available_credentials(None, None);
        assert!(pool.len() >= 5, "需要 5 号 pool 才能演示 ≥3 号环");
        // 模拟 select-time 每请求链式搬迁:cur 永远是「会话数最多」的过载源(每跳把全部会话塞到 cur),
        // 把「来源号」按修复后的环形历史(push_recent_evicted, cap=pool_len-1)累积、整段传给
        // rebalance_target_excl 当 exclude——这正是修复后 select-time 走的路。
        // 根治前传的是单槽(只排上一跳)→ 会绕环;根治后传整段历史 → 走遍号后无处可去即停,绝不绕回。
        let empty = std::collections::HashSet::new();
        let cap = pool.len().saturating_sub(1);
        let mut path = vec![1u64];
        let mut history: Vec<u64> = Vec::new(); // = 会话的 recent_evicted_from
        for _ in 0..8 {
            let cur = *path.last().unwrap();
            // 让 cur 成为「会话数最多」源:全部会话塞 cur(每跳重建 affinity)。
            {
                let mut aff = m.affinity.lock();
                aff.clear();
                for k in 0..3 {
                    aff.insert(
                        format!("filler-{cur}-{k}"),
                        AffinityBinding {
                            credential_id: cur,
                            bound_at: Utc::now(),
                            last_seen: Utc::now(),
                            last_switch_at: None,
                            last_switch_was_overflow: false,
                            priority: 0,
                            last_evicted_from: history.last().copied(),
                            recent_evicted_from: history.clone(),
                        },
                    );
                }
            }
            match m.rebalance_target_excl(&pool, cur, ma, &history, &empty) {
                Some((tgt, _)) => {
                    path.push(tgt);
                    // 落定:把来源 cur 压进环形历史(同 push_recent_evicted 逻辑:去重 + cap)。
                    history.retain(|&x| x != cur);
                    history.push(cur);
                    let c = cap.max(1);
                    while history.len() > c {
                        history.remove(0);
                    }
                }
                None => break, // 走遍号、无处可去 → 停(=环被打断,正是根治目标)
            }
        }
        // 检测环:path 里是否出现「回到先前访问过的号」。
        let mut seen = std::collections::HashSet::new();
        let mut ring_at = None;
        for (i, &id) in path.iter().enumerate() {
            if !seen.insert(id) {
                ring_at = Some(i);
                break;
            }
        }
        // 根治断言:传整段环形历史后,轨迹绝不回到任何已访问号(环被打断)。
        // 没有环 = ring_at == None。根治前(单槽)此处会是 Some(...)。
        assert!(
            ring_at.is_none(),
            "churn 根治:多跳环形历史应打断 ≥3 号环,但轨迹 {path:?} 仍回到了已访问号(环没断)"
        );
        // 旁证:确实走了几跳(不是 0 跳就停=没在测真东西),且最终因「无处可去」收敛停下。
        assert!(path.len() >= 3, "应至少搬几跳才停(轨迹 {path:?})");
        assert!(
            path.len() <= pool.len(),
            "走遍号后应停,不该超过号数(轨迹 {path:?} = 还在绕)"
        );
    }

    // ③ Pin 凌驾一切：被 pin 的会话即便在过载号上，也不被巡检搬走。
    #[test]
    fn test_scheduler_never_moves_pinned_session() {
        let m = scheduler_manager();
        // #1 绑 5 个睡眠会话，其中 "pinned-one" 被 pin 到 #1。
        for i in 0..4 {
            insert_binding(&m, &format!("sleep-{i}"), 1, 300); // 这 4 个更老 → 正常会先被选
        }
        insert_binding(&m, "pinned-one", 1, 999); // 最老，正常最先被搬
        m.pin_session("pinned-one", 1);
        // 连续巡检多轮，pinned-one 永远不该离开 #1。
        for _ in 0..5 {
            m.rebalance_tick();
        }
        let aff = m.affinity.lock();
        let b = aff.get("pinned-one").unwrap();
        assert_eq!(b.credential_id, 1, "Pin 凌驾一切：被 pin 的会话不被巡检搬走");
    }

    // ===== 优先级独享 exclusive_tick 测试 =====

    // ④ 高优先 active 会话不在理想号 → 迁到理想号（独享获取）。
    #[test]
    fn test_exclusive_high_priority_acquires_ideal_account() {
        let m = scheduler_manager();
        // 高优先会话现绑 #1（active=刚活动）；理想号默认按 safe_rps_hi(均0)→rpm 低→id 小，#1 已是其一。
        // 先把高优先放 #3，制造「不在理想号」。给 #1/#2 都不动(rpm 0)，理想号=最空+id小=#1。
        insert_binding_prio(&m, "vip", 3, 0, 5); // active, priority 5, 现在 #3
        let moved = m.exclusive_tick();
        assert_eq!(moved, 1, "高优先 active 会话应被迁到理想号");
        let aff = m.affinity.lock();
        let b = aff.get("vip").unwrap();
        assert_ne!(b.credential_id, 3, "应离开非理想号 #3");
    }

    // ⑤ 高优先 sleeping（空闲超 borrow 阈值）→ 不赶低优先（借号给普通会话、不浪费全局吞吐）。
    #[test]
    fn test_exclusive_sleeping_does_not_evict() {
        let m = scheduler_manager();
        // 高优先会话睡了很久（idle 大于 exclusive_borrow_idle_secs 默认 300），且已在理想号 #1。
        insert_binding_prio(&m, "vip-asleep", 1, 9999, 5);
        // #1 上有个普通活跃 squatter。
        insert_binding_prio(&m, "squatter", 1, 0, 0);
        let moved = m.exclusive_tick();
        assert_eq!(moved, 0, "高优先睡着时不赶低优先（借号）");
        let aff = m.affinity.lock();
        assert_eq!(aff.get("squatter").unwrap().credential_id, 1, "睡着期间 squatter 不被赶");
    }

    // ⑥ Pin 凌驾优先级：被 pin 的会话不参与独享调度、其号视为已占，高优先避开它。
    #[test]
    fn test_exclusive_pin_overrides_priority() {
        let m = scheduler_manager();
        // #1 被一个 pin 会话占住。
        insert_binding(&m, "pinned", 1, 0);
        m.pin_session("pinned", 1);
        // 高优先 active 会话在 #2，理想号本会挑 #1（id 小），但 #1 被 pin 占 → 应避开、不抢 #1。
        insert_binding_prio(&m, "vip", 2, 0, 5);
        for _ in 0..3 {
            m.exclusive_tick();
        }
        let aff = m.affinity.lock();
        // pin 会话纹丝不动在 #1；vip 绝不会被放到 #1（被 pin 占）。
        assert_eq!(aff.get("pinned").unwrap().credential_id, 1, "Pin 会话不被独享调度搬动");
        assert_ne!(aff.get("vip").unwrap().credential_id, 1, "高优先避开被 pin 占的号");
    }

    // ⑦ 独享号不够富余 → 赶走低优先 squatter（用超高 headroom_ratio 强制「永远不够富余」触发驱逐）。
    #[test]
    fn test_exclusive_evicts_low_priority_when_not_enough_headroom() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.enabled = true;
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        // ratio=2.0：headroom_ratio 最大才 1.0，永远 ≤ 2.0 → 视为"不够富余" → 必赶 squatter。
        config.adaptive_limit.multi_account.exclusive_headroom_ratio = 2.0;
        let m = MultiTokenManager::new(
            config,
            vec![grouped_cred("t1", &[]), grouped_cred("t2", &[]), grouped_cred("t3", &[])],
            None,
            None,
            false,
        )
        .unwrap();
        // 高优先 active 已在理想号 #1；#1 上有个活跃普通 squatter。
        insert_binding_prio(&m, "vip", 1, 0, 5);
        insert_binding_prio(&m, "squatter", 1, 0, 0);
        let moved = m.exclusive_tick();
        assert_eq!(moved, 1, "不够富余应赶走 squatter");
        let aff = m.affinity.lock();
        assert_eq!(aff.get("vip").unwrap().credential_id, 1, "高优先留在理想号 #1");
        assert_ne!(aff.get("squatter").unwrap().credential_id, 1, "低优先 squatter 被赶离 #1");
    }

    // ⑧ 反乒乓（Reviewer 向量6）：温和均衡 rebalance_tick 绝不搬走高优先会话——
    //    否则会把 exclusive 刚安排好的独享会话又搬走，两机制打架。
    #[test]
    fn test_rebalance_never_moves_high_priority_session() {
        let m = scheduler_manager();
        // #1 堆一个高优先睡眠会话 + 5 个普通睡眠会话（bound_gap 会想疏散 #1）。
        insert_binding_prio(&m, "vip-sleep", 1, 9999, 7); // 最老 + 高优先 → 正常最先被选为 victim
        for i in 0..5 {
            insert_binding(&m, &format!("plain-{i}"), 1, 120);
        }
        // 连续多轮温和均衡（exclusive_tick 对睡眠高优先不动作 → 走到 rebalance）。
        for _ in 0..8 {
            m.rebalance_tick();
        }
        let aff = m.affinity.lock();
        // 高优先会话即便最老、在过载号上，也绝不被温和均衡搬走。
        assert_eq!(
            aff.get("vip-sleep").unwrap().credential_id,
            1,
            "温和均衡绝不搬走高优先会话（防与 exclusive 打架）"
        );
    }

    // ⑨ Reviewer Finding #1：队头阻塞活锁——最忙的源号没有可搬会话（全 pin/全高优先）时，
    //    巡检应回退到次忙的源号继续疏散，而不是 return 0 白跑。
    #[test]
    fn test_scheduler_falls_back_to_next_source_when_busiest_has_no_victim() {
        let m = scheduler_manager();
        // #1（将成最忙源）：只挂 1 个高优先睡眠 + 1 个 pin 会话 → 无 priority-0 可搬。
        insert_binding_prio(&m, "vip-1", 1, 9999, 7);
        insert_binding(&m, "pinned-1", 1, 9999);
        m.pin_session("pinned-1", 1);
        // 制造 #1 rpm 最高（最忙）。
        for _ in 0..30 {
            m.note_request(1);
        }
        // #2（次忙源）：5 个普通睡眠会话——这些才是该疏散的对象。
        for i in 0..5 {
            insert_binding(&m, &format!("plain2-{i}"), 2, 120);
        }
        for _ in 0..10 {
            m.note_request(2);
        }
        let moved = m.rebalance_tick();
        assert_eq!(moved, 1, "最忙源无可搬会话时应回退到次忙源疏散（修队头阻塞活锁）");
        // 疏散的应是 #2 的某个普通会话（#1 的高优先/pin 都不该动）。
        let aff = m.affinity.lock();
        assert_eq!(aff.get("vip-1").unwrap().credential_id, 1, "#1 高优先不动");
        assert_eq!(aff.get("pinned-1").unwrap().credential_id, 1, "#1 pin 不动");
        let on2 = aff.values().filter(|b| b.credential_id == 2).count();
        assert_eq!(on2, 4, "应从次忙源 #2 疏散 1 个普通会话");
    }

    // ⑩ Reviewer Finding #2：温和均衡的目标号必须排除「独享归属号」，
    //    否则会把普通 squatter 搬进独享号引发反向 churn。
    #[test]
    fn test_rebalance_excludes_exclusive_owned_as_target() {
        let m = scheduler_manager();
        // #1 = 高优先 H 的独享家（H active），#1 此刻最空（rpm 0）。
        insert_binding_prio(&m, "vip-home", 1, 0, 7);
        // #2 很忙、挂普通会话 S → 温和均衡想把 S 迁到最空号；但最空号 #1 是独享家、应被排除，迁到 #3。
        insert_binding(&m, "squatter-s", 2, 0);
        for _ in 0..20 {
            m.note_request(2);
        }
        // 连续巡检：S 可能被疏散，但绝不能落到独享家 #1。
        for _ in 0..6 {
            m.rebalance_tick();
        }
        let aff = m.affinity.lock();
        assert_ne!(
            aff.get("squatter-s").unwrap().credential_id,
            1,
            "温和均衡绝不把普通会话搬进独享归属号 #1（防反向 churn）"
        );
    }

    // ⑪ Reviewer Finding #4：exclusive_tick 独立于 rebalance 信号——四个 gap 全关时独享仍生效。
    #[test]
    fn test_exclusive_runs_even_when_rebalance_signals_all_off() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.enabled = true;
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        config.adaptive_limit.multi_account.reclaim_debounce_secs = 0;
        // 四个 rebalance 信号全关（owner「只要独享、不要被动均摊」）。
        config.adaptive_limit.multi_account.rebalance_rpm_gap = 0.0;
        config.adaptive_limit.multi_account.rebalance_utilization_gap = 0.0;
        config.adaptive_limit.multi_account.rebalance_bound_gap = 0;
        config.adaptive_limit.multi_account.rebalance_min_gap = 0;
        let m = MultiTokenManager::new(
            config,
            vec![grouped_cred("t1", &[]), grouped_cred("t2", &[]), grouped_cred("t3", &[])],
            None,
            None,
            false,
        )
        .unwrap();
        // 高优先 active 在非理想号 #3 → 即便 rebalance 全关，rebalance_tick 也应通过 exclusive 把它迁走。
        insert_binding_prio(&m, "vip", 3, 0, 5);
        let moved = m.rebalance_tick();
        assert_eq!(moved, 1, "rebalance 信号全关时，独享仍应通过 exclusive_tick 生效");
        let aff = m.affinity.lock();
        assert_ne!(aff.get("vip").unwrap().credential_id, 3, "高优先应被独享调度迁离非理想号");
    }

    // ⑫ 借号语义（owner 核心规则 + 自查发现的洞）：高优先睡>borrow_idle 时，它独享的号
    //    应可被温和均衡借给普通会话（exclusive_owned 只算 active 高优先，睡着的不护着）。
    #[test]
    fn test_sleeping_exclusive_account_is_lendable() {
        let m = scheduler_manager();
        // #1 = 高优先 H 的独享家，但 H 睡了很久（> exclusive_borrow_idle_secs 默认 300）。
        insert_binding_prio(&m, "vip-asleep", 1, 9999, 7);
        // exclusive_owned_accounts 此刻不该包含 #1（H 睡着 → 可借出）。
        let owned = m.exclusive_owned_accounts();
        assert!(
            !owned.contains(&1),
            "睡着的高优先独享号应可借出（不在 exclusive_owned 集合里），owned={owned:?}"
        );
        // 对照：H 若 active，#1 应被护住。
        insert_binding_prio(&m, "vip-awake", 2, 0, 7);
        let owned2 = m.exclusive_owned_accounts();
        assert!(owned2.contains(&2), "active 高优先独享号应被护住（在 exclusive_owned 集合里）");
    }

    // ⑬ 持久化 round-trip（Reviewer 额外项 A）：last_evicted_from 落盘再读能正确还原；
    //    且老格式 JSON（无此字段）能 serde default 反序列化、不崩。
    #[test]
    fn test_affinity_binding_serde_roundtrip_and_old_format() {
        let now = Utc::now();
        // 1) 带 last_evicted_from 的 round-trip。
        let b = AffinityBinding {
            credential_id: 7,
            bound_at: now,
            last_seen: now,
            last_switch_at: Some(now),
            last_switch_was_overflow: false,
            priority: 3,
            last_evicted_from: Some(2),
            recent_evicted_from: vec![2],
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: AffinityBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.last_evicted_from, Some(2), "last_evicted_from 应 round-trip 还原");
        assert_eq!(back.credential_id, 7);
        // 2) 老格式（无 last_evicted_from / last_switch_* 字段）应 default 反序列化为 None/false。
        let old = r#"{"credential_id":5,"bound_at":"2026-06-23T00:00:00Z","last_seen":"2026-06-23T00:00:00Z","priority":0}"#;
        let parsed: AffinityBinding = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.credential_id, 5);
        assert_eq!(parsed.last_evicted_from, None, "老格式无此字段应 default None");
        assert!(!parsed.last_switch_was_overflow);
    }

    // ⑭ 第二轮 Reviewer 反例2 修复：原号 OPEN 强制切号后，last_evicted_from 应被**清除**（非 set），
    //    这样原号恢复后高优先能夺回最优主号，不被防回弹误挡 60s。
    #[tokio::test]
    async fn test_open_forced_switch_clears_evicted_from() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.enabled = true;
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        let m = MultiTokenManager::new(
            config,
            vec![grouped_cred("t1", &[]), grouped_cred("t2", &[])],
            None,
            None,
            false,
        )
        .unwrap();
        // 会话先绑 #1。
        let c = m.acquire_context(None, None, Some("sess-open")).await.unwrap();
        let bound = c.id;
        let other = if bound == 1 { 2 } else { 1 };
        // 把 bound 号打 OPEN（熔断）。
        {
            let lim = m.limiters().for_scope(&ThrottleScope::UserCredential(bound));
            for _ in 0..10 {
                lim.on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
                    .await;
            }
        }
        // 🔒 加硬（第三轮 Reviewer：test 半假绿）：先把 last_evicted_from 置 Some(99)，
        // 这样断言"变 None"才真证明"清除生效"，而不是"初值恰好是 None 恒过"。
        {
            let mut aff = m.affinity.lock();
            if let Some(b) = aff.get_mut("sess-open") {
                b.last_evicted_from = Some(99);
            }
        }
        // 再选号 → 原号 OPEN → 强制切到 other。
        let pick = m.select_with_affinity(None, None, Some("sess-open")).unwrap();
        assert_eq!(pick.0, other, "原号 OPEN 应强制切到另一个号");
        // 关键断言：强制切号后 last_evicted_from 应是 None（被迫逃，不防回弹），不是 Some(bound)。
        let b = m.affinity.lock().get("sess-open").cloned().unwrap();
        assert_eq!(
            b.last_evicted_from, None,
            "OPEN 强制切号应清除 last_evicted_from（先置 Some(99) → 切后必须变 None，证明清除真生效）"
        );
    }

    // ⑮ 第二轮 Reviewer 反例1 修复：live 请求路径下，priority=0 会话被温和均衡时，
    //    目标号必须排除「active 高优先独享号」——不能把普通会话搬进独享号（反向 churn）。
    #[tokio::test]
    async fn test_live_rebalance_excludes_active_exclusive_account() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.enabled = true;
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        // 让温和均衡易触发：rpm gap 设小。
        config.adaptive_limit.multi_account.rebalance_rpm_gap = 1.0;
        let m = MultiTokenManager::new(
            config,
            vec![grouped_cred("t1", &[]), grouped_cred("t2", &[]), grouped_cred("t3", &[])],
            None,
            None,
            false,
        )
        .unwrap();
        // #1 = active 高优先 H 的独享家（exclusive_owned 应含 #1）。
        insert_binding_prio(&m, "vip-active", 1, 0, 7);
        // #2 挂普通会话 S，#2 制造高 rpm 触发均衡。
        insert_binding(&m, "plain-s", 2, 0);
        for _ in 0..20 {
            m.note_request(2);
        }
        // 反复 live 选号 S（走 select_with_affinity 的均衡分支）。
        for _ in 0..8 {
            let _ = m.select_with_affinity(None, None, Some("plain-s"));
        }
        // S 即便被均衡走，也绝不能落到 active 独享家 #1。
        let b = m.affinity.lock().get("plain-s").cloned().unwrap();
        assert_ne!(
            b.credential_id, 1,
            "live 路径：普通会话绝不被均衡进 active 高优先独享号 #1（修反向 churn）"
        );
    }

    // ⑯ 第三轮 Reviewer Finding 1：cd 强制切号路径（最高频）也绝不能把普通会话甩进 active 独享号。
    //    根因修法=pick_pool 软排除独享号，三条路（cd强切/overflow/均衡）共用，这里专测 cd 强切那条。
    #[tokio::test]
    async fn test_cd_force_switch_excludes_active_exclusive_account() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.enabled = true;
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        config.adaptive_limit.multi_account.switch_threshold_secs = 1; // 冷却 >1s 即触发 cd 强切
        config.adaptive_limit.user_cooldown_base_secs = 10; // 撞一次冷却 ~10s（>1s 阈值，但不 OPEN 熔断）
        let m = MultiTokenManager::new(
            config,
            vec![grouped_cred("t1", &[]), grouped_cred("t2", &[]), grouped_cred("t3", &[])],
            None,
            None,
            false,
        )
        .unwrap();
        // #1 = active 高优先 H 独享家（rpm 最低，cd 强切若不排除会优先选它）。
        insert_binding_prio(&m, "vip-active", 1, 0, 7);
        // 普通会话 S 绑 #2；**单次** throttle 把 #2 冷却推过阈值但**不 OPEN 熔断**（关键：
        // 撞 10 次会 OPEN→走 OPEN 强切分支，不是 cd 强切；单次 + cooldown_base=10s 才真撞 cd 强切，
        // 修第四轮 Reviewer Finding B 假绿=之前测错了分支）。
        insert_binding(&m, "plain-s", 2, 0);
        m.limiters()
            .for_scope(&ThrottleScope::UserCredential(2))
            .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
            .await;
        // 前置断言：#2 必须仍 Healthy（没 OPEN），否则就不是在测 cd 强切分支。
        assert!(!m.is_account_open(2), "前置：#2 应仍 Healthy（单次 throttle 不 OPEN），才是真测 cd 强切");
        // S 触发 cd 强切——绝不能落到 active 独享家 #1，应去 #3。
        let pick = m.select_with_affinity(None, None, Some("plain-s")).unwrap();
        assert_ne!(pick.0, 1, "cd 强切：普通会话绝不被甩进 active 高优先独享号 #1");
        assert_ne!(pick.0, 2, "cd 强切应离开卡死的原号 #2");
    }

    // ⑰ 第五轮 Reviewer 承重行覆盖：H_ne={b} corner——唯一健康非独享号就是会话自己的冷却原号时，
    //    cd 强切应**黏回自己的冷却原号(Stick)**，而绝不被兜底链 `lowest_load(all_pool,Some(b))` 甩进独享号。
    //    这条直接打 token_manager.rs cd 强切兜底改动行（2号拓扑：#1 独享 active + #2 原号冷却）。
    #[tokio::test]
    async fn test_cd_force_switch_sticks_origin_when_only_healthy_nonexcl_is_self() {
        let mut config = Config::default();
        config.adaptive_limit.multi_account.enabled = true;
        config.adaptive_limit.multi_account.switch_debounce_secs = 0;
        config.adaptive_limit.multi_account.switch_threshold_secs = 1; // cd>1s 触发 cd 强切
        config.adaptive_limit.user_cooldown_base_secs = 10; // 撞一次冷却 ~10s（>阈值但不 OPEN）
        // 只 2 个号：#1 给高优先独享、#2 给普通会话原号。
        let m = MultiTokenManager::new(
            config,
            vec![grouped_cred("t1", &[]), grouped_cred("t2", &[])],
            None,
            None,
            false,
        )
        .unwrap();
        // #1 = active 高优先独享家（→ owned_excl 含 #1 → H_ne 把 #1 排掉）。
        insert_binding_prio(&m, "vip-active", 1, 0, 7);
        // 普通会话 S 绑 #2，单次 throttle 让 #2 冷却>阈值但仍 Healthy。
        insert_binding(&m, "plain-s", 2, 0);
        m.limiters()
            .for_scope(&ThrottleScope::UserCredential(2))
            .on_throttle(crate::kiro::rate_limiter::ThrottleReason::UserRate, None, 0)
            .await;
        assert!(!m.is_account_open(2), "前置：#2 仍 Healthy（真测 cd 强切兜底）");
        // H_ne = {健康且非独享} = {#2}（#1 被独享排除），但 cd 强切 exclude #2 自己 → 兜底链都空
        // → 应 Stick 黏回 #2，绝不甩进独享家 #1。
        let pick = m.select_with_affinity(None, None, Some("plain-s")).unwrap();
        assert_eq!(
            pick.0, 2,
            "H_ne={{b}} corner：唯一健康非独享号是自己 → cd 强切应黏回 #2，绝不甩进独享号 #1"
        );
    }
}

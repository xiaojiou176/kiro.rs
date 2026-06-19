use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    Rustls,
    NativeTls,
}

impl Default for TlsBackend {
    fn default() -> Self {
        Self::Rustls
    }
}

/// KNA 应用配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_region")]
    pub region: String,

    /// Auth Region（用于 Token 刷新），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_region: Option<String>,

    /// API Region（用于 API 请求），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_region: Option<String>,

    #[serde(default = "default_kiro_version")]
    pub kiro_version: String,

    #[serde(default)]
    pub machine_id: Option<String>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default = "default_system_version")]
    pub system_version: String,

    #[serde(default = "default_node_version")]
    pub node_version: String,

    #[serde(default = "default_tls_backend")]
    pub tls_backend: TlsBackend,

    /// 外部 count_tokens API 地址（可选）
    #[serde(default)]
    pub count_tokens_api_url: Option<String>,

    /// count_tokens API 密钥（可选）
    #[serde(default)]
    pub count_tokens_api_key: Option<String>,

    /// count_tokens API 认证类型（可选，"x-api-key" 或 "bearer"，默认 "x-api-key"）
    #[serde(default = "default_count_tokens_auth_type")]
    pub count_tokens_auth_type: String,

    /// HTTP 代理地址（可选）
    /// 支持格式: http://host:port, https://host:port, socks5://host:port
    #[serde(default)]
    pub proxy_url: Option<String>,

    /// 代理认证用户名（可选）
    #[serde(default)]
    pub proxy_username: Option<String>,

    /// 代理认证密码（可选）
    #[serde(default)]
    pub proxy_password: Option<String>,

    /// Admin API 密钥（可选，启用 Admin API 功能）
    #[serde(default)]
    pub admin_api_key: Option<String>,

    /// 上一次成功更新前正在运行的版本号，用于在前端展示「回退到 vX.Y.Z」按钮。
    /// 实际回退动作通过 `<exe>.backup` 文件完成，无需访问网络。
    #[serde(default)]
    pub update_previous_version: Option<String>,

    /// GitHub Personal Access Token（可选）。设置后 GitHub Releases 接口会带上
    /// `Authorization: Bearer <token>`，把限流从匿名 60/h 提到认证 5000/h。
    /// 仅需 `public_repo` 读取权限即可。
    #[serde(default)]
    pub github_token: Option<String>,

    /// 上一次成功完成在线更新的时间（RFC3339）。前端用于显示「上次更新于 …」。
    #[serde(default)]
    pub update_last_applied_at: Option<String>,

    /// 是否启用无人值守自动更新。开启后服务会在每天的 `update_auto_apply_time`
    /// 时刻检查 GitHub Releases，发现新版本即自动下载二进制并替换重启。
    #[serde(default)]
    pub update_auto_apply: bool,

    /// 自动更新的每日触发时间（本地时区，`HH:MM` 24 小时制）。
    /// 默认 03:00 凌晨执行，对在线服务影响最小。
    #[serde(default = "default_update_auto_apply_time")]
    pub update_auto_apply_time: String,

    /// 负载均衡模式（"priority" 或 "balanced"）
    #[serde(default = "default_load_balancing_mode")]
    pub load_balancing_mode: String,

    /// 账号级 429 风控触发时是否对当前凭据进入冷却并故障转移（默认 true）。
    ///
    /// 关闭后：429 + suspicious activity 仍按普通瞬态错误重试，不切换凭据。
    /// 开启后：识别到 suspicious activity 字符串时，把当前凭据冷却 `account_throttle_cooldown_secs` 秒，
    /// 立即切换到下一个可用凭据。
    #[serde(default = "default_account_throttle_failover")]
    pub account_throttle_failover: bool,

    /// 账号级风控冷却时长（秒，默认 1800 = 30 分钟）。
    #[serde(default = "default_account_throttle_cooldown_secs")]
    pub account_throttle_cooldown_secs: u64,

    /// 是否开启非流式响应的 thinking 块提取（默认 true）
    ///
    /// 启用后，非流式响应中的 `<thinking>...</thinking>` 标签会被解析为
    /// 独立的 `{"type": "thinking", ...}` 内容块,与流式响应行为一致。
    #[serde(default = "default_extract_thinking")]
    pub extract_thinking: bool,

    /// 默认端点名称（凭据未显式指定 endpoint 时使用，默认 "ide"）
    #[serde(default = "default_endpoint")]
    pub default_endpoint: String,

    /// 是否启用请求链路追踪（写 traces.db）。默认 true。
    ///
    /// 关闭后：不再写入 trace 记录、不走 TraceSink，但 `GET /api/admin/traces`
    /// 仍可查询历史已存记录。适合隐私敏感或磁盘紧张的场景。
    #[serde(default = "default_trace_enabled")]
    pub trace_enabled: bool,

    /// 请求链路追踪记录保留天数（默认 7）。后台任务每天清理超期记录。
    #[serde(default = "default_trace_retention_days")]
    pub trace_retention_days: u32,

    /// 请求用量日志（usage_log.*.jsonl + 聚合桶）保留天数（默认 31）。
    #[serde(default = "default_usage_log_retention_days")]
    pub usage_log_retention_days: u32,

    /// 端点特定的配置
    ///
    /// 键为端点名（如 "ide" / "cli"），值为该端点自由定义的参数对象。
    /// 未在此表出现的端点沿用实现内置默认值。
    #[serde(default)]
    pub endpoints: HashMap<String, serde_json::Value>,

    /// 自适应限速配置（解决 429）。缺省时使用保守默认值（见 [`AdaptiveLimitConfig`]）。
    ///
    /// 设计：user-scope 发送前令牌桶闸门 + AIMD 自适应调速 + 全局 429 冷却 + Fail Aloud。
    /// 详见 `docs/superpowers/plans/2026-06-19-kiro-adaptive-ratelimit.md`。
    #[serde(default)]
    pub adaptive_limit: AdaptiveLimitConfig,

    /// 配置文件路径（运行时元数据，不写入 JSON）
    #[serde(skip)]
    config_path: Option<PathBuf>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_kiro_version() -> String {
    "2.3.0".to_string()
}

fn default_system_version() -> String {
    "macos".to_string()
}

fn default_node_version() -> String {
    "22.22.0".to_string()
}

fn default_count_tokens_auth_type() -> String {
    "x-api-key".to_string()
}

fn default_tls_backend() -> TlsBackend {
    TlsBackend::Rustls
}

fn default_load_balancing_mode() -> String {
    "priority".to_string()
}

fn default_account_throttle_failover() -> bool {
    true
}

fn default_account_throttle_cooldown_secs() -> u64 {
    30 * 60
}

fn default_update_auto_apply_time() -> String {
    "03:00".to_string()
}

fn default_extract_thinking() -> bool {
    true
}

fn default_endpoint() -> String {
    crate::kiro::endpoint::ide::IDE_ENDPOINT_NAME.to_string()
}

fn default_trace_enabled() -> bool {
    true
}

fn default_trace_retention_days() -> u32 {
    7
}

fn default_usage_log_retention_days() -> u32 {
    31
}

// ===== 自适应限速配置（解决 429） =====

/// Fail Aloud 三档阈值子配置。只报警不熔断；🔴 档=本地返回 429 ≠ 停服。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailAloudConfig {
    /// 🟡 Soft Warn：limiter 速率低于此值（rps）持续 `soft_warn_duration_secs` → WARN 日志。
    #[serde(default = "default_soft_warn_rate_rps")]
    pub soft_warn_rate_rps: f64,
    /// 🟡 Soft Warn 持续时长阈值（秒）。
    #[serde(default = "default_soft_warn_duration_secs")]
    pub soft_warn_duration_secs: u64,
    /// 🟠 Degraded：429 率高于此值持续 `degraded_duration_secs` → 响应加 `X-Local-Throttled`。
    #[serde(default = "default_degraded_429_rate")]
    pub degraded_429_rate: f64,
    /// 🟠 Degraded 持续时长阈值（秒）。
    #[serde(default = "default_degraded_duration_secs")]
    pub degraded_duration_secs: u64,
}

impl Default for FailAloudConfig {
    fn default() -> Self {
        Self {
            soft_warn_rate_rps: default_soft_warn_rate_rps(),
            soft_warn_duration_secs: default_soft_warn_duration_secs(),
            degraded_429_rate: default_degraded_429_rate(),
            degraded_duration_secs: default_degraded_duration_secs(),
        }
    }
}

/// 多账号留口子配置。第一版默认关闭（单号优先，不靠多号硬分流）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiAccountConfig {
    /// 是否开启多账号并发分流。默认 false（Owner 红线：同机多号被 AWS 当“一人多开”全封）。
    #[serde(default)]
    pub enabled: bool,
}

impl Default for MultiAccountConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

/// 自适应限速主配置。全部带默认值，旧 config 无 `adaptiveLimit` 时零改动即保守默认。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdaptiveLimitConfig {
    /// 总开关。false 时 limiter 完全不介入，行为等同改造前。
    #[serde(default = "default_adaptive_enabled")]
    pub enabled: bool,
    /// 灰度：false=shadow（只计算决策不拦截）/ true=真拦截。
    #[serde(default)]
    pub enforce: bool,
    /// 灰度作用域："retry_only"（只拦 retry）/ "all"（初始+retry 全拦）。
    #[serde(default = "default_enforce_scope")]
    pub enforce_scope: String,
    /// 初始发送速率（rps）。低于实测安全值 1，避免冷启动撞墙。
    #[serde(default = "default_initial_rate_rps")]
    pub initial_rate_rps: f64,
    /// 最低速率（rps），防止退到 0 死锁。
    #[serde(default = "default_min_rate_rps")]
    pub min_rate_rps: f64,
    /// 最高速率（rps）。先不超过已知会高 429 的 2 rps。
    #[serde(default = "default_max_rate_rps")]
    pub max_rate_rps: f64,
    /// 令牌桶容量（突发）。实测 burst 很小，先禁止瞬时双发。
    #[serde(default = "default_burst")]
    pub burst: f64,
    /// 每个 scope 的最大在飞请求数。第一版 1（毫秒分析：在飞>1.5 升 429）。
    #[serde(default = "default_max_inflight_per_scope")]
    pub max_inflight_per_scope: usize,
    /// AIMD 加性增步长（rps）。
    #[serde(default = "default_additive_step_rps")]
    pub additive_step_rps: f64,
    /// 两次加速之间的最小间隔（秒）。
    #[serde(default = "default_increase_interval_secs")]
    pub increase_interval_secs: u64,
    /// 触发一次加速所需的累计成功数。
    #[serde(default = "default_successes_per_increase")]
    pub successes_per_increase: u64,
    /// 撞 429 时的乘性减速系数（rate *= beta）。
    #[serde(default = "default_beta_user")]
    pub beta_user: f64,
    /// 普通速率限流的基础冷却时长（秒）。
    #[serde(default = "default_user_cooldown_base_secs")]
    pub user_cooldown_base_secs: u64,
    /// 冷却时长封顶（秒）。
    #[serde(default = "default_cooldown_cap_secs")]
    pub cooldown_cap_secs: u64,
    /// Fail Aloud 🔴：acquire 排队预计超此值（秒）→ 本地返回 429，不再压队列。
    #[serde(default = "default_local_queue_timeout_secs")]
    pub local_queue_timeout_secs: u64,
    /// Fail Aloud 三档阈值。
    #[serde(default)]
    pub fail_aloud: FailAloudConfig,
    /// 是否信任上游 Retry-After 头。AWS 实证不返回此头，默认关；逻辑预留。
    #[serde(default)]
    pub respect_retry_after: bool,
    /// 多账号留口。默认关闭。
    #[serde(default)]
    pub multi_account: MultiAccountConfig,
}

impl Default for AdaptiveLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_adaptive_enabled(),
            enforce: false,
            enforce_scope: default_enforce_scope(),
            initial_rate_rps: default_initial_rate_rps(),
            min_rate_rps: default_min_rate_rps(),
            max_rate_rps: default_max_rate_rps(),
            burst: default_burst(),
            max_inflight_per_scope: default_max_inflight_per_scope(),
            additive_step_rps: default_additive_step_rps(),
            increase_interval_secs: default_increase_interval_secs(),
            successes_per_increase: default_successes_per_increase(),
            beta_user: default_beta_user(),
            user_cooldown_base_secs: default_user_cooldown_base_secs(),
            cooldown_cap_secs: default_cooldown_cap_secs(),
            local_queue_timeout_secs: default_local_queue_timeout_secs(),
            fail_aloud: FailAloudConfig::default(),
            respect_retry_after: false,
            multi_account: MultiAccountConfig::default(),
        }
    }
}

fn default_adaptive_enabled() -> bool {
    true
}
fn default_enforce_scope() -> String {
    "retry_only".to_string()
}
fn default_initial_rate_rps() -> f64 {
    0.8
}
fn default_min_rate_rps() -> f64 {
    0.1
}
fn default_max_rate_rps() -> f64 {
    2.0
}
fn default_burst() -> f64 {
    1.0
}
fn default_max_inflight_per_scope() -> usize {
    1
}
fn default_additive_step_rps() -> f64 {
    0.05
}
fn default_increase_interval_secs() -> u64 {
    30
}
fn default_successes_per_increase() -> u64 {
    20
}
fn default_beta_user() -> f64 {
    0.5
}
fn default_user_cooldown_base_secs() -> u64 {
    5
}
fn default_cooldown_cap_secs() -> u64 {
    120
}
fn default_local_queue_timeout_secs() -> u64 {
    90
}
fn default_soft_warn_rate_rps() -> f64 {
    0.3
}
fn default_soft_warn_duration_secs() -> u64 {
    180
}
fn default_degraded_429_rate() -> f64 {
    0.2
}
fn default_degraded_duration_secs() -> u64 {
    180
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            region: default_region(),
            auth_region: None,
            api_region: None,
            kiro_version: default_kiro_version(),
            machine_id: None,
            api_key: None,
            system_version: default_system_version(),
            node_version: default_node_version(),
            tls_backend: default_tls_backend(),
            count_tokens_api_url: None,
            count_tokens_api_key: None,
            count_tokens_auth_type: default_count_tokens_auth_type(),
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            admin_api_key: None,
            update_previous_version: None,
            github_token: None,
            update_last_applied_at: None,
            update_auto_apply: false,
            update_auto_apply_time: default_update_auto_apply_time(),
            load_balancing_mode: default_load_balancing_mode(),
            account_throttle_failover: default_account_throttle_failover(),
            account_throttle_cooldown_secs: default_account_throttle_cooldown_secs(),
            extract_thinking: default_extract_thinking(),
            default_endpoint: default_endpoint(),
            trace_enabled: default_trace_enabled(),
            trace_retention_days: default_trace_retention_days(),
            usage_log_retention_days: default_usage_log_retention_days(),
            endpoints: HashMap::new(),
            adaptive_limit: AdaptiveLimitConfig::default(),
            config_path: None,
        }
    }
}

impl Config {
    /// 获取默认配置文件路径
    pub fn default_config_path() -> &'static str {
        "config.json"
    }

    /// 获取有效的 Auth Region（用于 Token 刷新）
    /// 优先使用 auth_region，未配置时回退到 region
    pub fn effective_auth_region(&self) -> &str {
        self.auth_region.as_deref().unwrap_or(&self.region)
    }

    /// 获取有效的 API Region（用于 API 请求）
    /// 优先使用 api_region，未配置时回退到 region
    pub fn effective_api_region(&self) -> &str {
        self.api_region.as_deref().unwrap_or(&self.region)
    }

    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            // 配置文件不存在，返回默认配置
            let mut config = Self::default();
            config.config_path = Some(path.to_path_buf());
            return Ok(config);
        }

        let content = fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&content)?;
        config.config_path = Some(path.to_path_buf());

        // 用户手工把字符串字段清空（如 `"updateAutoApplyTime": ""`）时，serde 默认值不会
        // 介入；这里把"看起来像空"的关键字段回退到默认值，避免后续业务用到
        // 空字符串导致难以诊断的错误。
        if config.update_auto_apply_time.trim().is_empty() {
            config.update_auto_apply_time = default_update_auto_apply_time();
        }

        Ok(config)
    }

    /// 获取配置文件路径（如果有）
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// 将当前配置写回原始配置文件
    pub fn save(&self) -> anyhow::Result<()> {
        let path = self
            .config_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("配置文件路径未知，无法保存配置"))?;

        let content = serde_json::to_string_pretty(self).context("序列化配置失败")?;
        fs::write(path, content)
            .with_context(|| format!("写入配置文件失败: {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod adaptive_limit_tests {
    use super::*;

    #[test]
    fn adaptive_limit_defaults_are_conservative() {
        let c = AdaptiveLimitConfig::default();
        assert!(c.enabled, "默认应启用（但 enforce=false 走 shadow）");
        assert!(!c.enforce, "默认 shadow，不真拦截");
        assert_eq!(c.enforce_scope, "retry_only");
        assert_eq!(c.initial_rate_rps, 0.8);
        assert_eq!(c.min_rate_rps, 0.1);
        assert_eq!(c.max_rate_rps, 2.0);
        assert_eq!(c.burst, 1.0);
        assert_eq!(c.max_inflight_per_scope, 1, "第一版必须为 1");
        assert_eq!(c.beta_user, 0.5);
        assert_eq!(c.local_queue_timeout_secs, 90);
        assert!(!c.respect_retry_after, "AWS 不返回 Retry-After，默认关");
        assert!(!c.multi_account.enabled, "多号留口默认关");
    }

    #[test]
    fn config_without_adaptive_limit_uses_defaults() {
        // 旧 config（无 adaptiveLimit 字段）反序列化后应回落到保守默认。
        let json = r#"{"host":"127.0.0.1","port":8318}"#;
        let c: Config = serde_json::from_str(json).expect("应能反序列化旧 config");
        assert!(c.adaptive_limit.enabled);
        assert_eq!(c.adaptive_limit.max_inflight_per_scope, 1);
        assert!(!c.adaptive_limit.enforce);
    }

    #[test]
    fn fail_aloud_defaults() {
        let f = FailAloudConfig::default();
        assert_eq!(f.degraded_429_rate, 0.2);
        assert_eq!(f.soft_warn_rate_rps, 0.3);
    }
}

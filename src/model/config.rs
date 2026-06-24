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

    /// 是否将推理端点从 legacy `q.{region}.amazonaws.com` 切到现役
    /// `runtime.{region}.kiro.dev`。默认 false（保持旧行为，可灰度 / 回滚）。
    ///
    /// 实测（mitmproxy 抓包 + 真账 A/B）：runtime 端点限速更松（同号同负载 429 约 -30%），
    /// apikey 鉴权下仍免费（额度 0 消耗，计费看鉴权不看端点），且为现役 Kiro CLI
    /// （v2/v3、Social/apikey）实际使用的推理端点；legacy 已被官方标注为待弃用、只发遥测。
    #[serde(default = "default_runtime_endpoint")]
    pub runtime_endpoint: bool,

    /// Kiro CLI 客户端版本号,用于 CLI 端点 UA 的 `md/appVersion-`。
    /// 默认对齐当前真实 CLI 版本(抓包实测);官方 CLI 升级后可在 config 里直接 bump,
    /// 无需重编译,避免指纹再次过时。
    #[serde(default = "default_cli_version")]
    pub cli_version: String,

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

fn default_runtime_endpoint() -> bool {
    // 默认开：runtime 端点实测 429 更低且 apikey 仍免费，是现役 Kiro CLI 的真实推理端点。
    // 设为默认 true 后，万一 config 丢失/重置，回退到「好状态」(runtime + 新指纹) 而非
    // legacy 端点的 429 风暴。要回 legacy 显式在 config 写 runtimeEndpoint=false。
    true
}

fn default_cli_version() -> String {
    "2.8.1".to_string()
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
    /// session affinity：黏定的号若处于冷却且剩余 > 此秒数，则切换到负载最低的号（不再黏回旧号）。
    /// 默认 15 秒（实测正常 429 冷却仅几秒，15s 只在真卡很久时触发切号，避免反复横跳）。
    #[serde(default = "default_switch_threshold_secs")]
    pub switch_threshold_secs: u64,
    /// 会话绑定的存活时长（秒）。超过此时长未活动则释放绑定。默认 3600（1 小时）。
    #[serde(default = "default_affinity_ttl_secs")]
    pub affinity_ttl_secs: u64,
    /// 切号后的防抖窗口（秒）：同一会话切号后此窗口内不再切，防止反复横跳。默认 30。
    #[serde(default = "default_switch_debounce_secs")]
    pub switch_debounce_secs: u64,
    /// 负载再平衡的「活跃会话」窗口（秒）：只统计 `last_seen` 在此窗口内的会话作为各号活跃负载。
    /// 默认 300（5 分钟）——比 affinity TTL 短，反映「当前真正在用」的会话。
    #[serde(default = "default_rebalance_active_window_secs")]
    pub rebalance_active_window_secs: u64,
    /// 负载再平衡触发的活跃会话数差距阈值（滞后/防横跳）：仅当「原号活跃会话数 − 最空号活跃会话数 ≥ 此值」
    /// 才把当前会话迁到最空号。默认 2（≥2 保证迁移后两边不会立刻反向触发）。0 表示关闭被动再平衡。
    #[serde(default = "default_rebalance_min_gap")]
    pub rebalance_min_gap: usize,
    /// 负载再平衡的「真实利用率」差距阈值。利用率 = current_rate / safe_rps_hi（越接近/超过 1 越满载）。
    /// 仅当「原号利用率 − 最闲号利用率 ≥ 此值」才迁移。这是比会话数更真实的负载信号：
    /// 一个号会话少但每个都在撞墙(利用率高)，应把会话迁给会话多但很闲(利用率低)的号。
    /// 默认 0.3。0 表示关闭按利用率再平衡（回退到纯会话数）。
    #[serde(default = "default_rebalance_utilization_gap")]
    pub rebalance_utilization_gap: f64,
    /// 后台主动巡检调度器的间隔（秒）：每隔此秒数算一次全局负载快照、按优先级栈做温和搬迁/睡眠疏散。
    /// 不依赖 Thread 自己发请求——根治「睡眠会话永不被挪、肇事 Thread 赖着原号」。默认 10。
    /// 0 表示关闭后台巡检（回退到纯被动 select_with_affinity 路径）。
    #[serde(default = "default_scheduler_tick_secs")]
    pub scheduler_tick_secs: u64,
    /// 负载再平衡的「纯 RPM 负载」差距阈值（req/min）：本号 RPM 比全局最空号高出此值即触发温和搬迁。
    /// 这是修「忙但没撞墙」盲区的核心信号——不挂 util 的 SATURATED 门，作为 rebalance 第一优先级信号。
    /// 默认 8.0。0 表示关闭按 RPM 再平衡。
    #[serde(default = "default_rebalance_rpm_gap")]
    pub rebalance_rpm_gap: f64,
    /// 睡眠会话疏散的「绑定数」差距阈值：本号 TTL 内绑定会话数（含睡着的）比最空号多 ≥ 此值，
    /// 后台巡检就把它名下「压力最小/睡眠」的会话提前疏散到最空号。防睡眠会话堆弱号、唤醒后瞬间打满。
    /// 默认 4。0 表示关闭睡眠疏散。
    #[serde(default = "default_rebalance_bound_gap")]
    pub rebalance_bound_gap: usize,
    /// 被限流硬触发疏散：某号最近 5 分钟「上游 429 率」超过此值（且持续撞墙、非单次瞬态）即立刻把它名下
    /// 压力最小的会话疏散到最健康的号——**绕过 RPM/利用率门槛**，因为「正在被限流」是比「忙」更紧急的信号。
    /// 这是修「单人低 RPM 场景下号被 429 压垮、却因 RPM 差够不到 rebalance_rpm_gap 而永不疏散」的核心信号。
    /// 默认 0.05（5%）。0 表示关闭按 429 率硬触发疏散。
    #[serde(default = "default_rebalance_429_rate_threshold")]
    pub rebalance_429_rate_threshold: f64,
    /// 利用率信号的「饱和」前置门：仅当原号利用率 ≥ 此值才考虑按利用率差疏散。
    /// 原为硬编码 1.0（要真正贴满天花板才动），导致「快撞墙但还没撞满」的中间态永不触发。
    /// 下调到 0.8 让中间态也能提前疏散。默认 0.8。
    #[serde(default = "default_rebalance_util_saturated")]
    pub rebalance_util_saturated: f64,
    /// 优先级独享：高优先 Thread 独享号时，仅当该号余量 headroom 比例 > 此值，才允许「负载特别低的」
    /// priority=0 Thread 蹭进来填空（蹭的不抢高优先资源、也保持粘性）。默认 0.5（留一半余量才让蹭）。
    #[serde(default = "default_exclusive_headroom_ratio")]
    pub exclusive_headroom_ratio: f64,
    /// 优先级独享：独享 Thread 连续无 inflight 且空闲超此秒数 → 把独享号临时借给普通 Thread。
    /// 独立于 rebalance_active_window_secs（避免 5 分钟边界振荡）。默认 300。
    #[serde(default = "default_exclusive_borrow_idle_secs")]
    pub exclusive_borrow_idle_secs: u64,
    /// 优先级独享：借出的独享号被高优先 Thread 夺回后的防抖窗口（秒），防「醒来夺回→又睡→又借」抖动。
    /// 默认 60。
    #[serde(default = "default_reclaim_debounce_secs")]
    pub reclaim_debounce_secs: u64,
    /// overflow-on-busy：当**绑定号真撞墙**（429 频发 + 吞吐被压低且不是「没活干」）时，
    /// 把**整个会话(Thread)** 迁移到池里更健康的号。与负载再平衡的区别：再平衡是「均摊负载」，
    /// 这是「逃离正在烧的号」——优先级更高、判定更严（要同时满足 429 率高 + goodput 低 + 非 app_limited）。
    /// 迁移走切号路径（写 last_switch_at + 防抖），迁后 `migrate_debounce_secs` 窗口内不再迁，防来回横跳。
    /// 默认关闭（Owner 红线：同机多号风险；开了也只是「换健康号」非裸轮询）。
    #[serde(default)]
    pub overflow_on_busy: OverflowOnBusyConfig,
}

/// overflow-on-busy（健康度触发的整-Thread 迁移）配置。
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverflowOnBusyConfig {
    /// 是否开启。默认 false——Owner 改 config + 重启 kiro-rs 才生效。
    #[serde(default)]
    pub enabled: bool,
    /// 触发门槛①：绑定号 5 分钟上游 429 率超此值才算「真撞墙」。默认 0.2（20%）。
    #[serde(default = "default_overflow_upstream429_rate_threshold")]
    pub upstream429_rate_threshold: f64,
    /// 触发门槛②：绑定号 goodput_rps 低于 `learned_safe_rps_hi × 此比例` 才算「吞吐被压低」。
    /// 默认 0.5（被压到健康上界一半以下）。
    #[serde(default = "default_overflow_goodput_ratio_threshold")]
    pub goodput_ratio_threshold: f64,
    /// 迁移后的防抖窗口（秒）：同一会话 overflow 迁移后此窗口内不再迁/切，防来回横跳。
    /// 默认 60（比普通切号 debounce 30 长——撞墙迁移代价大，迁完多观察一会）。
    #[serde(default = "default_overflow_migrate_debounce_secs")]
    pub migrate_debounce_secs: u64,
}

impl Default for OverflowOnBusyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream429_rate_threshold: default_overflow_upstream429_rate_threshold(),
            goodput_ratio_threshold: default_overflow_goodput_ratio_threshold(),
            migrate_debounce_secs: default_overflow_migrate_debounce_secs(),
        }
    }
}

impl Default for MultiAccountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            switch_threshold_secs: default_switch_threshold_secs(),
            affinity_ttl_secs: default_affinity_ttl_secs(),
            switch_debounce_secs: default_switch_debounce_secs(),
            rebalance_active_window_secs: default_rebalance_active_window_secs(),
            rebalance_min_gap: default_rebalance_min_gap(),
            rebalance_utilization_gap: default_rebalance_utilization_gap(),
            scheduler_tick_secs: default_scheduler_tick_secs(),
            rebalance_rpm_gap: default_rebalance_rpm_gap(),
            rebalance_bound_gap: default_rebalance_bound_gap(),
            rebalance_429_rate_threshold: default_rebalance_429_rate_threshold(),
            rebalance_util_saturated: default_rebalance_util_saturated(),
            exclusive_headroom_ratio: default_exclusive_headroom_ratio(),
            exclusive_borrow_idle_secs: default_exclusive_borrow_idle_secs(),
            reclaim_debounce_secs: default_reclaim_debounce_secs(),
            overflow_on_busy: OverflowOnBusyConfig::default(),
        }
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
    /// 绝对速率下界（rps），与学习下界取 max，防除零/死锁。
    #[serde(default = "default_absolute_min_rate_rps")]
    pub absolute_min_rate_rps: f64,
    /// 有学习数据时：有效下界 = max(absolute_min, safe_rps_lo × 此系数)。
    #[serde(default = "default_learned_floor_factor")]
    pub learned_floor_factor: f64,
    /// 启用 learned floor 所需最少样本数（未成熟则回退 min_rate_rps）。
    #[serde(default = "default_learning_min_samples_for_floor")]
    pub learning_min_samples_for_floor: u64,
    /// acquire 本地排队硬顶（秒）：Absorb-First，在此时间内只等待不 Fail Aloud。
    #[serde(default = "default_max_absorb_wait_secs")]
    pub max_absorb_wait_secs: u64,
    /// 最高速率（rps）。先不超过已知会高 429 的 2 rps。
    #[serde(default = "default_max_rate_rps")]
    pub max_rate_rps: f64,
    /// 令牌桶容量（突发）。实测 burst 很小，先禁止瞬时双发。
    #[serde(default = "default_burst")]
    pub burst: f64,
    /// 每个 scope 的最大在飞请求数（旧字段，语义已被重载，注意陷阱）：
    /// - `> 1`：作为 `adaptiveConcurrency.hardMaxInflight` 的上限（下钳到该值）；
    /// - `== 1`：视为「serde 默认 / 未配置」哨兵，**不覆盖** adaptive，走 `adaptiveConcurrency`。
    ///
    /// ⚠️ 因此本字段**无法表达「真单飞 1」**：写 1 会被当成「没配置」而忽略。
    /// 要强制单飞，请改用 `adaptiveConcurrency.hardMaxInflight = 1`，不要在这里写 1。
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
    /// 账号熔断器（OPEN/HALF_OPEN 静养）。
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// 自适应并发（maxInflight 在线学习）。
    #[serde(default)]
    pub adaptive_concurrency: AdaptiveConcurrencyConfig,
    /// 429 预算驱动的上探。
    #[serde(default)]
    pub probe: ProbeConfig,
    /// 在线学习引擎。
    #[serde(default)]
    pub learning: LearningConfig,
}

/// 限速器纯数值参数的运行时热改补丁（admin `PUT /config/rate-limit`）。
/// 全 `Option`：只改传入的字段，其余保留当前值。**不含 `hard_max_inflight`**——
/// 信号量容量构造时定死，无法原子热改（见 `LimiterRegistry::reconfigure_all` 注释）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdaptiveConfigPatch {
    /// AIMD/goodput 加性增步长（rps），>= 0。
    #[serde(default)]
    pub additive_step_rps: Option<f64>,
    /// 两次加速之间的最小间隔（秒）。
    #[serde(default)]
    pub increase_interval_secs: Option<u64>,
    /// 触发一次加速所需累计成功数，>= 1。
    #[serde(default)]
    pub successes_per_increase: Option<u64>,
    /// 最高速率（rps），> 0。
    #[serde(default)]
    pub max_rate_rps: Option<f64>,
    /// goodput 429 硬上限，0~1。
    #[serde(default)]
    pub goodput_hard_ceiling: Option<f64>,
    /// goodput 失控保险丝：rate 绝对上限（rps），> 0。
    #[serde(default)]
    pub goodput_sanity_max_rps: Option<f64>,
    /// overflow-on-busy 子配置补丁（嵌套，全 Option）。
    #[serde(default)]
    pub overflow_on_busy: Option<OverflowOnBusyPatch>,
}

impl AdaptiveConfigPatch {
    /// 是否一个字段都没传（用于「至少给一个字段」校验）。
    pub fn is_empty(&self) -> bool {
        self.additive_step_rps.is_none()
            && self.increase_interval_secs.is_none()
            && self.successes_per_increase.is_none()
            && self.max_rate_rps.is_none()
            && self.goodput_hard_ceiling.is_none()
            && self.goodput_sanity_max_rps.is_none()
            && self
                .overflow_on_busy
                .as_ref()
                .map(|o| o.is_empty())
                .unwrap_or(true)
    }
}

/// overflow-on-busy 配置的运行时热改补丁（全 Option）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverflowOnBusyPatch {
    /// 是否开启整-Thread 健康度迁移。
    #[serde(default)]
    pub enabled: Option<bool>,
    /// 触发门槛①：5 分钟上游 429 率阈值，0~1。
    #[serde(default)]
    pub upstream429_rate_threshold: Option<f64>,
    /// 触发门槛②：goodput 占健康上界比例阈值，0~1。
    #[serde(default)]
    pub goodput_ratio_threshold: Option<f64>,
    /// 迁移后防抖窗口（秒）。
    #[serde(default)]
    pub migrate_debounce_secs: Option<u64>,
}

impl OverflowOnBusyPatch {
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.upstream429_rate_threshold.is_none()
            && self.goodput_ratio_threshold.is_none()
            && self.migrate_debounce_secs.is_none()
    }
}

/// 账号熔断器配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_circuit_breaker_enabled")]
    pub enabled: bool,
    #[serde(default = "default_open_429_threshold")]
    pub open_429_threshold: u32,
    #[serde(default = "default_half_open_success_target")]
    pub half_open_success_target: u32,
    #[serde(default = "default_initial_quarantine_secs")]
    pub initial_quarantine_secs: u64,
    #[serde(default = "default_min_quarantine_secs")]
    pub min_quarantine_secs: u64,
    #[serde(default = "default_max_quarantine_secs")]
    pub max_quarantine_secs: u64,
    /// HalfOpen 停留超过此秒数 → 强制清 canary 重新探测（RAII 之外的第二层兜底，防 canary 泄漏卡死）。
    #[serde(default = "default_half_open_max_secs")]
    pub half_open_max_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: default_circuit_breaker_enabled(),
            open_429_threshold: default_open_429_threshold(),
            half_open_success_target: default_half_open_success_target(),
            initial_quarantine_secs: default_initial_quarantine_secs(),
            min_quarantine_secs: default_min_quarantine_secs(),
            max_quarantine_secs: default_max_quarantine_secs(),
            half_open_max_secs: default_half_open_max_secs(),
        }
    }
}

/// 自适应并发配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdaptiveConcurrencyConfig {
    #[serde(default = "default_adaptive_concurrency_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_inflight")]
    pub min_inflight: usize,
    #[serde(default = "default_hard_max_inflight")]
    pub hard_max_inflight: usize,
    #[serde(default = "default_safety_factor")]
    pub safety_factor: f64,
    #[serde(default = "default_grow_factor_per_window")]
    pub grow_factor_per_window: f64,
    #[serde(default = "default_shrink_factor_on_429")]
    pub shrink_factor_on_429: f64,
    #[serde(default = "default_duration_quantile")]
    pub duration_quantile: String,
}

impl Default for AdaptiveConcurrencyConfig {
    fn default() -> Self {
        Self {
            enabled: default_adaptive_concurrency_enabled(),
            min_inflight: default_min_inflight(),
            hard_max_inflight: default_hard_max_inflight(),
            safety_factor: default_safety_factor(),
            grow_factor_per_window: default_grow_factor_per_window(),
            shrink_factor_on_429: default_shrink_factor_on_429(),
            duration_quantile: default_duration_quantile(),
        }
    }
}

/// 429 预算上探配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeConfig {
    #[serde(default = "default_upstream_429_budget_low")]
    pub upstream_429_budget_low: f64,
    #[serde(default = "default_upstream_429_budget_high")]
    pub upstream_429_budget_high: f64,
    #[serde(default = "default_probe_window_secs")]
    pub window_secs: u64,
    /// goodput 控制器：429 目标护栏带下沿。窗口 429 率 < 此值 → 仍有余量，
    /// 允许 goodput 爬山探更高 rate。默认 0.02（2%）。
    #[serde(default = "default_goodput_band_low")]
    pub goodput_band_low: f64,
    /// goodput 控制器：429 目标护栏带上沿。带内([low,high])= 贴着天花板的理想稳态，
    /// 不主动升降。默认 0.08（8%）。
    #[serde(default = "default_goodput_band_high")]
    pub goodput_band_high: f64,
    /// goodput 控制器：429 硬上限。超过此值 → 强制降速（无视 goodput 趋势），
    /// 并记录可能的升级惩罚信号。默认 0.15（15%）。
    #[serde(default = "default_goodput_hard_ceiling")]
    pub goodput_hard_ceiling: f64,
    /// goodput 控制器：失控保险丝——rate 的绝对上限（rps）。去掉了日常 maxRateRps
    /// 人为封顶后，这是防控制器 bug 把 rate 冲上天的最后护栏。默认 5.0
    /// （远高于实测单号 ~2/s 真顶，日常碰不到）。
    #[serde(default = "default_goodput_sanity_max_rps")]
    pub goodput_sanity_max_rps: f64,
    /// goodput 控制器：判定 goodput「上涨」的最小相对增幅（占上一窗口的比例）。
    /// 涨幅低于此视为「持平」→ 停止继续爬。默认 0.05（5%）。
    #[serde(default = "default_goodput_rise_epsilon")]
    pub goodput_rise_epsilon: f64,
    /// goodput 控制器：app-limited 去抖拍数。inflight 瞬时低于并发上限只是「这一拍碰巧没排满」，
    /// 不代表真没需求；连续 N 拍都判 app-limited 才真当 app-limited（暂停爬升）。
    /// 防瞬时 inflight 抖动单拍误判把正在爬升的状态机打断。默认 2。
    #[serde(default = "default_app_limited_debounce_ticks")]
    pub app_limited_debounce_ticks: u32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            upstream_429_budget_low: default_upstream_429_budget_low(),
            upstream_429_budget_high: default_upstream_429_budget_high(),
            window_secs: default_probe_window_secs(),
            goodput_band_low: default_goodput_band_low(),
            goodput_band_high: default_goodput_band_high(),
            goodput_hard_ceiling: default_goodput_hard_ceiling(),
            goodput_sanity_max_rps: default_goodput_sanity_max_rps(),
            goodput_rise_epsilon: default_goodput_rise_epsilon(),
            app_limited_debounce_ticks: default_app_limited_debounce_ticks(),
        }
    }
}

/// 在线学习配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LearningConfig {
    #[serde(default = "default_learning_enabled")]
    pub enabled: bool,
    #[serde(default = "default_learning_persist_path")]
    pub persist_path: String,
    #[serde(default = "default_ewma_alpha")]
    pub ewma_alpha: f64,
    /// 学习分桶时间衰减的半衰期（秒）。后台周期对所有账号的桶做指数半衰，
    /// 让旧 429 随时间被遗忘——避免某号几小时前撞过墙就被永久按慢号对待。
    #[serde(default = "default_bucket_decay_half_life_secs")]
    pub bucket_decay_half_life_secs: u64,
    /// 轻流量恢复速率（每次「未撞 429 的成功」让 safe_rps 安全带朝出厂默认
    /// (`DEFAULT_SAFE_RPS_LO/HI`) 方向乘性回升的比例，0~1）。
    ///
    /// 根因（2026-06-22）：safe_rps 只在「429 下砍」和「高速成功上抬」时变；而高速成功
    /// 的前提是发送率 > 当前 safe_rps，但 rate_limiter 的爬升上限又被 safe_rps_hi 卡住
    /// → 两者互相钳制，一旦被 429 砍到地板，轻流量（发送率贴着低 safe_rps）下永远爬不回来，
    /// 号被永久按慢号对待（实测 6 号 429=0% 却全趴在 0.2~0.5 rps）。
    /// 这个温和回升给安全带一条「没撞墙就慢慢往回松」的出路：撞 429 仍立刻被砍（保护不变），
    /// 只是不再「一被砍就永久趴底」。设 0 即关闭（回到旧行为）。
    #[serde(default = "default_recovery_per_sample")]
    pub recovery_per_sample: f64,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            enabled: default_learning_enabled(),
            persist_path: default_learning_persist_path(),
            ewma_alpha: default_ewma_alpha(),
            bucket_decay_half_life_secs: default_bucket_decay_half_life_secs(),
            recovery_per_sample: default_recovery_per_sample(),
        }
    }
}

impl Default for AdaptiveLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_adaptive_enabled(),
            enforce: false,
            enforce_scope: default_enforce_scope(),
            initial_rate_rps: default_initial_rate_rps(),
            min_rate_rps: default_min_rate_rps(),
            absolute_min_rate_rps: default_absolute_min_rate_rps(),
            learned_floor_factor: default_learned_floor_factor(),
            learning_min_samples_for_floor: default_learning_min_samples_for_floor(),
            max_absorb_wait_secs: default_max_absorb_wait_secs(),
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
            circuit_breaker: CircuitBreakerConfig::default(),
            adaptive_concurrency: AdaptiveConcurrencyConfig::default(),
            probe: ProbeConfig::default(),
            learning: LearningConfig::default(),
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
fn default_absolute_min_rate_rps() -> f64 {
    0.02
}
fn default_learned_floor_factor() -> f64 {
    0.8
}
fn default_learning_min_samples_for_floor() -> u64 {
    20
}
fn default_max_absorb_wait_secs() -> u64 {
    120
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
fn default_switch_threshold_secs() -> u64 {
    15
}
fn default_affinity_ttl_secs() -> u64 {
    3600
}
fn default_switch_debounce_secs() -> u64 {
    30
}
fn default_rebalance_active_window_secs() -> u64 {
    300
}
fn default_rebalance_min_gap() -> usize {
    2
}
fn default_rebalance_utilization_gap() -> f64 {
    0.3
}

fn default_scheduler_tick_secs() -> u64 {
    10
}

fn default_rebalance_rpm_gap() -> f64 {
    2.0
}

fn default_rebalance_bound_gap() -> usize {
    4
}

fn default_rebalance_429_rate_threshold() -> f64 {
    0.05
}

fn default_rebalance_util_saturated() -> f64 {
    0.8
}

fn default_exclusive_headroom_ratio() -> f64 {
    0.5
}

fn default_exclusive_borrow_idle_secs() -> u64 {
    300
}

fn default_reclaim_debounce_secs() -> u64 {
    60
}

fn default_overflow_upstream429_rate_threshold() -> f64 {
    0.2
}

fn default_overflow_goodput_ratio_threshold() -> f64 {
    0.5
}

fn default_overflow_migrate_debounce_secs() -> u64 {
    60
}

fn default_circuit_breaker_enabled() -> bool {
    true
}
fn default_open_429_threshold() -> u32 {
    3
}
fn default_half_open_success_target() -> u32 {
    2
}
fn default_initial_quarantine_secs() -> u64 {
    30
}
fn default_min_quarantine_secs() -> u64 {
    5
}
fn default_max_quarantine_secs() -> u64 {
    1800
}
fn default_half_open_max_secs() -> u64 {
    // HalfOpen 探测窗口上限：超过则强制清 canary 重新探测。取一个比 canary 单次请求
    // 合理耗时大得多、又不至于让坏号长期占着 HalfOpen 的值。
    120
}
fn default_adaptive_concurrency_enabled() -> bool {
    true
}
fn default_min_inflight() -> usize {
    4
}
fn default_hard_max_inflight() -> usize {
    32
}
fn default_safety_factor() -> f64 {
    0.8
}
fn default_grow_factor_per_window() -> f64 {
    1.25
}
fn default_shrink_factor_on_429() -> f64 {
    0.5
}
fn default_duration_quantile() -> String {
    "p80".to_string()
}
fn default_upstream_429_budget_low() -> f64 {
    0.01
}
fn default_upstream_429_budget_high() -> f64 {
    0.02
}
fn default_probe_window_secs() -> u64 {
    300
}
fn default_goodput_band_low() -> f64 {
    0.02
}
fn default_goodput_band_high() -> f64 {
    0.08
}
fn default_goodput_hard_ceiling() -> f64 {
    0.15
}
fn default_goodput_sanity_max_rps() -> f64 {
    5.0
}
fn default_goodput_rise_epsilon() -> f64 {
    0.05
}
fn default_app_limited_debounce_ticks() -> u32 {
    2
}
fn default_learning_enabled() -> bool {
    true
}
fn default_learning_persist_path() -> String {
    "account_learning.json".to_string()
}
fn default_ewma_alpha() -> f64 {
    0.2
}
fn default_bucket_decay_half_life_secs() -> u64 {
    // 1800s = 30min 半衰期：约 30 分钟后旧 429 的权重减半，2-3 小时基本淡出。
    // 既能让被打狠的号在白天逐步恢复，又不会快到「刚撞墙就忘」失去保护意义。
    1800
}
fn default_recovery_per_sample() -> f64 {
    // 0.01 = 每次「未撞 429 的成功」让安全带朝出厂默认回升 1% 的剩余差距（乘性逼近）。
    // 很温和：约 70 次连续无 429 成功才把差距收掉一半；轻流量号几百次 idle 成功能在
    // 几十分钟~数小时内从地板缓慢爬回默认，而一旦撞 429 立刻被既有 `min(send_rate*0.85)`
    // 砍回去，保护强度不变。设 0 关闭（回到「一被砍永久趴底」的旧行为）。
    0.01
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
            runtime_endpoint: default_runtime_endpoint(),
            cli_version: default_cli_version(),
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
        assert_eq!(c.absolute_min_rate_rps, 0.02);
        assert_eq!(c.learned_floor_factor, 0.8);
        assert_eq!(c.learning_min_samples_for_floor, 20);
        assert_eq!(c.max_absorb_wait_secs, 120);
        assert_eq!(c.max_rate_rps, 2.0);
        assert_eq!(c.burst, 1.0);
        assert_eq!(c.max_inflight_per_scope, 1, "serde 默认仍为 1（不覆盖 adaptive）");
        assert_eq!(c.adaptive_concurrency.hard_max_inflight, 32);
        assert_eq!(
            crate::kiro::rate_limiter::AdaptiveConfig::from_cfg(&c).hard_max_inflight,
            32,
            "默认 max_inflight_per_scope=1 不应 cap adaptive hard max"
        );
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

    #[test]
    fn max_inflight_per_scope_caps_hard_max_when_above_one() {
        let json = r#"{
            "maxInflightPerScope": 12,
            "adaptiveConcurrency": { "hardMaxInflight": 32, "minInflight": 4 }
        }"#;
        let c: AdaptiveLimitConfig = serde_json::from_str(json).expect("parse config");
        let adaptive = crate::kiro::rate_limiter::AdaptiveConfig::from_cfg(&c);
        assert_eq!(adaptive.hard_max_inflight, 12);
    }
}

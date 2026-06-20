//! 分层自适应学习调度器（解决 AWS 429）。
//!
//! 设计：账号状态机 + AIMD + 自适应 maxInflight + 429 预算上探 + 在线学习。
//! Spec: docs/2026-06-19-hierarchical-adaptive-scheduler-spec.md

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::Serialize;
use std::time::Instant;
use tokio::sync::{Notify, Semaphore};
use tokio::time::sleep;

use crate::kiro::account_learning::{
    BottleneckDimension, LearningStore, SendContextSample,
};
use crate::model::config::AdaptiveLimitConfig;

/// 限速作用域。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThrottleScope {
    UserCredential(u64),
    ServiceProfile(String),
}

impl ThrottleScope {
    fn key(&self) -> String {
        match self {
            ThrottleScope::UserCredential(id) => format!("user:{id}"),
            ThrottleScope::ServiceProfile(arn) => format!("service:{arn}"),
        }
    }

    pub fn credential_id(&self) -> Option<u64> {
        match self {
            ThrottleScope::UserCredential(id) => Some(*id),
            _ => None,
        }
    }
}

/// 上游 429 的类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleReason {
    UserRate,
    ServiceRate,
    Suspicious,
    Unknown,
}

pub fn classify_throttle_reason(body: &str) -> ThrottleReason {
    if body.contains("SERVICE_REQUEST_RATE_EXCEEDED") {
        ThrottleReason::ServiceRate
    } else if body.contains("USER_REQUEST_RATE_EXCEEDED") {
        ThrottleReason::UserRate
    } else if body.to_ascii_lowercase().contains("suspicious activity") {
        ThrottleReason::Suspicious
    } else {
        ThrottleReason::Unknown
    }
}

/// EWMA 偶发 lo>hi 时规范化，避免 f64::clamp panic。
fn normalize_learned_bounds((lo, hi): (f64, f64)) -> (f64, f64) {
    if lo <= hi {
        (lo, hi)
    } else {
        (hi, lo)
    }
}

/// 账号熔断状态（对外观测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountState {
    Healthy,
    Open,
    HalfOpen,
    Disabled,
}

/// 在飞许可：drop 时记录持有时长并唤醒 WaitInflight 等待者。
pub(crate) struct LimiterPermit {
    permit: tokio::sync::OwnedSemaphorePermit,
    limiter: Arc<AdaptiveLimiter>,
    /// 仅当 token 桶放行、真实请求在飞时起算；abort 路径为 None，drop 时不记 held 样本。
    acquired_at: Option<Instant>,
}

impl LimiterPermit {
    pub(crate) fn new(limiter: Arc<AdaptiveLimiter>, permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self {
            permit,
            limiter,
            acquired_at: None,
        }
    }

    /// token 桶等待结束、即将发请求时调用，held_ms 只统计此后到 drop 的时长。
    fn mark_request_started(&mut self) {
        self.acquired_at = Some(Instant::now());
    }
}

impl std::fmt::Debug for LimiterPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LimiterPermit")
            .field(
                "held_ms",
                &self
                    .acquired_at
                    .map(|t| t.elapsed().as_millis())
                    .unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for LimiterPermit {
    fn drop(&mut self) {
        if let Some(acquired_at) = self.acquired_at {
            let held_ms = acquired_at.elapsed().as_millis() as u64;
            self.limiter.record_held_duration(held_ms);
        }
        self.limiter.notify.notify_waiters();
    }
}

/// HalfOpen canary 的 RAII 守卫。
///
/// 当 `acquire()` 内某次决策把 `canary_in_flight` 置 true 后，立刻把这个守卫
/// armed 起来。守卫 `Drop` 时（无论是 LocalThrottled 正常返回、还是 acquire future
/// 在任意 await 点被取消而整体 drop）都会无条件把 canary 清回 false。
///
/// 唯一例外是 `disarm()`：当 permit 成功交还给调用方（`Proceed`）时调用，把清理
/// 责任移交给 provider 侧的 `LimiterAttemptGuard` + `on_success`/`on_throttle`/
/// `on_acquire_aborted`，避免重复清理。
struct CanaryGuard {
    limiter: Arc<AdaptiveLimiter>,
    armed: bool,
}

impl CanaryGuard {
    fn new(limiter: Arc<AdaptiveLimiter>) -> Self {
        Self {
            limiter,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CanaryGuard {
    fn drop(&mut self) {
        if self.armed {
            self.limiter.clear_half_open_canary();
        }
    }
}

/// acquire 的结果。
#[derive(Debug)]
pub enum AcquireOutcome {
    Proceed(LimiterPermit),
    LocalThrottled {
        est_wait_ms: u64,
        current_rps: f64,
        reason: &'static str,
    },
    ShadowProceed { would_wait_ms: u64, would_rps: f64 },
}

/// 运行时强类型配置（从 AdaptiveLimitConfig 映射）。
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    pub enabled: bool,
    pub enforce: bool,
    pub initial_rate_rps: f64,
    pub min_rate_rps: f64,
    pub absolute_min_rate_rps: f64,
    pub learned_floor_factor: f64,
    pub learning_min_samples_for_floor: u64,
    pub max_absorb_wait: Duration,
    pub max_rate_rps: f64,
    pub burst: f64,
    pub hard_max_inflight: usize,
    pub min_inflight: usize,
    pub additive_step_rps: f64,
    pub increase_interval: Duration,
    pub successes_per_increase: u64,
    pub beta_user: f64,
    pub user_cooldown_base: Duration,
    pub cooldown_cap: Duration,
    pub local_queue_timeout: Duration,
    pub circuit_breaker_enabled: bool,
    pub open_429_threshold: u32,
    pub half_open_success_target: u32,
    pub initial_quarantine: Duration,
    pub min_quarantine: Duration,
    pub max_quarantine: Duration,
    pub half_open_max: Duration,
    pub adaptive_concurrency_enabled: bool,
    pub safety_factor: f64,
    pub grow_factor: f64,
    pub shrink_factor: f64,
    pub probe_budget_low: f64,
    pub probe_budget_high: f64,
    pub probe_window: Duration,
    /// goodput 控制器护栏带：[band_low, band_high] 是理想稳态(贴天花板),
    /// 低于 band_low 允许爬山，高于 hard_ceiling 强制降速。
    pub goodput_band_low: f64,
    pub goodput_band_high: f64,
    pub goodput_hard_ceiling: f64,
    /// 失控保险丝：rate 绝对上限(rps)，去掉日常 max_rate 封顶后防 bug 冲天。
    pub goodput_sanity_max_rps: f64,
    /// goodput 判「上涨」的最小相对增幅；低于此视为持平→停止爬升。
    pub goodput_rise_epsilon: f64,
    /// app-limited 去抖拍数：连续 N 拍都判 app-limited 才真当 app-limited，
    /// 防瞬时 inflight 抖动单拍误判打断爬升。
    pub app_limited_debounce_ticks: u32,
    pub learning_enabled: bool,
}

impl AdaptiveConfig {
    pub fn from_cfg(c: &AdaptiveLimitConfig) -> Self {
        let min_rate = c.min_rate_rps.max(0.001);
        let max_rate = c.max_rate_rps.max(min_rate);
        let initial = c.initial_rate_rps.clamp(min_rate, max_rate);
        let ac = &c.adaptive_concurrency;
        let cb = &c.circuit_breaker;
        let pr = &c.probe;
        let ac_hard = ac.hard_max_inflight.max(ac.min_inflight).max(1);
        // max_inflight_per_scope > 1 表示 ops 显式配置了旧字段；=1 为 serde 默认，不覆盖 adaptive_concurrency。
        let hard_max_inflight = if c.max_inflight_per_scope > 1 {
            let requested = c.max_inflight_per_scope;
            let raised = requested.max(ac.min_inflight).min(ac_hard);
            if requested < ac.min_inflight {
                tracing::warn!(
                    max_inflight_per_scope = requested,
                    min_inflight = ac.min_inflight,
                    effective = raised,
                    "maxInflightPerScope 低于 minInflight，已上抬至 minInflight"
                );
            } else if requested > ac_hard {
                tracing::warn!(
                    max_inflight_per_scope = requested,
                    hard_max_inflight = ac_hard,
                    effective = raised,
                    "maxInflightPerScope 超过 hardMaxInflight，已下调至 hardMaxInflight"
                );
            }
            raised
        } else {
            ac_hard
        };
        Self {
            enabled: c.enabled,
            enforce: c.enforce,
            initial_rate_rps: initial,
            min_rate_rps: min_rate,
            absolute_min_rate_rps: c.absolute_min_rate_rps.max(0.001),
            learned_floor_factor: c.learned_floor_factor.clamp(0.1, 1.0),
            learning_min_samples_for_floor: c.learning_min_samples_for_floor.max(1),
            max_absorb_wait: Duration::from_secs(c.max_absorb_wait_secs.max(1)),
            max_rate_rps: max_rate,
            burst: c.burst.max(1.0),
            hard_max_inflight,
            min_inflight: ac.min_inflight.max(1),
            additive_step_rps: c.additive_step_rps.max(0.0),
            increase_interval: Duration::from_secs(c.increase_interval_secs),
            successes_per_increase: c.successes_per_increase.max(1),
            beta_user: c.beta_user.clamp(0.05, 0.95),
            user_cooldown_base: Duration::from_secs(c.user_cooldown_base_secs.max(1)),
            cooldown_cap: Duration::from_secs(c.cooldown_cap_secs.max(1)),
            local_queue_timeout: Duration::from_secs(c.local_queue_timeout_secs.max(1)),
            circuit_breaker_enabled: cb.enabled,
            open_429_threshold: cb.open_429_threshold.max(1),
            half_open_success_target: cb.half_open_success_target.max(1),
            initial_quarantine: Duration::from_secs(cb.initial_quarantine_secs.max(1)),
            min_quarantine: Duration::from_secs(cb.min_quarantine_secs.max(1)),
            max_quarantine: Duration::from_secs(cb.max_quarantine_secs.max(cb.min_quarantine_secs)),
            half_open_max: Duration::from_secs(cb.half_open_max_secs.max(1)),
            adaptive_concurrency_enabled: ac.enabled,
            safety_factor: ac.safety_factor.clamp(0.1, 1.0),
            grow_factor: ac.grow_factor_per_window.max(1.0),
            shrink_factor: ac.shrink_factor_on_429.clamp(0.1, 1.0),
            probe_budget_low: pr.upstream_429_budget_low.clamp(0.0, 1.0),
            probe_budget_high: pr.upstream_429_budget_high.clamp(0.0, 1.0),
            probe_window: Duration::from_secs(pr.window_secs.max(60)),
            goodput_band_low: pr.goodput_band_low.clamp(0.0, 1.0),
            goodput_band_high: pr.goodput_band_high.clamp(0.0, 1.0),
            goodput_hard_ceiling: pr.goodput_hard_ceiling.clamp(0.0, 1.0),
            goodput_sanity_max_rps: pr.goodput_sanity_max_rps.max(min_rate),
            goodput_rise_epsilon: pr.goodput_rise_epsilon.max(0.0),
            app_limited_debounce_ticks: pr.app_limited_debounce_ticks.max(1),
            learning_enabled: c.learning.enabled,
        }
    }
}

#[derive(Debug, Clone)]
enum CircuitState {
    Healthy,
    Open { until: Instant, reason: String },
    HalfOpen {
        canary_in_flight: bool,
        successes: u32,
        /// 进入 HalfOpen 的时刻，用于超时自愈（防 canary 泄漏永久卡死）。
        entered_at: Instant,
    },
}

enum AcquireDecision {
    Return(AcquireOutcome),
    WaitInflight,
    /// 放行去拿 permit。`claimed_canary=true` 表示本次决策刚把 HalfOpen canary 置 true，
    /// 调用方必须用 `CanaryGuard` 保证后续无论成功/失败/被取消都能清回 false。
    ProceedToPermit { claimed_canary: bool },
}

struct State {
    rate_rps: f64,
    tokens: f64,
    last_refill: Instant,
    cooldown_until: Option<Instant>,
    consecutive_throttles: u32,
    consecutive_user_429: u32,
    successes_since_increase: u64,
    last_increase: Instant,
    circuit: CircuitState,
    effective_max_inflight: usize,
    upstream_events: VecDeque<(Instant, bool)>,
    /// goodput 测量：每次成功完成(on_success)记一个时间戳，按窗口算「成功请求/秒」。
    goodput_events: VecDeque<Instant>,
    /// 上一次 goodput 爬山时的 (goodput_rps, rate_rps)，用于「涨了继续/没涨退回」判断。
    last_probe_goodput: f64,
    last_probe_rate: f64,
    /// goodput 爬山方向：true=正在向上探(上轮抬了 rate)，需下轮验证 goodput 是否随之涨。
    probe_climbing: bool,
    /// app-limited 连击计数（瞬态，不持久化）：连续多少拍判定为 app-limited。
    /// 用于去抖——只有连续 ≥ app_limited_debounce_ticks 拍才真当 app-limited，
    /// 防瞬时 inflight 抖动单拍误判把正在爬升的状态机打断。
    app_limited_streak: u32,
    /// 自适应退避：上次退避(on_throttle 降速)的时刻，用于「退避后多快又撞 429」判断。
    last_backoff_at: Option<Instant>,
    /// 自适应退避学到的当前 beta（乘性减速系数），随「退避后是否很快又 429」调整。
    adaptive_beta: f64,
}

/// 单 scope 自适应限速 + 熔断 + 学习。
pub struct AdaptiveLimiter {
    credential_id: Option<u64>,
    cfg: AdaptiveConfig,
    pub(crate) state: Mutex<State>,
    inflight: Arc<Semaphore>,
    notify: Notify,
    learning: Option<Arc<LearningStore>>,
    sends_counter: Mutex<VecDeque<Instant>>,
}

impl AdaptiveLimiter {
    pub fn new_with_context(
        cfg: AdaptiveConfig,
        credential_id: Option<u64>,
        learning: Option<Arc<LearningStore>>,
    ) -> Arc<Self> {
        let now = Instant::now();
        let hard = cfg.hard_max_inflight;
        let effective = cfg.min_inflight.min(hard);
        let inflight = Arc::new(Semaphore::new(hard));
        let initial_rate = if let (Some(id), Some(store)) = (credential_id, &learning) {
            if store.learning_is_mature(id, cfg.learning_min_samples_for_floor) {
                let (lo, hi) = normalize_learned_bounds(store.learned_safe_rps(id));
                cfg.initial_rate_rps.clamp(lo, hi)
            } else {
                cfg.initial_rate_rps
            }
        } else {
            cfg.initial_rate_rps
        };
        let state = State {
            rate_rps: initial_rate,
            tokens: cfg.burst.min(1.0),
            last_refill: now,
            cooldown_until: None,
            consecutive_throttles: 0,
            consecutive_user_429: 0,
            successes_since_increase: 0,
            last_increase: now,
            circuit: CircuitState::Healthy,
            effective_max_inflight: effective,
            upstream_events: VecDeque::new(),
            goodput_events: VecDeque::new(),
            last_probe_goodput: 0.0,
            last_probe_rate: initial_rate,
            probe_climbing: false,
            app_limited_streak: 0,
            last_backoff_at: None,
            adaptive_beta: cfg.beta_user,
        };
        Arc::new(Self {
            credential_id,
            cfg,
            state: Mutex::new(state),
            inflight,
            notify: Notify::new(),
            learning,
            sends_counter: Mutex::new(VecDeque::new()),
        })
    }

    pub fn new(cfg: AdaptiveConfig) -> Arc<Self> {
        Self::new_with_context(cfg, None, None)
    }

    fn learned_bounds_if_mature(&self) -> Option<(f64, f64)> {
        let id = self.credential_id?;
        let store = self.learning.as_ref()?;
        if !store.learning_is_mature(id, self.cfg.learning_min_samples_for_floor) {
            return None;
        }
        Some(normalize_learned_bounds(store.learned_safe_rps(id)))
    }

    fn effective_rate_floor(&self) -> f64 {
        let absolute = self.cfg.absolute_min_rate_rps.max(0.001);
        if let Some((lo, _)) = self.learned_bounds_if_mature() {
            return (lo * self.cfg.learned_floor_factor).max(absolute);
        }
        self.cfg.min_rate_rps
    }

    fn learned_probe_cap(&self) -> f64 {
        if let Some((_, hi)) = self.learned_bounds_if_mature() {
            hi.min(self.cfg.max_rate_rps)
        } else {
            self.cfg.max_rate_rps
        }
    }

    pub fn current_rate_rps(&self) -> f64 {
        self.state.lock().rate_rps
    }

    pub fn cooldown_remaining(&self) -> Duration {
        Self::cooldown_remaining_from_state(&self.state.lock())
    }

    fn cooldown_remaining_from_state(st: &State) -> Duration {
        let now = Instant::now();
        match st.cooldown_until {
            Some(until) if until > now => until - now,
            _ => Duration::ZERO,
        }
    }

    fn circuit_snapshot(cfg: &AdaptiveConfig, st: &mut State) -> (AccountState, String, u64) {
        Self::maybe_advance_circuit(cfg, st);
        let now = Instant::now();
        match &st.circuit {
            CircuitState::Healthy => (AccountState::Healthy, String::new(), 0),
            CircuitState::Open { until, reason } => {
                let ms = if *until > now {
                    (*until - now).as_millis() as u64
                } else {
                    0
                };
                (AccountState::Open, reason.clone(), ms)
            }
            CircuitState::HalfOpen { .. } => (AccountState::HalfOpen, "canary_probe".into(), 0),
        }
    }

    pub fn account_state(&self) -> (AccountState, String, u64) {
        let mut st = self.state.lock();
        Self::circuit_snapshot(&self.cfg, &mut st)
    }

    pub fn is_open(&self) -> bool {
        matches!(self.account_state().0, AccountState::Open)
    }

    pub fn current_inflight(&self) -> usize {
        self.cfg.hard_max_inflight - self.inflight.available_permits()
    }

    pub fn current_max_inflight(&self) -> usize {
        self.state.lock().effective_max_inflight
    }

    pub fn consecutive_throttles(&self) -> u32 {
        self.state.lock().consecutive_throttles
    }

    pub fn upstream_429_rate(&self) -> f64 {
        rate_429_locked(&self.state.lock().upstream_events, self.cfg.probe_window)
    }

    /// 恢复探测条件的单一判定源(持锁版)：电路 Healthy、已冷却、rate 未到 max、
    /// 最近窗口 429 率 < budget_low。`recovery_probe_tick()`(实际抬升的门) 和
    /// `observe_full()`(面板 `recovery_eligible` 指标) 都复用它，避免两处各写一份导致
    /// 「面板说能恢复但实际不抬」或反之的漂移。
    fn recovery_eligible_locked(cfg: &AdaptiveConfig, st: &State) -> bool {
        matches!(st.circuit, CircuitState::Healthy)
            && st.cooldown_until.map(|t| Instant::now() >= t).unwrap_or(true)
            && st.rate_rps < cfg.max_rate_rps - f64::EPSILON
            && rate_429_locked(&st.upstream_events, cfg.probe_window) < cfg.probe_budget_low
    }

    /// goodput 控制器 tick（统一替代旧 recovery_probe + on_success 的 AIMD 上探）。
    ///
    /// 核心：目标函数是「最大化 goodput（成功请求/秒）」，不是「429 最低」。由后台周期调用，
    /// 即使零流量也能驱动恢复。决策逻辑（按优先级）：
    ///
    /// 1. 门：仅在 Healthy + 已冷却时动作；否则交给熔断/退避路径。
    /// 2. 🔴 **429 硬上限**：窗口 429 率 > `goodput_hard_ceiling`(默认15%) → 强制降速一档，
    ///    无视 goodput 趋势（防被 AWS 升级惩罚），并记录信号。
    /// 3. 🅿️ **app-limited**：在飞远低于并发上限(没 backlog) → 说明「没活干」不是「到顶了」，
    ///    保持 rate 不动（不把空闲误判成天花板，根治 #19 卡 0.06 那种病）。
    /// 4. ✅ **护栏带内** `[band_low, band_high]`：贴着天花板的理想稳态，保持不动。
    /// 5. 🔺 **带下沿以下**(429 < band_low，还有余量)：BBR 式 goodput 爬山——
    ///    上一轮抬了 rate 后，这轮看 goodput 涨没涨：涨了(≥ rise_epsilon)继续抬；
    ///    没涨/降了说明过了最优点，回退一档并停止爬升，直到 goodput 重新有空间。
    ///
    /// rate 受 `goodput_sanity_max_rps`(失控保险丝)封顶，不再受日常 `max_rate_rps` 封。
    /// 返回是否实际改动了 rate。
    pub fn goodput_control_tick(&self) -> bool {
        let mut st = self.state.lock();
        let now = Instant::now();
        // 门 1：仅 Healthy + 已冷却时由本控制器调速；其余状态交给熔断/退避。
        let cooled = st.cooldown_until.map(|t| now >= t).unwrap_or(true);
        if !matches!(st.circuit, CircuitState::Healthy) || !cooled {
            return false;
        }
        Self::refill_locked(&self.cfg, &mut st);

        let window = self.cfg.probe_window;
        let throttle_rate = rate_429_locked(&st.upstream_events, window);
        let goodput = goodput_rps_locked(&st.goodput_events, window);
        let floor = self.effective_rate_floor();
        let sanity_max = self.cfg.goodput_sanity_max_rps;
        let step = self.cfg.additive_step_rps.max(0.0);
        let before = st.rate_rps;

        // 门 2：429 硬上限——强制降速，无视 goodput（防升级惩罚）。
        if throttle_rate > self.cfg.goodput_hard_ceiling {
            st.rate_rps = (st.rate_rps - step).max(floor);
            st.probe_climbing = false;
            st.last_probe_goodput = goodput;
            st.last_probe_rate = st.rate_rps;
            if (before - st.rate_rps).abs() > f64::EPSILON {
                tracing::warn!(
                    event = "goodput_hard_ceiling_hit",
                    credential_id = ?self.credential_id,
                    throttle_rate = throttle_rate,
                    ceiling = self.cfg.goodput_hard_ceiling,
                    "429 超硬上限，强制降速（可能的升级惩罚信号）"
                );
                self.notify.notify_waiters();
                return true;
            }
            return false;
        }

        // 门 3：app-limited——在飞远低于并发上限，没 backlog → 没活干，不是到顶（P2-c）。
        // 判据：当前在飞 + 1 < effective_max_inflight（还有空槽没被占满 = 需求不足）。
        // 两处修复：
        //  ① 去抖：瞬时 inflight 低只是「这一拍碰巧没排满」，不代表真没需求。连续
        //     `app_limited_debounce_ticks` 拍都判 app-limited 才真当 app-limited，
        //     防单拍抖动误判。未达阈值时不暂停，继续走下面正常的护栏带/爬升逻辑。
        //  ② 保留爬升状态：真进入 app-limited 时只记基线、**不清 probe_climbing**——
        //     这样需求恢复后从原档继续爬，而不是被打断后从头起步（旧 bug：每次空闲一拍就重置）。
        let app_limited_now = self.current_inflight() + 1 < st.effective_max_inflight;
        if app_limited_now {
            st.app_limited_streak = st.app_limited_streak.saturating_add(1);
        } else {
            st.app_limited_streak = 0;
        }
        if app_limited_now && st.app_limited_streak >= self.cfg.app_limited_debounce_ticks {
            // 连续多拍确认需求不足 → 记录基线但不动 rate、保留 probe_climbing（需求回来接着爬）。
            st.last_probe_goodput = goodput;
            st.last_probe_rate = st.rate_rps;
            return false;
        }

        // 门 4a：带上沿以上、硬上限以下 [band_high, hard_ceiling] → 偏热，轻微抑制：
        // 退一档让 429 回落进带内，但不像硬上限那样强降（区别于门 2）。
        if throttle_rate > self.cfg.goodput_band_high {
            st.rate_rps = (st.rate_rps - step).max(floor);
            st.probe_climbing = false;
            st.last_probe_goodput = goodput;
            st.last_probe_rate = st.rate_rps;
            let changed = (before - st.rate_rps).abs() > f64::EPSILON;
            if changed {
                self.notify.notify_waiters();
            }
            return changed;
        }
        // 门 4b：护栏带内 [band_low, band_high] → 贴着天花板的理想稳态，保持不动。
        if throttle_rate >= self.cfg.goodput_band_low {
            st.probe_climbing = false;
            st.last_probe_goodput = goodput;
            st.last_probe_rate = st.rate_rps;
            return false;
        }

        // 门 5：429 < band_low，确认还有余量 → 爬升。
        if step <= 0.0 || st.rate_rps >= sanity_max - f64::EPSILON {
            return false;
        }
        // 控制律（修正 P1）：低 429 = 上游确认有余量，这本身就是「可以探更高」的许可。
        // goodput-delta 只用来**否决**爬升——仅当上一拍抬了 rate 后 goodput 明显**回落**
        // （rate 升反而吞吐降，说明 429 在吃掉产能/过了最优点）才退档并停爬。
        //
        // 为什么不要求 goodput「必须上涨」才继续：稳态需求下 goodput = min(需求, rate)，
        // 抬 rate 不一定立刻让 goodput 涨（需求没那么多/backlog 已清），但只要 429 仍 < band_low
        // 且 goodput 没倒退，就说明没撞墙、继续贴墙探是安全的。要求「必须涨 5%」会在稳态需求下
        // 恒为 false → 抬一档又退一档的极限环（P1 根因）。
        if st.probe_climbing {
            // regressed：goodput 比上次探测时明显回落（跌破 1 - epsilon）= 抬过头了。
            let regressed =
                goodput < st.last_probe_goodput * (1.0 - self.cfg.goodput_rise_epsilon);
            if regressed {
                // 抬 rate 反而吞吐降 → 回退一档并停爬，停在上一个更优点。
                st.rate_rps = (st.rate_rps - step).max(floor);
                st.probe_climbing = false;
            } else {
                // 没回退 + 429 仍低 → 继续抬一档贴墙探。
                st.rate_rps = (st.rate_rps + step).min(sanity_max);
            }
        } else {
            // 起步爬升：抬一档，下一拍用 regressed 判据验证。
            st.rate_rps = (st.rate_rps + step).min(sanity_max);
            st.probe_climbing = true;
        }
        // 记录本拍 goodput 高水位：只在 goodput 创新高时更新基线，避免「需求抖动暂时低一下」
        // 被误判成 regressed（基线一直跟着最高吞吐走，回退判定更稳）。
        if goodput > st.last_probe_goodput {
            st.last_probe_goodput = goodput;
        }
        st.last_probe_rate = st.rate_rps;
        st.last_increase = now;
        let changed = (before - st.rate_rps).abs() > f64::EPSILON;
        if changed {
            self.notify.notify_waiters();
        }
        changed
    }

    pub fn observe_full(&self) -> LimiterObservation {
        let mut st = self.state.lock();
        let (state, reason, reopen_ms) = Self::circuit_snapshot(&self.cfg, &mut st);
        let (safe_lo, safe_hi) = self
            .credential_id
            .and_then(|id| {
                self.learning
                    .as_ref()
                    .map(|s| normalize_learned_bounds(s.learned_safe_rps(id)))
            })
            .unwrap_or((0.5, 1.0));
        let p80 = self
            .credential_id
            .and_then(|id| self.learning.as_ref().map(|s| s.p80_held_ms(id)))
            .unwrap_or(30_000);
        let bottleneck = self
            .credential_id
            .and_then(|id| self.learning.as_ref().map(|s| s.bottleneck(id)))
            .unwrap_or(BottleneckDimension::SendRate);
        let optimal_t = self
            .credential_id
            .and_then(|id| {
                self.learning.as_ref().map(|s| {
                    s.optimal_quarantine(id, self.cfg.initial_quarantine.as_secs())
                        .as_secs()
                })
            })
            .unwrap_or(self.cfg.initial_quarantine.as_secs());
        LimiterObservation {
            state,
            state_reason: reason,
            reopen_in_ms: reopen_ms,
            current_max_inflight: st.effective_max_inflight,
            current_inflight: self.cfg.hard_max_inflight - self.inflight.available_permits(),
            current_rate_rps: st.rate_rps,
            effective_rate_floor_rps: self.effective_rate_floor(),
            learned_safe_rps_lo: safe_lo,
            learned_safe_rps_hi: safe_hi,
            p80_held_ms: p80,
            learned_optimal_t_secs: optimal_t,
            bottleneck_dimension: bottleneck,
            upstream_429_rate_5m: rate_429_locked(&st.upstream_events, self.cfg.probe_window),
            consecutive_throttles: st.consecutive_throttles,
            cooldown_remaining_ms: Self::cooldown_remaining_from_state(&st).as_millis() as u64,
            recovery_eligible: Self::recovery_eligible_locked(&self.cfg, &st),
            goodput_rps: goodput_rps_locked(&st.goodput_events, self.cfg.probe_window),
            app_limited: (self.cfg.hard_max_inflight - self.inflight.available_permits()) + 1
                < st.effective_max_inflight,
            adaptive_beta: st.adaptive_beta,
        }
    }

    fn account_state_from_circuit(
        &self,
        circuit: &CircuitState,
    ) -> (AccountState, String, u64) {
        let now = Instant::now();
        match circuit {
            CircuitState::Healthy => (AccountState::Healthy, String::new(), 0),
            CircuitState::Open { until, reason } => {
                let ms = if *until > now {
                    (*until - now).as_millis() as u64
                } else {
                    0
                };
                (AccountState::Open, reason.clone(), ms)
            }
            CircuitState::HalfOpen { .. } => (AccountState::HalfOpen, "canary_probe".into(), 0),
        }
    }

    fn transition_circuit(
        &self,
        st: &mut State,
        to: CircuitState,
        from_label: &str,
        reason: &str,
    ) {
        let to_label = match &to {
            CircuitState::Healthy => "HEALTHY",
            CircuitState::Open { .. } => "OPEN",
            CircuitState::HalfOpen { .. } => "HALF_OPEN",
        };
        if from_label != to_label {
            tracing::info!(
                event = "account_state_change",
                credential_id = ?self.credential_id,
                from = from_label,
                to = to_label,
                reason = reason,
            );
        }
        st.circuit = to;
    }

    fn circuit_label(st: &State) -> &'static str {
        match st.circuit {
            CircuitState::Healthy => "HEALTHY",
            CircuitState::Open { .. } => "OPEN",
            CircuitState::HalfOpen { .. } => "HALF_OPEN",
        }
    }

    fn maybe_advance_circuit(cfg: &AdaptiveConfig, st: &mut State) {
        let now = Instant::now();
        if let CircuitState::Open { until, .. } = &st.circuit {
            if now >= *until {
                st.circuit = CircuitState::HalfOpen {
                    canary_in_flight: false,
                    successes: 0,
                    entered_at: now,
                };
            }
        } else if let CircuitState::HalfOpen {
            canary_in_flight,
            entered_at,
            ..
        } = &mut st.circuit
        {
            // 超时自愈：HalfOpen 停留过久（多半是 canary 被取消/漏调清理而泄漏，
            // 或探测请求长期未回）→ 强制清 canary，让下一次 acquire 能重新放探测请求。
            // 这是 HalfOpenCanaryGuard（RAII）之外的第二层兜底，确保即使 RAII 失效
            // 也不会让账号永久卡在 HalfOpen。
            if *canary_in_flight && now.duration_since(*entered_at) >= cfg.half_open_max {
                *canary_in_flight = false;
                *entered_at = now;
                tracing::warn!(
                    event = "half_open_canary_timeout",
                    "HalfOpen canary 探测超时，强制清 canary 重新探测"
                );
            }
        }
    }

    pub fn acquire_shadow(&self) -> AcquireOutcome {
        let mut st = self.state.lock();
        Self::refill_locked(&self.cfg, &mut st);
        let now = Instant::now();
        let cd = st
            .cooldown_until
            .filter(|t| *t > now)
            .map(|t| (t - now).as_millis() as u64)
            .unwrap_or(0);
        let token_wait = if st.tokens >= 1.0 {
            0
        } else {
            ((1.0 - st.tokens) / st.rate_rps.max(self.cfg.absolute_min_rate_rps) * 1000.0) as u64
        };
        AcquireOutcome::ShadowProceed {
            would_wait_ms: cd.max(token_wait),
            would_rps: st.rate_rps,
        }
    }

    pub async fn acquire(self: &Arc<Self>) -> AcquireOutcome {
        if !self.cfg.enforce {
            return self.acquire_shadow();
        }

        // RAII canary 守卫：一旦某次决策把 HalfOpen canary 置 true，就用这个守卫接管它。
        // 只有把 permit 成功交还给调用方（Proceed）时才 disarm（此后由 provider 侧的
        // LimiterAttemptGuard + on_success/on_throttle/on_acquire_aborted 接管清理）。
        // 其余任何出口——LocalThrottled 返回、或 acquire future 在 await 点被取消而整体 drop
        // ——守卫 drop 都会无条件把 canary 清回 false，从结构上根治「canary 泄漏卡死」。
        let mut canary_guard: Option<CanaryGuard> = None;

        loop {
            if let Some(out) = self.try_acquire_decision() {
                match out {
                    AcquireDecision::Return(o) => return o,
                    AcquireDecision::WaitInflight => {
                        tokio::select! {
                            _ = sleep(Duration::from_millis(50)) => {}
                            _ = self.notify.notified() => {}
                        }
                        continue;
                    }
                    AcquireDecision::ProceedToPermit { claimed_canary } => {
                        if claimed_canary {
                            canary_guard = Some(CanaryGuard::new(Arc::clone(self)));
                        }
                        break;
                    }
                }
            }
        }

        let raw_permit = self
            .inflight
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed");
        let mut permit = LimiterPermit::new(Arc::clone(self), raw_permit);

        let absorb_deadline = Instant::now() + self.cfg.max_absorb_wait;
        let mut slice_deadline = Instant::now() + self.cfg.local_queue_timeout;
        loop {
            let wait = {
                let mut st = self.state.lock();
                Self::refill_locked(&self.cfg, &mut st);
                let now = Instant::now();

                if let Some(until) = st.cooldown_until {
                    if until > now {
                        Some((until - now, st.rate_rps))
                    } else {
                        st.cooldown_until = None;
                        None
                    }
                } else if st.tokens >= 1.0 {
                    st.tokens -= 1.0;
                    self.note_send();
                    permit.mark_request_started();
                    // 成功放行：把 canary 清理责任交给调用方（provider LimiterAttemptGuard +
                    // on_success/on_throttle/on_acquire_aborted），disarm 本地守卫避免重复清。
                    if let Some(g) = canary_guard.as_mut() {
                        g.disarm();
                    }
                    return AcquireOutcome::Proceed(permit);
                } else {
                    let missing = 1.0 - st.tokens;
                    let secs = missing
                        / st.rate_rps.max(self.cfg.absolute_min_rate_rps);
                    Some((Duration::from_secs_f64(secs), st.rate_rps))
                }
            };

            let (wait_dur, current_rps) = match wait {
                Some(w) => w,
                None => continue,
            };

            let now = Instant::now();
            if now + wait_dur > slice_deadline {
                if now < absorb_deadline {
                    let capped = wait_dur.min(absorb_deadline.saturating_duration_since(now));
                    let wait_dur = add_small_jitter(capped);
                    tokio::select! {
                        _ = sleep(wait_dur) => {}
                        _ = self.notify.notified() => {}
                    }
                    slice_deadline = Instant::now() + self.cfg.local_queue_timeout;
                    continue;
                }
                let at_effective_floor =
                    current_rps <= self.effective_rate_floor() + f64::EPSILON;
                let upstream_hot =
                    self.upstream_429_rate() > self.cfg.probe_budget_high;
                let est_wait_ms = wait_dur.as_millis() as u64;
                drop(permit);
                self.clear_half_open_canary();
                return AcquireOutcome::LocalThrottled {
                    est_wait_ms,
                    current_rps,
                    reason: if at_effective_floor && upstream_hot {
                        "upstream_throttle_storm"
                    } else {
                        "absorb_timeout"
                    },
                };
            }

            let wait_dur = add_small_jitter(wait_dur);
            tokio::select! {
                _ = sleep(wait_dur) => {}
                _ = self.notify.notified() => {}
            }
        }
    }

    fn try_acquire_decision(&self) -> Option<AcquireDecision> {
        let mut st = self.state.lock();
        Self::maybe_advance_circuit(&self.cfg, &mut st);
        if let CircuitState::Open { until, .. } = st.circuit {
            let now = Instant::now();
            if now < until {
                return Some(AcquireDecision::Return(AcquireOutcome::LocalThrottled {
                    est_wait_ms: (until - now).as_millis() as u64,
                    current_rps: 0.0,
                    reason: "account_open",
                }));
            }
        }
        let half_open_needs_canary = matches!(st.circuit, CircuitState::HalfOpen { .. });
        if let CircuitState::HalfOpen { canary_in_flight, .. } = &st.circuit {
            if *canary_in_flight {
                return Some(AcquireDecision::Return(AcquireOutcome::LocalThrottled {
                    est_wait_ms: 500,
                    current_rps: 0.0,
                    reason: "account_open",
                }));
            }
        }
        let in_flight = self.cfg.hard_max_inflight - self.inflight.available_permits();
        if in_flight >= st.effective_max_inflight {
            return Some(AcquireDecision::WaitInflight);
        }
        if half_open_needs_canary {
            if let CircuitState::HalfOpen { canary_in_flight, .. } = &mut st.circuit {
                *canary_in_flight = true;
            }
            return Some(AcquireDecision::ProceedToPermit {
                claimed_canary: true,
            });
        }
        Some(AcquireDecision::ProceedToPermit {
            claimed_canary: false,
        })
    }

    fn clear_half_open_canary(&self) {
        let mut st = self.state.lock();
        if let CircuitState::HalfOpen { canary_in_flight, .. } = &mut st.circuit {
            *canary_in_flight = false;
        }
    }

    /// Permit 释放且未走 on_success/on_throttle（网络错误、5xx 等）时清 HALF_OPEN canary。
    pub fn on_acquire_aborted(&self) {
        self.clear_half_open_canary();
    }

    fn note_send(&self) {
        let now = Instant::now();
        let mut q = self.sends_counter.lock();
        q.push_back(now);
        while q.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(1)) {
            q.pop_front();
        }
    }

    fn sends_last_1s(&self) -> u32 {
        let now = Instant::now();
        let q = self.sends_counter.lock();
        q.iter()
            .filter(|t| now.duration_since(**t) <= Duration::from_secs(1))
            .count() as u32
    }

    pub async fn on_success(&self, rpm_last_60s: usize) {
        let mut st = self.state.lock();
        Self::refill_locked(&self.cfg, &mut st);
        st.consecutive_throttles = 0;
        st.consecutive_user_429 = 0;
        st.successes_since_increase += 1;
        record_upstream(&mut st.upstream_events, false, self.cfg.probe_window);
        // goodput 测量：每次成功完成记一个样本。rate 的升降统一由 goodput_control_tick
        // 驱动（见该函数），on_success 不再直接 AIMD 抬升 rate——目标函数从「429 最低」
        // 改成「goodput 最大」，这是本控制器的核心。
        record_goodput(&mut st.goodput_events, self.cfg.probe_window);

        let from = Self::circuit_label(&st);
        if let CircuitState::HalfOpen { canary_in_flight, successes, .. } = &mut st.circuit {
            *canary_in_flight = false;
            *successes += 1;
            if *successes >= self.cfg.half_open_success_target {
                self.transition_circuit(&mut st, CircuitState::Healthy, from, "half_open_successes");
                if let (Some(id), Some(store)) = (self.credential_id, &self.learning) {
                    store.on_quarantine_probe_stable(id, self.cfg.min_quarantine.as_secs());
                }
            }
        }

        self.record_learning_sample(SendContextSample {
            inflight: self.current_inflight(),
            sends_last_1s: self.sends_last_1s(),
            rpm_last_60s,
            send_rate_rps: st.rate_rps,
            was_429: false,
        });

        self.recompute_effective_inflight(&mut st);
    }

    pub async fn on_throttle(
        &self,
        reason: ThrottleReason,
        retry_after: Option<Duration>,
        rpm_last_60s: usize,
    ) {
        let mut st = self.state.lock();
        Self::refill_locked(&self.cfg, &mut st);
        let now = Instant::now();
        st.consecutive_throttles = st.consecutive_throttles.saturating_add(1);
        st.successes_since_increase = 0;
        record_upstream(&mut st.upstream_events, true, self.cfg.probe_window);

        if matches!(reason, ThrottleReason::UserRate | ThrottleReason::ServiceRate) {
            st.consecutive_user_429 = st.consecutive_user_429.saturating_add(1);
        }

        self.record_learning_sample(SendContextSample {
            inflight: self.current_inflight(),
            sends_last_1s: self.sends_last_1s(),
            rpm_last_60s,
            send_rate_rps: st.rate_rps,
            was_429: true,
        });

        let at_min = st.rate_rps <= self.effective_rate_floor() + f64::EPSILON;
        let should_open = self.cfg.circuit_breaker_enabled
            && (matches!(reason, ThrottleReason::Suspicious)
                || (at_min && matches!(reason, ThrottleReason::UserRate | ThrottleReason::ServiceRate | ThrottleReason::Unknown))
                || st.consecutive_user_429 >= self.cfg.open_429_threshold);

        let from = Self::circuit_label(&st);
        if should_open {
            let quarantine = self.quarantine_duration();
            let until = now + quarantine;
            self.transition_circuit(
                &mut st,
                CircuitState::Open {
                    until,
                    reason: format!("{reason:?}"),
                },
                from,
                "circuit_open",
            );
            st.tokens = 0.0;
            st.rate_rps = self.effective_rate_floor();
            self.notify.notify_waiters();
            return;
        }

        if let CircuitState::HalfOpen { canary_in_flight, .. } = &mut st.circuit {
            *canary_in_flight = false;
            let quarantine = self.quarantine_duration();
            if let (Some(id), Some(store)) = (self.credential_id, &self.learning) {
                store.on_quarantine_probe_failed(id, self.cfg.max_quarantine.as_secs());
            }
            self.transition_circuit(
                &mut st,
                CircuitState::Open {
                    until: now + quarantine,
                    reason: "half_open_canary_429".into(),
                },
                from,
                "canary_failed",
            );
            st.tokens = 0.0;
            self.notify.notify_waiters();
            return;
        }

        // 自适应退避：beta(乘性减速系数)随「上次退避后多快又撞 429」学习。
        // - 退避后很快(< probe_window/4)又 429 → 上次退得不够狠 → beta 调小(降更狠)。
        // - 距上次退避很久(> probe_window)才 429 → 上次退过头了 → beta 调大(降更温柔)。
        // beta 夹在 [beta_user×0.5, 0.9] 之间，避免学飞。Suspicious 仍用固定狠降 0.1。
        let beta = match reason {
            ThrottleReason::Suspicious => 0.1,
            _ => {
                let beta_min = (self.cfg.beta_user * 0.5).clamp(0.05, 0.9);
                let beta_max = 0.9_f64;
                if let Some(last) = st.last_backoff_at {
                    let since = now.duration_since(last);
                    if since < self.cfg.probe_window / 4 {
                        // 退避后很快又撞 → 退更狠。
                        st.adaptive_beta = (st.adaptive_beta * 0.8).max(beta_min);
                    } else if since > self.cfg.probe_window {
                        // 隔了很久才撞，上次退过头 → 退更温柔。
                        st.adaptive_beta = (st.adaptive_beta * 1.1).min(beta_max);
                    }
                    // 中间区间：保持当前 adaptive_beta 不变。
                } else {
                    st.adaptive_beta = self.cfg.beta_user.clamp(beta_min, beta_max);
                }
                st.adaptive_beta
            }
        };
        st.last_backoff_at = Some(now);
        st.rate_rps = (st.rate_rps * beta).max(self.effective_rate_floor());

        if self.cfg.adaptive_concurrency_enabled {
            let new_eff = ((st.effective_max_inflight as f64) * self.cfg.shrink_factor)
                .round() as usize;
            st.effective_max_inflight = new_eff
                .max(self.cfg.min_inflight)
                .min(self.cfg.hard_max_inflight);
        }

        st.tokens = 0.0;

        let local_cd = exp_cooldown(
            self.cfg.user_cooldown_base,
            self.cfg.cooldown_cap,
            st.consecutive_throttles,
        );
        let cooldown = retry_after
            .map(|d| d.min(self.cfg.cooldown_cap))
            .unwrap_or(local_cd)
            .min(self.cfg.local_queue_timeout);
        let until = now + cooldown;
        st.cooldown_until = Some(match st.cooldown_until {
            Some(old) if old > until => old,
            _ => until,
        });
        self.notify.notify_waiters();
    }

    fn quarantine_duration(&self) -> Duration {
        if let (Some(id), Some(store)) = (self.credential_id, &self.learning) {
            store.optimal_quarantine(id, self.cfg.initial_quarantine.as_secs())
        } else {
            self.cfg.initial_quarantine
        }
        .max(self.cfg.min_quarantine)
        .min(self.cfg.max_quarantine)
    }

    fn recompute_effective_inflight(&self, st: &mut State) {
        if !self.cfg.adaptive_concurrency_enabled {
            return;
        }
        let (safe_rps, _) = self
            .credential_id
            .and_then(|id| {
                self.learning.as_ref().and_then(|s| {
                    if !s.learning_is_mature(id, self.cfg.learning_min_samples_for_floor) {
                        return None;
                    }
                    let (lo, hi) = normalize_learned_bounds(s.learned_safe_rps(id));
                    Some(((lo + hi) / 2.0, hi))
                })
            })
            .unwrap_or((st.rate_rps, st.rate_rps));
        let p80_ms = self
            .credential_id
            .and_then(|id| self.learning.as_ref().map(|s| s.p80_held_ms(id)))
            .unwrap_or(30_000) as f64;
        let p80_secs = (p80_ms / 1000.0).max(0.1);
        let desired = (safe_rps * p80_secs * self.cfg.safety_factor).ceil() as usize;
        let clamped = desired
            .clamp(self.cfg.min_inflight, self.cfg.hard_max_inflight);
        let old = st.effective_max_inflight;
        let new_eff = if clamped > old {
            ((old as f64) * self.cfg.grow_factor).round() as usize
        } else if clamped < old {
            ((old as f64) * self.cfg.shrink_factor).round() as usize
        } else {
            old
        };
        st.effective_max_inflight = new_eff.clamp(self.cfg.min_inflight, self.cfg.hard_max_inflight);
    }

    fn record_learning_sample(&self, sample: SendContextSample) {
        if !self.cfg.learning_enabled {
            return;
        }
        if let (Some(id), Some(store)) = (self.credential_id, &self.learning) {
            store.record_sample(id, sample);
        }
    }

    pub fn record_held_duration(&self, held_ms: u64) {
        if !self.cfg.learning_enabled {
            return;
        }
        if let (Some(id), Some(store)) = (self.credential_id, &self.learning) {
            store.record_held_ms(id, held_ms);
            let mut st = self.state.lock();
            self.recompute_effective_inflight(&mut st);
        }
    }

    fn refill_locked(cfg: &AdaptiveConfig, st: &mut State) {
        let now = Instant::now();
        let elapsed = now.duration_since(st.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            st.tokens = (st.tokens + elapsed * st.rate_rps).min(cfg.burst);
            st.last_refill = now;
        }
    }

    pub fn headroom(&self) -> isize {
        let st = self.state.lock();
        st.effective_max_inflight as isize - self.current_inflight() as isize
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LimiterObservation {
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
    pub bottleneck_dimension: BottleneckDimension,
    pub upstream_429_rate_5m: f64,
    pub consecutive_throttles: u32,
    pub cooldown_remaining_ms: u64,
    /// 是否满足恢复探测条件(最近窗口干净、电路健康、可向上恢复速率)——观测指标。
    pub recovery_eligible: bool,
    /// goodput 控制器：窗口内成功请求/秒（真吞吐，控制器的优化目标）。
    pub goodput_rps: f64,
    /// goodput 控制器：当前是否 app-limited（在飞低于并发上限=没活干，非到顶）。
    pub app_limited: bool,
    /// 自适应退避当前学到的 beta（乘性减速系数）。
    pub adaptive_beta: f64,
}

fn record_upstream(events: &mut VecDeque<(Instant, bool)>, was_429: bool, window: Duration) {
    let now = Instant::now();
    events.push_back((now, was_429));
    while events
        .front()
        .is_some_and(|(t, _)| now.duration_since(*t) > window)
    {
        events.pop_front();
    }
}

fn rate_429_locked(events: &VecDeque<(Instant, bool)>, window: Duration) -> f64 {
    let now = Instant::now();
    let relevant: Vec<_> = events
        .iter()
        .filter(|(t, _)| now.duration_since(*t) <= window)
        .collect();
    if relevant.is_empty() {
        return 0.0;
    }
    let throttled = relevant.iter().filter(|(_, r)| *r).count();
    throttled as f64 / relevant.len() as f64
}

/// 记录一次成功完成（goodput 样本），并淘汰窗口外旧样本。
fn record_goodput(events: &mut VecDeque<Instant>, window: Duration) {
    let now = Instant::now();
    events.push_back(now);
    while events
        .front()
        .is_some_and(|t| now.duration_since(*t) > window)
    {
        events.pop_front();
    }
}

/// 计算窗口内 goodput（成功请求/秒）= 窗口内成功数 / 窗口长度（秒）。
/// 用「成功数 / 窗口秒数」而非「/ 样本时间跨度」，避免低样本时分母过小放大噪声。
/// 估算「当前」goodput（成功请求/秒）。
///
/// 关键：分母用窗口内样本的**实际时间跨度**(最新−最旧)，而不是固定 window 长度。
/// 若用固定 300s 当分母，goodput 就成了「过去 5 分钟平均」这种慢变量——每 15s 一次的
/// 控制 tick 根本无法在一拍里把它抬高一个可检测的相对增幅，爬山判据(rose)会恒为 false，
/// 退化成「抬一档→判没涨→退一档」的极限环(P1)。用实际跨度则反映**最近真实速率**，
/// rate 一升、单位时间成功数随之升，goodput 能同步跟上，爬山判据才有意义。
///
/// 边界：窗口内样本 < 2 或跨度过小（< 1s）时无法可靠估速，返回 count/window 的保守平均
/// （避免极小分母把 goodput 放大成噪声）。
fn goodput_rps_locked(events: &VecDeque<Instant>, window: Duration) -> f64 {
    let now = Instant::now();
    let recent: Vec<Instant> = events
        .iter()
        .filter(|t| now.duration_since(**t) <= window)
        .copied()
        .collect();
    let count = recent.len();
    if count < 2 {
        // 样本太少，无法测速率：用 count/window 的保守平均（低估而非高估，不制造噪声）。
        return count as f64 / window.as_secs_f64().max(1.0);
    }
    // 实际跨度 = 最新样本到「现在」的时间（含正在累积的当前区间），下限 1s 防极小分母放大。
    let oldest = recent.iter().min().copied().unwrap_or(now);
    let span = now.duration_since(oldest).as_secs_f64().max(1.0);
    count as f64 / span
}

fn exp_cooldown(base: Duration, cap: Duration, n: u32) -> Duration {
    let pow = 2u32.saturating_pow(n.saturating_sub(1).min(6));
    let raw = base.saturating_mul(pow).min(cap);
    add_small_jitter(raw)
}

fn add_small_jitter(d: Duration) -> Duration {
    let millis = d.as_millis() as u64;
    if millis == 0 {
        return d;
    }
    let spread = (millis / 5).max(1);
    let delta = fastrand::u64(0..=spread * 2) as i64 - spread as i64;
    let jittered = (millis as i64 + delta).max(1) as u64;
    Duration::from_millis(jittered)
}

/// 多 scope limiter 容器。
pub struct LimiterRegistry {
    cfg: AdaptiveConfig,
    map: Mutex<HashMap<String, Arc<AdaptiveLimiter>>>,
    learning: Option<Arc<LearningStore>>,
}

impl LimiterRegistry {
    pub fn new(cfg: AdaptiveConfig, learning: Option<Arc<LearningStore>>) -> Self {
        Self {
            cfg,
            map: Mutex::new(HashMap::new()),
            learning,
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn learning(&self) -> Option<Arc<LearningStore>> {
        self.learning.clone()
    }

    pub fn for_scope(&self, scope: &ThrottleScope) -> Arc<AdaptiveLimiter> {
        let key = scope.key();
        let mut map = self.map.lock();
        if let Some(l) = map.get(&key) {
            return l.clone();
        }
        let cred = scope.credential_id();
        let limiter = AdaptiveLimiter::new_with_context(
            self.cfg.clone(),
            cred,
            self.learning.clone(),
        );
        map.insert(key, limiter.clone());
        limiter
    }

    pub fn cooldown_remaining(&self, scope: &ThrottleScope) -> Duration {
        let key = scope.key();
        let map = self.map.lock();
        match map.get(&key) {
            Some(l) => l.cooldown_remaining(),
            None => Duration::ZERO,
        }
    }

    pub fn is_account_open(&self, scope: &ThrottleScope) -> bool {
        let key = scope.key();
        let map = self.map.lock();
        map.get(&key).is_some_and(|l| l.is_open())
    }

    pub fn observe(&self, scope: &ThrottleScope) -> Option<(f64, Duration)> {
        let key = scope.key();
        let map = self.map.lock();
        map.get(&key)
            .map(|l| (l.current_rate_rps(), l.cooldown_remaining()))
    }

    pub fn observe_full(&self, scope: &ThrottleScope) -> Option<LimiterObservation> {
        let key = scope.key();
        let map = self.map.lock();
        map.get(&key).map(|l| l.observe_full())
    }

    /// 对所有 scope 跑一次 goodput 控制器 tick(后台周期调用)。返回实际改动 rate 的 scope 数量。
    pub fn recovery_probe_tick_all(&self) -> usize {
        let limiters: Vec<Arc<AdaptiveLimiter>> = self.map.lock().values().cloned().collect();
        limiters.iter().filter(|l| l.goodput_control_tick()).count()
    }

    pub fn global_upstream_429_rate(&self) -> f64 {
        let map = self.map.lock();
        let mut events: VecDeque<(Instant, bool)> = VecDeque::new();
        for lim in map.values() {
            let st = lim.state.lock();
            for e in &st.upstream_events {
                events.push_back(*e);
            }
        }
        rate_429_locked(&events, self.cfg.probe_window)
    }

    pub fn account_state_counts(&self) -> HashMap<AccountState, usize> {
        let map = self.map.lock();
        let mut counts = HashMap::new();
        for lim in map.values() {
            let (s, _, _) = lim.account_state();
            *counts.entry(s).or_insert(0) += 1;
        }
        counts
    }
}

#[cfg(test)]
impl AdaptiveLimiter {
    async fn test_acquire_unmarked_permit(self: &Arc<Self>) -> LimiterPermit {
        let raw = self
            .inflight
            .clone()
            .acquire_owned()
            .await
            .expect("inflight semaphore open");
        LimiterPermit::new(Arc::clone(self), raw)
    }

    fn test_notify(&self) -> &Notify {
        &self.notify
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> AdaptiveConfig {
        AdaptiveConfig {
            enabled: true,
            enforce: true,
            initial_rate_rps: 1.0,
            min_rate_rps: 0.1,
            absolute_min_rate_rps: 0.02,
            learned_floor_factor: 0.8,
            learning_min_samples_for_floor: 20,
            max_absorb_wait: Duration::from_secs(120),
            max_rate_rps: 2.0,
            burst: 1.0,
            hard_max_inflight: 8,
            min_inflight: 2,
            additive_step_rps: 0.5,
            increase_interval: Duration::from_millis(0),
            successes_per_increase: 1,
            beta_user: 0.5,
            user_cooldown_base: Duration::from_secs(2),
            cooldown_cap: Duration::from_secs(60),
            local_queue_timeout: Duration::from_secs(90),
            circuit_breaker_enabled: true,
            open_429_threshold: 3,
            half_open_success_target: 2,
            initial_quarantine: Duration::from_secs(1),
            min_quarantine: Duration::from_millis(100),
            max_quarantine: Duration::from_secs(60),
            half_open_max: Duration::from_secs(120),
            adaptive_concurrency_enabled: true,
            safety_factor: 0.8,
            grow_factor: 1.25,
            shrink_factor: 0.5,
            probe_budget_low: 0.01,
            probe_budget_high: 0.02,
            probe_window: Duration::from_secs(300),
            goodput_band_low: 0.02,
            goodput_band_high: 0.08,
            goodput_hard_ceiling: 0.15,
            goodput_sanity_max_rps: 5.0,
            goodput_rise_epsilon: 0.05,
            app_limited_debounce_ticks: 2,
            learning_enabled: false,
        }
    }

    #[tokio::test]
    async fn test_consecutive_429_opens_account() {
        let lim = AdaptiveLimiter::new(test_cfg());
        for _ in 0..3 {
            lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        }
        match lim.acquire().await {
            AcquireOutcome::LocalThrottled { reason, .. } if reason == "account_open" => {}
            other => panic!("第4次 acquire 应 account_open LocalThrottled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_open_zero_traffic_no_permit() {
        let lim = AdaptiveLimiter::new(test_cfg());
        for _ in 0..3 {
            lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        }
        assert_eq!(lim.current_inflight(), 0);
    }

    #[tokio::test]
    async fn test_half_open_canary_recovery() {
        let mut cfg = test_cfg();
        cfg.initial_quarantine = Duration::from_millis(50);
        cfg.min_quarantine = Duration::from_millis(50);
        cfg.half_open_success_target = 2;
        let lim = AdaptiveLimiter::new(cfg);
        for _ in 0..3 {
            lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        match lim.acquire().await {
            AcquireOutcome::Proceed(_) => {}
            other => panic!("HALF_OPEN canary 应 Proceed, got {other:?}"),
        }
        lim.on_success(0).await;
        lim.on_success(0).await;
        assert_eq!(lim.account_state().0, AccountState::Healthy);
    }

    #[tokio::test]
    async fn test_half_open_canary_429_reopens() {
        let mut cfg = test_cfg();
        cfg.initial_quarantine = Duration::from_millis(50);
        cfg.min_quarantine = Duration::from_millis(50);
        let lim = AdaptiveLimiter::new(cfg);
        for _ in 0..3 {
            lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
        let _ = lim.acquire().await;
        lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        assert_eq!(lim.account_state().0, AccountState::Open);
    }

    #[tokio::test]
    async fn test_effective_inflight_clamped() {
        let cfg = test_cfg();
        let lim = AdaptiveLimiter::new(cfg.clone());
        {
            let mut st = lim.state.lock();
            st.effective_max_inflight = 100;
        }
        lim.on_success(0).await;
        assert!(lim.current_max_inflight() <= cfg.hard_max_inflight);
        assert!(lim.current_max_inflight() >= cfg.min_inflight);
    }

    #[tokio::test]
    async fn test_on_success_does_not_directly_climb_rate() {
        // 新语义：on_success 只记 goodput 样本，不再直接抬 rate（抬升交给 goodput 控制器 tick）。
        let lim = AdaptiveLimiter::new(test_cfg());
        let before = lim.current_rate_rps();
        lim.on_success(0).await;
        assert!(
            (lim.current_rate_rps() - before).abs() < 1e-9,
            "on_success 不应直接改 rate（goodput 控制器统一负责升降）"
        );
    }

    #[tokio::test]
    async fn test_token_bucket_gates_second_request() {
        let lim = AdaptiveLimiter::new(test_cfg());
        match lim.acquire().await {
            AcquireOutcome::Proceed(_) => {}
            other => panic!("第1个应 Proceed, got {other:?}"),
        }
        let r = tokio::time::timeout(Duration::from_millis(500), lim.acquire()).await;
        assert!(r.is_err(), "第2个不该在 0.5s 内拿到");
    }

    #[tokio::test]
    async fn test_on_throttle_halves_rate_and_cools_down() {
        let mut cfg = test_cfg();
        cfg.open_429_threshold = 100;
        let lim = AdaptiveLimiter::new(cfg);
        let before = lim.current_rate_rps();
        lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        let after = lim.current_rate_rps();
        assert!((after - before * 0.5).abs() < 1e-9);
        assert!(lim.cooldown_remaining() > Duration::ZERO);
    }

    #[tokio::test]
    async fn test_absorb_timeout_after_max_wait() {
        let mut cfg = test_cfg();
        cfg.local_queue_timeout = Duration::from_millis(50);
        cfg.max_absorb_wait = Duration::from_millis(120);
        cfg.open_429_threshold = 100;
        let lim = AdaptiveLimiter::new(cfg);
        match lim.acquire().await {
            AcquireOutcome::Proceed(_) => {}
            other => panic!("第1个应 Proceed, got {other:?}"),
        }
        match lim.acquire().await {
            AcquireOutcome::LocalThrottled { reason, .. } => {
                assert_eq!(reason, "absorb_timeout");
            }
            other => panic!("应 LocalThrottled absorb_timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_single_429_does_not_activate_learned_floor() {
        use crate::kiro::account_learning::{LearningStore, SendContextSample};
        use crate::model::config::LearningConfig;

        let learning = LearningStore::new(LearningConfig::default(), None);
        learning.record_sample(
            99,
            SendContextSample {
                inflight: 1,
                sends_last_1s: 1,
                rpm_last_60s: 1,
                send_rate_rps: 0.1,
                was_429: true,
            },
        );
        let mut cfg = test_cfg();
        cfg.min_rate_rps = 0.1;
        cfg.learning_min_samples_for_floor = 20;
        let lim = AdaptiveLimiter::new_with_context(cfg, Some(99), Some(learning));
        let floor = lim.observe_full().effective_rate_floor_rps;
        assert!(
            (floor - 0.1).abs() < 1e-9,
            "single 429 must not drop floor below min_rate_rps, got {floor}"
        );
    }

    #[tokio::test]
    async fn test_immature_learning_falls_back_to_min_rate_floor() {
        let mut cfg = test_cfg();
        cfg.min_rate_rps = 0.1;
        cfg.learning_min_samples_for_floor = 20;
        let learning = learning_store_with(66, 0.5, 1.0);
        let lim = AdaptiveLimiter::new_with_context(cfg, Some(66), Some(learning));
        let floor = lim.observe_full().effective_rate_floor_rps;
        assert!((floor - 0.1).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_fail_aloud_storm_when_at_floor_with_upstream_429() {
        let mut cfg = test_cfg();
        cfg.local_queue_timeout = Duration::from_millis(50);
        cfg.max_absorb_wait = Duration::from_millis(120);
        cfg.initial_rate_rps = 0.1;
        cfg.open_429_threshold = 100;
        cfg.circuit_breaker_enabled = false;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.2;
        }
        lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        {
            let mut st = lim.state.lock();
            st.tokens = 1.0;
            st.cooldown_until = None;
        }
        match lim.acquire().await {
            AcquireOutcome::Proceed(_) => {}
            other => panic!("第1个应 Proceed, got {other:?}"),
        }
        match lim.acquire().await {
            AcquireOutcome::LocalThrottled { reason, .. } => {
                assert_eq!(reason, "upstream_throttle_storm");
            }
            other => panic!("应 LocalThrottled storm, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_learned_floor_waits_instead_of_fail_aloud() {
        let mut cfg = test_cfg();
        cfg.local_queue_timeout = Duration::from_millis(80);
        cfg.max_absorb_wait = Duration::from_secs(2);
        cfg.open_429_threshold = 100;
        cfg.min_rate_rps = 0.1;
        cfg.absolute_min_rate_rps = 0.02;
        cfg.learned_floor_factor = 0.8;
        let learning = learning_store_with(88, 0.05, 0.06);
        let lim = AdaptiveLimiter::new_with_context(cfg, Some(88), Some(learning));
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.04;
        }
        match lim.acquire().await {
            AcquireOutcome::Proceed(_) => {}
            other => panic!("第1个应 Proceed, got {other:?}"),
        }
        let r = tokio::time::timeout(Duration::from_millis(500), lim.acquire()).await;
        assert!(r.is_err(), "墙下慢速无上游429时应继续等 token，不 Fail Aloud");
    }

    #[tokio::test]
    async fn test_shadow_never_blocks() {
        let mut cfg = test_cfg();
        cfg.enforce = false;
        let lim = AdaptiveLimiter::new(cfg);
        for _ in 0..5 {
            match lim.acquire().await {
                AcquireOutcome::ShadowProceed { .. } => {}
                other => panic!("shadow 应 ShadowProceed, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_classify_reason() {
        assert_eq!(
            classify_throttle_reason(r#"{"reason":"USER_REQUEST_RATE_EXCEEDED"}"#),
            ThrottleReason::UserRate
        );
    }

    #[tokio::test]
    async fn test_acquire_future_is_send() {
        let lim = AdaptiveLimiter::new(test_cfg());
        tokio::spawn(async move {
            let _ = lim.acquire().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_observe_full_under_cooldown_does_not_deadlock() {
        let lim = AdaptiveLimiter::new(test_cfg());
        lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        let obs = lim.observe_full();
        assert!(obs.cooldown_remaining_ms > 0 || obs.consecutive_throttles > 0);
    }

    #[test]
    fn test_observe_full_concurrent_no_deadlock() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration as StdDuration;

        let lim = Arc::new(AdaptiveLimiter::new(test_cfg()));
        let start = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let lim = lim.clone();
                thread::spawn(move || {
                    for _ in 0..20 {
                        let _ = lim.observe_full();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("observe_full must not deadlock");
        }
        assert!(start.elapsed() < StdDuration::from_secs(2));
    }

    #[tokio::test]
    async fn test_half_open_does_not_set_canary_when_inflight_full() {
        let mut cfg = test_cfg();
        cfg.hard_max_inflight = 1;
        cfg.min_inflight = 1;
        let lim = AdaptiveLimiter::new(cfg);
        let _held = match lim.acquire().await {
            AcquireOutcome::Proceed(p) => p,
            other => panic!("expected Proceed, got {other:?}"),
        };
        {
            let mut st = lim.state.lock();
            st.circuit = CircuitState::HalfOpen {
                canary_in_flight: false,
                successes: 0,
                entered_at: Instant::now(),
            };
        }
        let r = tokio::time::timeout(Duration::from_millis(100), lim.acquire()).await;
        assert!(r.is_err(), "inflight full should wait, not return immediately");
        let st = lim.state.lock();
        match &st.circuit {
            CircuitState::HalfOpen { canary_in_flight, .. } => {
                assert!(!canary_in_flight, "canary must not be claimed while waiting on inflight");
            }
            other => panic!("expected HalfOpen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_expired_open_advances_to_half_open_on_read() {
        let mut cfg = test_cfg();
        cfg.initial_quarantine = Duration::from_millis(50);
        cfg.min_quarantine = Duration::from_millis(50);
        let lim = AdaptiveLimiter::new(cfg);
        for _ in 0..3 {
            lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        }
        assert_eq!(lim.account_state().0, AccountState::Open);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!lim.is_open(), "expired OPEN must not block selection as OPEN");
        assert_eq!(lim.account_state().0, AccountState::HalfOpen);
    }

    #[tokio::test]
    async fn test_on_acquire_aborted_clears_half_open_canary() {
        let lim = AdaptiveLimiter::new(test_cfg());
        {
            let mut st = lim.state.lock();
            st.circuit = CircuitState::HalfOpen {
                canary_in_flight: true,
                successes: 0,
                entered_at: Instant::now(),
            };
        }
        lim.on_acquire_aborted();
        match &lim.state.lock().circuit {
            CircuitState::HalfOpen { canary_in_flight, .. } => {
                assert!(!canary_in_flight, "aborted acquire must clear canary");
            }
            other => panic!("expected HalfOpen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_cancelled_acquire_clears_half_open_canary() {
        // P1 回归：HalfOpen 放行 canary 后，acquire() future 在 await 点被取消（客户端断连），
        // CanaryGuard drop 必须把 canary 清回 false，否则该号永久卡死在 HalfOpen。
        let mut cfg = test_cfg();
        cfg.initial_rate_rps = 0.001; // 极低 rate → token 桶要等很久 → acquire 卡在 absorb 循环 await
        cfg.burst = 1.0;
        let lim = AdaptiveLimiter::new(cfg);
        // 先消耗掉初始 burst token，确保下一次 acquire 必须在 token 等待处 await。
        match lim.acquire().await {
            AcquireOutcome::Proceed(p) => drop(p),
            other => panic!("warm-up acquire should Proceed, got {other:?}"),
        }
        {
            let mut st = lim.state.lock();
            st.circuit = CircuitState::HalfOpen {
                canary_in_flight: false,
                successes: 0,
                entered_at: Instant::now(),
            };
        }
        // acquire 会放行 canary（置 true）然后卡在 token 等待 await；timeout 取消它 → future drop。
        let r = tokio::time::timeout(Duration::from_millis(120), lim.acquire()).await;
        assert!(r.is_err(), "acquire should still be waiting on token bucket");
        // 关键断言：被取消后 canary 必须已清回 false（RAII 守卫生效）。
        match &lim.state.lock().circuit {
            CircuitState::HalfOpen { canary_in_flight, .. } => {
                assert!(
                    !canary_in_flight,
                    "cancelled acquire must clear canary via RAII guard (P1 fix)"
                );
            }
            other => panic!("expected HalfOpen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_half_open_canary_timeout_self_heals() {
        // P1 第二层兜底：即便 canary 因任何原因泄漏卡 true，HalfOpen 停留超过 half_open_max
        // 后，maybe_advance_circuit（被 account_state 触发）必须强制清 canary 重新探测。
        let mut cfg = test_cfg();
        cfg.half_open_max = Duration::from_millis(50);
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.circuit = CircuitState::HalfOpen {
                canary_in_flight: true,
                successes: 0,
                entered_at: Instant::now() - Duration::from_millis(200),
            };
        }
        // 触发 maybe_advance_circuit（account_state 内部会调）。
        let _ = lim.account_state();
        match &lim.state.lock().circuit {
            CircuitState::HalfOpen { canary_in_flight, .. } => {
                assert!(
                    !canary_in_flight,
                    "HalfOpen canary stuck past half_open_max must self-heal to false"
                );
            }
            other => panic!("expected HalfOpen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_goodput_climbs_when_clean_and_demand_present() {
        // goodput 控制器：窗口干净(429<band_low) + 有需求(非 app-limited) → 爬山抬 rate。
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.goodput_sanity_max_rps = 1.0;
        cfg.goodput_band_low = 0.02;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.02; // 模拟"学死卡地板"
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear(); // 最近窗口干净
            st.effective_max_inflight = 1; // 配合下面占满 1 个在飞 → 非 app-limited
        }
        // 占满唯一在飞槽，确保不被判 app-limited（current_inflight+1 >= max）。
        let _permit = match lim.acquire().await {
            AcquireOutcome::Proceed(p) => p,
            other => panic!("expected Proceed, got {other:?}"),
        };
        let before = lim.current_rate_rps();
        let raised = lim.goodput_control_tick();
        let after = lim.current_rate_rps();
        assert!(raised, "clean window + demand -> should climb");
        assert!(after > before, "rate must increase: {before} -> {after}");
        assert!(after <= 1.0 + 1e-9, "must not exceed sanity max");
    }

    #[tokio::test]
    async fn test_goodput_holds_when_app_limited() {
        // app-limited(在飞远低于并发上限=没活干) → 不把空闲误判成天花板，rate 保持不动。
        // 这正是根治 #19 卡 0.06 的关键：低流量不该被当成「到顶了」而降速。
        // P2-c：去抖后需连续 app_limited_debounce_ticks 拍才真当 app-limited，故先跑满阈值。
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.goodput_sanity_max_rps = 1.0;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.02;
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear();
            st.effective_max_inflight = 8; // 无在飞 → current_inflight(0)+1 < 8 → app-limited
        }
        let debounce = lim.cfg.app_limited_debounce_ticks;
        // 先跑满去抖阈值（每拍都 app-limited），最后一拍应进入 hold。
        let mut last_raised = true;
        for _ in 0..debounce {
            last_raised = lim.goodput_control_tick();
        }
        let before = lim.current_rate_rps();
        let raised = lim.goodput_control_tick();
        assert!(!last_raised, "持续 app-limited(达去抖阈值) -> rate must hold");
        assert!(!raised, "app-limited 稳态 -> rate must hold");
        assert!((lim.current_rate_rps() - before).abs() < 1e-9, "rate stays put when no demand");
    }

    // P2-c①：真进入 app-limited(连续达去抖阈值)时不清 probe_climbing —— 需求回来从原档继续爬。
    #[tokio::test]
    async fn test_app_limited_preserves_probe_climbing() {
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.goodput_sanity_max_rps = 1.0;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.2;
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear();
            st.effective_max_inflight = 8; // 无在飞 → app-limited
            st.probe_climbing = true; // 假装正在爬升
        }
        let debounce = lim.cfg.app_limited_debounce_ticks;
        for _ in 0..(debounce + 2) {
            lim.goodput_control_tick();
        }
        assert!(
            lim.state.lock().probe_climbing,
            "app-limited 不该清 probe_climbing（需求回来要从原档继续爬，旧 bug 每拍重置）"
        );
    }

    // P2-c②：去抖——仅 1 拍 app-limited(阈值=2)不该触发 hold，仍按正常逻辑走(429 低时能爬)。
    #[tokio::test]
    async fn test_app_limited_single_tick_debounced() {
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.goodput_sanity_max_rps = 1.0;
        cfg.goodput_band_low = 0.02;
        assert!(
            cfg.app_limited_debounce_ticks >= 2,
            "本测前提：去抖阈值 ≥2，单拍才不触发"
        );
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.2;
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear(); // 0% 429 < band_low → 有余量该爬
            st.effective_max_inflight = 8; // app-limited（但只这一拍）
        }
        let before = lim.current_rate_rps();
        let raised = lim.goodput_control_tick(); // streak=1 < 2 → 不进 app-limited，走爬升
        assert!(
            raised && lim.current_rate_rps() > before,
            "仅 1 拍 app-limited(阈值2)应被去抖忽略，按 429<band_low 正常爬升"
        );
    }

    // P2-c③：连续达到去抖阈值后才进入 app-limited hold（第 N 拍起 rate 不再升）。
    #[tokio::test]
    async fn test_app_limited_engages_after_n_ticks() {
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.goodput_sanity_max_rps = 5.0;
        cfg.goodput_band_low = 0.02;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.2;
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear();
            st.effective_max_inflight = 8; // 持续 app-limited
        }
        let debounce = lim.cfg.app_limited_debounce_ticks;
        // 前 debounce-1 拍：streak 未达阈值 → 仍按 429<band_low 爬升。
        for _ in 0..(debounce - 1) {
            lim.goodput_control_tick();
        }
        let rate_before_engage = lim.current_rate_rps();
        // 第 debounce 拍：streak 达阈值 → 进入 hold，rate 不再升。
        let raised = lim.goodput_control_tick();
        assert!(!raised, "达去抖阈值后应进入 app-limited hold，不再升 rate");
        assert!(
            (lim.current_rate_rps() - rate_before_engage).abs() < 1e-9,
            "进入 hold 后 rate 保持不动"
        );
    }

    #[tokio::test]
    async fn test_goodput_hard_ceiling_forces_down() {
        // 429 超硬上限 → 强制降速，无视 goodput 趋势（防升级惩罚）。
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.goodput_hard_ceiling = 0.15;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.5;
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear();
            // 塞满窗口 429（5 个全 429 → 100% > 15% 硬上限）。
            for _ in 0..5 {
                st.upstream_events.push_back((Instant::now(), true));
            }
        }
        let before = lim.current_rate_rps();
        let changed = lim.goodput_control_tick();
        assert!(changed, "over hard ceiling -> force down");
        assert!(lim.current_rate_rps() < before, "rate must drop: {before} -> {}", lim.current_rate_rps());
    }

    // 面板指标 observe_full().recovery_eligible 仍反映「窗口干净、Healthy、已冷却、未到上限」，
    // 作为「这个号还有恢复空间」的可观测信号（与 goodput 控制器是否真抬升解耦：
    // 真抬升还取决于是否 app-limited）。
    #[tokio::test]
    async fn test_recovery_eligible_metric_reflects_clean_window() {
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.max_rate_rps = 1.0;
        cfg.probe_budget_low = 0.01;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.02;
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear();
        }
        assert!(lim.observe_full().recovery_eligible, "clean window -> metric true");

        let mut cfg2 = test_cfg();
        cfg2.probe_budget_low = 0.01;
        let lim2 = AdaptiveLimiter::new(cfg2);
        {
            let mut st = lim2.state.lock();
            st.rate_rps = 0.02;
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear();
            st.upstream_events.push_back((Instant::now(), true));
        }
        assert!(!lim2.observe_full().recovery_eligible, "recent 429 -> metric false");
    }

    #[test]
    fn test_registry_isolates_scopes() {
        let reg = LimiterRegistry::new(test_cfg(), None);
        let a = reg.for_scope(&ThrottleScope::UserCredential(17));
        let b = reg.for_scope(&ThrottleScope::UserCredential(20));
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn test_normalize_learned_bounds_swaps_inverted() {
        let (lo, hi) = normalize_learned_bounds((0.101, 0.075));
        assert!((lo - 0.075).abs() < 1e-9);
        assert!((hi - 0.101).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_init_rate_no_panic_when_learned_bounds_inverted() {
        let cfg = test_cfg();
        let learning = learning_store_with(55, 0.101, 0.075);
        let lim = AdaptiveLimiter::new_with_context(cfg, Some(55), Some(learning));
        assert!(lim.current_rate_rps() >= 0.075 - 1e-9);
        assert!(lim.current_rate_rps() <= 0.101 + 1e-9);
    }

    fn learning_store_with(id: u64, safe_lo: f64, safe_hi: f64) -> Arc<crate::kiro::account_learning::LearningStore> {
        use crate::model::config::LearningConfig;
        let path = std::env::temp_dir().join(format!(
            "learn_floor_test_{}_{}.json",
            id,
            std::process::id()
        ));
        let json = format!(
            r#"{{"accounts":{{"{id}":{{"safeRpsLo":{safe_lo},"safeRpsHi":{safe_hi},"p80HeldMs":30000,"optimalQuarantineSecs":30,"bottleneckDimension":"SendRate"}}}}}}"#,
            id = id,
            safe_lo = safe_lo,
            safe_hi = safe_hi
        );
        std::fs::write(&path, json).expect("seed learning file");
        crate::kiro::account_learning::LearningStore::new(LearningConfig::default(), Some(path))
    }

    #[tokio::test]
    async fn test_on_throttle_breaks_static_min_rate_with_learning() {
        let mut cfg = test_cfg();
        cfg.open_429_threshold = 100;
        cfg.min_rate_rps = 0.1;
        cfg.absolute_min_rate_rps = 0.02;
        cfg.learned_floor_factor = 0.8;
        cfg.learning_min_samples_for_floor = 1;
        let learning = learning_store_with(42, 0.05, 0.06);
        let lim = AdaptiveLimiter::new_with_context(cfg, Some(42), Some(learning));
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.1;
        }
        lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        let after = lim.current_rate_rps();
        assert!(after < 0.1, "rate should break static min_rate floor, got {after}");
        assert!(after >= 0.02, "rate must stay above absolute_min, got {after}");
        assert!((after - 0.05).abs() < 1e-9, "expected 0.05 after halving 0.1, got {after}");
    }

    #[tokio::test]
    async fn test_effective_floor_falls_back_to_min_rate_without_learning() {
        let mut cfg = test_cfg();
        cfg.open_429_threshold = 100;
        cfg.min_rate_rps = 0.1;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.2;
        }
        lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
        assert!((lim.current_rate_rps() - 0.1).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_goodput_climbs_past_stale_lifetime_hi_when_clean() {
        // 根治:窗口干净 + 有需求时,goodput 控制器抬 rate 不被"终身学到的 hi"(0.08)压制,
        // 而是向 sanity_max 爬。多次 tick 模拟后台周期驱动。
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.goodput_band_low = 0.02;
        cfg.goodput_sanity_max_rps = 1.0;
        cfg.goodput_rise_epsilon = 0.05;
        cfg.learning_enabled = true;
        cfg.learning_min_samples_for_floor = 1;
        let learning = learning_store_with(7, 0.04, 0.08);
        let lim = AdaptiveLimiter::new_with_context(cfg, Some(7), Some(learning));
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.04;
            st.effective_max_inflight = 1;
        }
        // 占满唯一在飞槽 → 非 app-limited，且持续灌成功样本让 goodput 持续上涨。
        let _permit = match lim.acquire().await {
            AcquireOutcome::Proceed(p) => p,
            other => panic!("expected Proceed, got {other:?}"),
        };
        // 反复：灌成功样本(goodput 涨) + tick(爬山)。goodput 单调涨 → 持续抬 rate。
        for _ in 0..40 {
            lim.on_success(0).await;
            lim.goodput_control_tick();
        }
        assert!(
            lim.current_rate_rps() > 0.08,
            "clean+demand: rate must climb PAST stale lifetime hi 0.08, got {}",
            lim.current_rate_rps()
        );
        assert!(
            lim.current_rate_rps() <= 1.0 + 1e-9,
            "rate must not exceed sanity max 1.0, got {}",
            lim.current_rate_rps()
        );
    }

    // P1 反假绿回归（真实时间节奏）：上一版 goodput 用固定 300s 窗口当分母 → 成了慢均值，
    // 15s 一拍的 tick 抬一档后下拍 goodput 几乎不动(< rise_epsilon) → rose 恒 false → 极限环爬不动。
    // 本测用**真实墙钟时间间隔**喂样本：rate 升 → 单位时间成功数升 → 实际跨度分母下的 goodput
    // 必须同步上涨被检测到，从而真正连爬多拍。紧循环零墙钟的旧测掩盖了这个问题，这里专门复现。
    #[tokio::test]
    async fn test_goodput_climbs_under_realtime_pacing() {
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.goodput_band_low = 0.02;
        cfg.goodput_sanity_max_rps = 2.0;
        cfg.goodput_rise_epsilon = 0.05;
        cfg.probe_window = Duration::from_secs(300); // 与生产同量级的大窗口
        cfg.hard_max_inflight = 1; // 单飞：占满 1 个 permit = 饱和(非 app-limited)
        cfg.min_inflight = 1;
        cfg.adaptive_concurrency_enabled = false; // 防 recompute 把 effective_max_inflight 涨回去
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.2;
            st.effective_max_inflight = 1;
        }
        let _permit = match lim.acquire().await {
            AcquireOutcome::Proceed(p) => p,
            other => panic!("expected Proceed, got {other:?}"),
        };
        let start = lim.current_rate_rps();
        // 模拟真实节奏：每拍之间隔真实时间(20ms)喂几个成功样本再 tick。
        // 关键是样本带**真实时间间隔**，使「实际跨度分母」的 goodput 能反映速率上升。
        for _ in 0..12 {
            for _ in 0..3 {
                lim.on_success(0).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            lim.goodput_control_tick();
        }
        let end = lim.current_rate_rps();
        // 核心断言：真实时间节奏下 rate 必须实打实往上爬（不是卡在起点附近的极限环）。
        assert!(
            end > start + 0.05,
            "真实时间节奏下 goodput 控制器必须能持续爬升: {start} -> {end}（卡住=P1 未修）"
        );
    }

    #[test]
    fn test_effective_floor_concurrent_no_deadlock() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration as StdDuration;

        let mut cfg = test_cfg();
        cfg.learning_enabled = true;
        let learning = learning_store_with(99, 0.05, 0.07);
        let lim = Arc::new(AdaptiveLimiter::new_with_context(cfg, Some(99), Some(learning)));
        let start = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let lim = lim.clone();
                thread::spawn(move || {
                    for _ in 0..20 {
                        let _ = lim.observe_full();
                        if i % 2 == 0 {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .unwrap();
                            rt.block_on(async {
                                lim.on_throttle(ThrottleReason::UserRate, None, 0).await;
                                lim.on_success(0).await;
                            });
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("concurrent observe/throttle/success must not deadlock");
        }
        assert!(start.elapsed() < StdDuration::from_secs(5));
    }

    #[tokio::test]
    async fn test_permit_drop_records_held_duration_for_p80() {
        use crate::kiro::account_learning::LearningStore;
        use crate::model::config::LearningConfig;

        let mut cfg = test_cfg();
        cfg.learning_enabled = true;
        let learning = LearningStore::new(LearningConfig::default(), None);
        let lim = AdaptiveLimiter::new_with_context(cfg, Some(42), Some(learning.clone()));

        assert_eq!(learning.p80_held_ms(42), 30_000);

        let permit = ensure_proceed(lim.acquire().await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(permit);

        let p80 = learning.p80_held_ms(42);
        assert_ne!(p80, 30_000, "p80 should update after record_held_duration on permit drop");
        assert!(p80 >= 45, "held ~50ms should reflect in p80, got {p80}");
    }

    #[tokio::test]
    async fn test_permit_drop_notifies_inflight_waiters() {
        let mut cfg = test_cfg();
        cfg.hard_max_inflight = 1;
        cfg.min_inflight = 1;
        cfg.initial_rate_rps = 100.0;
        cfg.max_rate_rps = 100.0;
        cfg.burst = 10.0;
        let lim = Arc::new(AdaptiveLimiter::new(cfg));

        let held = ensure_proceed(lim.acquire().await);

        let lim2 = lim.clone();
        let waiter = tokio::spawn(async move {
            let start = Instant::now();
            ensure_proceed(lim2.acquire().await);
            start.elapsed()
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(held);

        let elapsed = tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("waiter should complete after permit drop")
            .expect("waiter join");
        assert!(
            elapsed < Duration::from_millis(40),
            "waiter should wake on notify, not poll 50ms; got {:?}",
            elapsed
        );
    }

    #[test]
    fn test_max_inflight_per_scope_caps_hard_max_in_adaptive_config() {
        let json = r#"{
            "maxInflightPerScope": 12,
            "adaptiveConcurrency": { "hardMaxInflight": 32, "minInflight": 4 }
        }"#;
        let c: AdaptiveLimitConfig = serde_json::from_str(json).expect("parse");
        let adaptive = AdaptiveConfig::from_cfg(&c);
        assert_eq!(adaptive.hard_max_inflight, 12);
    }

    #[test]
    fn test_max_inflight_below_min_warns_and_raises() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::EnvFilter;

        let logs = Arc::new(Mutex::new(Vec::new()));
        let make_writer = {
            let logs = Arc::clone(&logs);
            move || TestLogWriter(Arc::clone(&logs))
        };
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new("warn"))
                .with_writer(make_writer)
                .with_ansi(false)
                .finish(),
        );

        let json = r#"{
            "maxInflightPerScope": 2,
            "adaptiveConcurrency": { "hardMaxInflight": 32, "minInflight": 4 }
        }"#;
        let c: AdaptiveLimitConfig = serde_json::from_str(json).expect("parse");
        let adaptive = AdaptiveConfig::from_cfg(&c);
        assert_eq!(
            adaptive.hard_max_inflight, 4,
            "maxInflightPerScope=2 should be raised to minInflight=4"
        );

        let log_text = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            log_text.contains("maxInflightPerScope 低于 minInflight"),
            "expected warn log, got: {log_text}"
        );
        assert!(log_text.contains("min_inflight=4") || log_text.contains("min_inflight: 4"));
    }

    #[tokio::test]
    async fn test_held_ms_excludes_token_bucket_wait() {
        use crate::kiro::account_learning::LearningStore;
        use crate::model::config::LearningConfig;

        let mut cfg = test_cfg();
        cfg.learning_enabled = true;
        cfg.initial_rate_rps = 0.5;
        cfg.min_rate_rps = 0.5;
        cfg.max_rate_rps = 0.5;
        cfg.burst = 1.0;
        cfg.local_queue_timeout = Duration::from_secs(30);
        cfg.max_absorb_wait = Duration::from_secs(30);
        let learning = LearningStore::new(LearningConfig::default(), None);
        let lim = Arc::new(AdaptiveLimiter::new_with_context(
            cfg,
            Some(77),
            Some(learning.clone()),
        ));

        let held_first = ensure_proceed(lim.acquire().await);
        let lim2 = Arc::clone(&lim);
        let waiter = tokio::spawn(async move {
            let permit = ensure_proceed(lim2.acquire().await);
            tokio::time::sleep(Duration::from_millis(60)).await;
            permit
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(held_first);

        let permit = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("second acquire should complete after token refill")
            .expect("waiter join");
        drop(permit);

        let p80 = learning.p80_held_ms(77);
        assert!(
            p80 < 500,
            "held_ms should exclude ~2s token wait; p80={p80}"
        );
        assert!(p80 >= 45, "held_ms should include ~60ms in-flight; p80={p80}");
    }

    #[tokio::test]
    async fn test_abort_permit_drop_notifies_waiters_without_held_sample() {
        use crate::kiro::account_learning::LearningStore;
        use crate::model::config::LearningConfig;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut cfg = test_cfg();
        cfg.hard_max_inflight = 2;
        cfg.min_inflight = 2;
        cfg.learning_enabled = true;
        let learning = LearningStore::new(LearningConfig::default(), None);
        let lim = Arc::new(AdaptiveLimiter::new_with_context(
            cfg,
            Some(91),
            Some(learning.clone()),
        ));

        assert_eq!(learning.p80_held_ms(91), 30_000);

        let held = ensure_proceed(lim.acquire().await);
        let abort_permit = lim.test_acquire_unmarked_permit().await;

        let lim_notify = Arc::clone(&lim);
        let notified = Arc::new(AtomicBool::new(false));
        let notified_flag = Arc::clone(&notified);
        let listener = tokio::spawn(async move {
            lim_notify.test_notify().notified().await;
            notified_flag.store(true, Ordering::SeqCst);
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(abort_permit);

        tokio::time::timeout(Duration::from_millis(100), listener)
            .await
            .expect("listener should wake on abort permit drop notify")
            .expect("listener join");
        assert!(
            notified.load(Ordering::SeqCst),
            "abort drop must notify waiters on notify.notified()"
        );
        assert_eq!(
            learning.p80_held_ms(91),
            30_000,
            "abort drop (acquired_at=None) must not record held sample"
        );

        drop(held);
    }

    #[test]
    fn test_max_inflight_above_hard_warns_and_caps() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::EnvFilter;

        let logs = Arc::new(Mutex::new(Vec::new()));
        let make_writer = {
            let logs = Arc::clone(&logs);
            move || TestLogWriter(Arc::clone(&logs))
        };
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new("warn"))
                .with_writer(make_writer)
                .with_ansi(false)
                .finish(),
        );

        let json = r#"{
            "maxInflightPerScope": 50,
            "adaptiveConcurrency": { "hardMaxInflight": 32, "minInflight": 4 }
        }"#;
        let c: AdaptiveLimitConfig = serde_json::from_str(json).expect("parse");
        let adaptive = AdaptiveConfig::from_cfg(&c);
        assert_eq!(
            adaptive.hard_max_inflight, 32,
            "maxInflightPerScope=50 should be capped to hardMaxInflight=32"
        );

        let log_text = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            log_text.contains("maxInflightPerScope 超过 hardMaxInflight"),
            "expected warn log, got: {log_text}"
        );
        assert!(
            log_text.contains("hard_max_inflight=32") || log_text.contains("hard_max_inflight: 32")
        );
    }

    #[tokio::test]
    async fn test_local_throttled_abort_does_not_record_held() {
        use crate::kiro::account_learning::LearningStore;
        use crate::model::config::LearningConfig;

        let mut cfg = test_cfg();
        cfg.learning_enabled = true;
        cfg.local_queue_timeout = Duration::from_millis(50);
        cfg.max_absorb_wait = Duration::from_millis(120);
        cfg.open_429_threshold = 100;
        let learning = LearningStore::new(LearningConfig::default(), None);
        let lim = Arc::new(AdaptiveLimiter::new_with_context(
            cfg,
            Some(88),
            Some(learning.clone()),
        ));

        assert_eq!(learning.p80_held_ms(88), 30_000);

        let held = ensure_proceed(lim.acquire().await);
        match lim.acquire().await {
            AcquireOutcome::LocalThrottled { reason, .. } => {
                assert_eq!(reason, "absorb_timeout");
            }
            other => panic!("expected LocalThrottled absorb_timeout, got {other:?}"),
        }
        assert_eq!(
            learning.p80_held_ms(88),
            30_000,
            "abort drop must not record held sample"
        );
        drop(held);
    }

    struct TestLogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for TestLogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn ensure_proceed(outcome: AcquireOutcome) -> LimiterPermit {
        match outcome {
            AcquireOutcome::Proceed(p) => p,
            other => panic!("expected Proceed, got {other:?}"),
        }
    }
}

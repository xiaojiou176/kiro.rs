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
    pub adaptive_concurrency_enabled: bool,
    pub safety_factor: f64,
    pub grow_factor: f64,
    pub shrink_factor: f64,
    pub probe_budget_low: f64,
    pub probe_budget_high: f64,
    pub probe_window: Duration,
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
            adaptive_concurrency_enabled: ac.enabled,
            safety_factor: ac.safety_factor.clamp(0.1, 1.0),
            grow_factor: ac.grow_factor_per_window.max(1.0),
            shrink_factor: ac.shrink_factor_on_429.clamp(0.1, 1.0),
            probe_budget_low: pr.upstream_429_budget_low.clamp(0.0, 1.0),
            probe_budget_high: pr.upstream_429_budget_high.clamp(0.0, 1.0),
            probe_window: Duration::from_secs(pr.window_secs.max(60)),
            learning_enabled: c.learning.enabled,
        }
    }
}

#[derive(Debug, Clone)]
enum CircuitState {
    Healthy,
    Open { until: Instant, reason: String },
    HalfOpen { canary_in_flight: bool, successes: u32 },
}

enum AcquireDecision {
    Return(AcquireOutcome),
    WaitInflight,
    ProceedToPermit,
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
    sends_recent: VecDeque<Instant>,
    upstream_events: VecDeque<(Instant, bool)>,
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
            sends_recent: VecDeque::new(),
            upstream_events: VecDeque::new(),
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

    fn circuit_snapshot(st: &mut State) -> (AccountState, String, u64) {
        Self::maybe_advance_circuit(st);
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
        Self::circuit_snapshot(&mut st)
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

    /// 恢复探测(根治"学死卡地板")：低流量也能把 rate 从地板爬回「最近真实天花板」。
    ///
    /// 只依据**最近 `probe_window` 窗口**的 429 率(不是终身均值,旧 429 会随窗口自然过期),
    /// 当窗口干净(< `probe_budget_low`)、电路 Healthy、已冷却、rate 未达 max 时,
    /// 按 `additive_step_rps` 抬升 rate 向 `max_rate_rps`。
    ///
    /// 与 `on_success` 的涨速不同:**不要求 near_cap、不依赖流量、不被终身学习 hi 压制** ——
    /// 由后台周期调用,所以即使零流量也能恢复。撞墙后 `on_throttle` 会把窗口 429 拉高 →
    /// 本探测自动停手并退避,形成"贴着最近墙浮动"的闭环。返回是否实际抬升。
    pub fn recovery_probe_tick(&self) -> bool {
        let mut st = self.state.lock();
        // 门：复用单一判定源，确保「面板 recovery_eligible」与「实际抬升」永远一致。
        if !Self::recovery_eligible_locked(&self.cfg, &st) {
            return false;
        }
        let now = Instant::now();
        let step = self.cfg.additive_step_rps.max(0.0);
        if step <= 0.0 {
            return false;
        }
        Self::refill_locked(&self.cfg, &mut st);
        st.rate_rps = (st.rate_rps + step).min(self.cfg.max_rate_rps);
        st.last_increase = now;
        self.notify.notify_waiters();
        true
    }

    pub fn observe_full(&self) -> LimiterObservation {
        let mut st = self.state.lock();
        let (state, reason, reopen_ms) = Self::circuit_snapshot(&mut st);
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

    fn maybe_advance_circuit(st: &mut State) {
        let now = Instant::now();
        if let CircuitState::Open { until, .. } = &st.circuit {
            if now >= *until {
                st.circuit = CircuitState::HalfOpen {
                    canary_in_flight: false,
                    successes: 0,
                };
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
                    AcquireDecision::ProceedToPermit => break,
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
        Self::maybe_advance_circuit(&mut st);
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
        }
        Some(AcquireDecision::ProceedToPermit)
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
        let now = Instant::now();
        st.consecutive_throttles = 0;
        st.consecutive_user_429 = 0;
        st.successes_since_increase += 1;
        record_upstream(&mut st.upstream_events, false, self.cfg.probe_window);

        let from = Self::circuit_label(&st);
        if let CircuitState::HalfOpen { canary_in_flight, successes } = &mut st.circuit {
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

        let cooled = st.cooldown_until.map(|t| now >= t).unwrap_or(true);
        let near_cap = self.current_inflight() + 1 >= st.effective_max_inflight;
        let can_increase = cooled
            && near_cap
            && now.duration_since(st.last_increase) >= self.cfg.increase_interval
            && st.successes_since_increase >= self.cfg.successes_per_increase
            && matches!(st.circuit, CircuitState::Healthy);

        if can_increase {
            let global_429 = rate_429_locked(&st.upstream_events, self.cfg.probe_window);
            let probe_step = if global_429 < self.cfg.probe_budget_low {
                self.cfg.additive_step_rps
            } else if global_429 > self.cfg.probe_budget_high {
                -self.cfg.additive_step_rps
            } else {
                0.0
            };
            if probe_step > 0.0 {
                // 最近窗口干净(probe_step>0 ⟺ global_429<budget_low)→ 上探向 max,
                // 不被终身学习 hi 压制(与 recovery_probe 一致,贴最近真实天花板)。
                st.rate_rps = (st.rate_rps + probe_step).min(self.cfg.max_rate_rps);
            } else if probe_step < 0.0 {
                st.rate_rps = (st.rate_rps + probe_step).max(self.effective_rate_floor());
            } else {
                st.rate_rps = (st.rate_rps + self.cfg.additive_step_rps).min(self.learned_probe_cap());
            }
            st.successes_since_increase = 0;
            st.last_increase = now;
            self.notify.notify_waiters();
        }
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

        let beta = match reason {
            ThrottleReason::Suspicious => 0.1,
            _ => self.cfg.beta_user,
        };
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

    /// 对所有 scope 跑一次恢复探测(后台周期调用)。返回实际抬升 rate 的 scope 数量。
    pub fn recovery_probe_tick_all(&self) -> usize {
        let limiters: Vec<Arc<AdaptiveLimiter>> = self.map.lock().values().cloned().collect();
        limiters.iter().filter(|l| l.recovery_probe_tick()).count()
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
            adaptive_concurrency_enabled: true,
            safety_factor: 0.8,
            grow_factor: 1.25,
            shrink_factor: 0.5,
            probe_budget_low: 0.01,
            probe_budget_high: 0.02,
            probe_window: Duration::from_secs(300),
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
    async fn test_probe_budget_increase() {
        let lim = AdaptiveLimiter::new(test_cfg());
        let before = lim.current_rate_rps();
        lim.on_success(0).await;
        assert!(lim.current_rate_rps() >= before);
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
    async fn test_recovery_probe_climbs_when_recent_429_clean() {
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.max_rate_rps = 1.0;
        cfg.probe_budget_low = 0.01;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.02; // 模拟"学死卡地板"
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear(); // 最近窗口干净
        }
        let before = lim.current_rate_rps();
        let raised = lim.recovery_probe_tick();
        let after = lim.current_rate_rps();
        assert!(raised, "recent window clean -> should climb");
        assert!(after > before, "rate must increase: {before} -> {after}");
        assert!(after <= 1.0 + 1e-9, "must not exceed max_rate");
    }

    #[tokio::test]
    async fn test_recovery_probe_holds_when_recent_429_present() {
        let mut cfg = test_cfg();
        cfg.probe_budget_low = 0.01;
        let lim = AdaptiveLimiter::new(cfg);
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.02;
            st.cooldown_until = None;
            st.circuit = CircuitState::Healthy;
            st.upstream_events.clear();
            st.upstream_events.push_back((Instant::now(), true)); // 最近有 429
        }
        let before = lim.current_rate_rps();
        let raised = lim.recovery_probe_tick();
        assert!(!raised, "recent 429 above budget -> must NOT climb");
        assert!((lim.current_rate_rps() - before).abs() < 1e-9, "rate must stay put");
    }

    // P2-1 回归：面板指标 observe_full().recovery_eligible 必须与「探测会不会抬升」一致，
    // 防止两处判定漂移(面板说能恢复但实际不抬，或反之)。
    #[tokio::test]
    async fn test_recovery_eligible_metric_matches_probe_outcome() {
        // case A：窗口干净 → 指标应为 true，且探测确实抬升
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
        assert!(lim.recovery_probe_tick(), "clean window -> probe fires");

        // case B：最近有 429 → 指标应为 false，且探测不抬升
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
        assert!(!lim2.recovery_probe_tick(), "recent 429 -> probe holds");
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
    async fn test_probe_climbs_past_stale_lifetime_hi_when_window_clean() {
        // 根治:最近窗口干净时,上探不再被"终身学到的 hi"(此处 0.08)压制,而是向 max_rate 爬。
        let mut cfg = test_cfg();
        cfg.additive_step_rps = 0.05;
        cfg.increase_interval = Duration::from_millis(0);
        cfg.successes_per_increase = 1;
        cfg.probe_budget_low = 0.01;
        cfg.probe_budget_high = 0.02;
        cfg.max_rate_rps = 1.0;
        cfg.learning_enabled = true;
        cfg.learning_min_samples_for_floor = 1;
        let learning = learning_store_with(7, 0.04, 0.08);
        let lim = AdaptiveLimiter::new_with_context(cfg, Some(7), Some(learning));
        {
            let mut st = lim.state.lock();
            st.rate_rps = 0.04;
            st.effective_max_inflight = 1;
        }
        let _permit = match lim.acquire().await {
            AcquireOutcome::Proceed(p) => p,
            other => panic!("expected Proceed, got {other:?}"),
        };
        for _ in 0..10 {
            lim.on_success(0).await;
        }
        assert!(
            lim.current_rate_rps() > 0.08,
            "clean window: rate must climb PAST stale lifetime hi 0.08, got {}",
            lim.current_rate_rps()
        );
        assert!(
            lim.current_rate_rps() <= 1.0 + 1e-9,
            "rate must not exceed max_rate 1.0, got {}",
            lim.current_rate_rps()
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

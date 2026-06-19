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

/// 账号熔断状态（对外观测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountState {
    Healthy,
    Open,
    HalfOpen,
    Disabled,
}

/// acquire 的结果。
#[derive(Debug)]
pub enum AcquireOutcome {
    Proceed(tokio::sync::OwnedSemaphorePermit),
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
        Self {
            enabled: c.enabled,
            enforce: c.enforce,
            initial_rate_rps: initial,
            min_rate_rps: min_rate,
            max_rate_rps: max_rate,
            burst: c.burst.max(1.0),
            hard_max_inflight: ac.hard_max_inflight.max(ac.min_inflight).max(1),
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
            let (lo, hi) = store.learned_safe_rps(id);
            cfg.initial_rate_rps.clamp(lo, hi)
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

    pub fn current_rate_rps(&self) -> f64 {
        self.state.lock().rate_rps
    }

    pub fn cooldown_remaining(&self) -> Duration {
        let st = self.state.lock();
        match st.cooldown_until {
            Some(until) => {
                let now = Instant::now();
                if until > now {
                    until - now
                } else {
                    Duration::ZERO
                }
            }
            None => Duration::ZERO,
        }
    }

    pub fn account_state(&self) -> (AccountState, String, u64) {
        let st = self.state.lock();
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

    pub fn observe_full(&self) -> LimiterObservation {
        let st = self.state.lock();
        let (state, reason, reopen_ms) = self.account_state_from_circuit(&st.circuit);
        let (safe_lo, safe_hi) = self
            .credential_id
            .and_then(|id| self.learning.as_ref().map(|s| s.learned_safe_rps(id)))
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
            learned_safe_rps_lo: safe_lo,
            learned_safe_rps_hi: safe_hi,
            p80_held_ms: p80,
            learned_optimal_t_secs: optimal_t,
            bottleneck_dimension: bottleneck,
            upstream_429_rate_5m: rate_429_locked(&st.upstream_events, self.cfg.probe_window),
            consecutive_throttles: st.consecutive_throttles,
            cooldown_remaining_ms: self.cooldown_remaining().as_millis() as u64,
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
            ((1.0 - st.tokens) / st.rate_rps.max(self.cfg.min_rate_rps) * 1000.0) as u64
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

        let permit = self
            .inflight
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed");

        let deadline = Instant::now() + self.cfg.local_queue_timeout;
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
                    return AcquireOutcome::Proceed(permit);
                } else {
                    let missing = 1.0 - st.tokens;
                    let secs = missing / st.rate_rps.max(self.cfg.min_rate_rps);
                    Some((Duration::from_secs_f64(secs), st.rate_rps))
                }
            };

            let (wait_dur, current_rps) = match wait {
                Some(w) => w,
                None => continue,
            };

            let now = Instant::now();
            if now + wait_dur > deadline {
                let est_wait_ms = wait_dur.as_millis() as u64;
                drop(permit);
                self.clear_half_open_canary();
                return AcquireOutcome::LocalThrottled {
                    est_wait_ms,
                    current_rps,
                    reason: if current_rps <= self.cfg.min_rate_rps + f64::EPSILON {
                        "upstream_throttle_storm"
                    } else {
                        "local_queue_timeout"
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
        if let CircuitState::HalfOpen { canary_in_flight, .. } = &mut st.circuit {
            if *canary_in_flight {
                return Some(AcquireDecision::Return(AcquireOutcome::LocalThrottled {
                    est_wait_ms: 500,
                    current_rps: 0.0,
                    reason: "account_open",
                }));
            }
            *canary_in_flight = true;
        }
        let in_flight = self.cfg.hard_max_inflight - self.inflight.available_permits();
        if in_flight >= st.effective_max_inflight {
            Some(AcquireDecision::WaitInflight)
        } else {
            Some(AcquireDecision::ProceedToPermit)
        }
    }

    fn clear_half_open_canary(&self) {
        let mut st = self.state.lock();
        if let CircuitState::HalfOpen { canary_in_flight, .. } = &mut st.circuit {
            *canary_in_flight = false;
        }
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
                let cap = self
                    .credential_id
                    .and_then(|id| self.learning.as_ref().map(|s| s.learned_safe_rps(id).1))
                    .unwrap_or(self.cfg.max_rate_rps);
                st.rate_rps = (st.rate_rps + probe_step).min(cap.max(self.cfg.max_rate_rps));
            } else if probe_step < 0.0 {
                st.rate_rps = (st.rate_rps + probe_step).max(self.cfg.min_rate_rps);
            } else {
                st.rate_rps =
                    (st.rate_rps + self.cfg.additive_step_rps).min(self.cfg.max_rate_rps);
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

        let at_min = st.rate_rps <= self.cfg.min_rate_rps + f64::EPSILON;
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
            st.rate_rps = self.cfg.min_rate_rps;
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
        st.rate_rps = (st.rate_rps * beta).max(self.cfg.min_rate_rps);

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
            .and_then(|id| self.learning.as_ref().map(|s| s.learned_safe_rps(id)))
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
    pub learned_safe_rps_lo: f64,
    pub learned_safe_rps_hi: f64,
    pub p80_held_ms: u64,
    pub learned_optimal_t_secs: u64,
    pub bottleneck_dimension: BottleneckDimension,
    pub upstream_429_rate_5m: f64,
    pub consecutive_throttles: u32,
    pub cooldown_remaining_ms: u64,
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
mod tests {
    use super::*;

    fn test_cfg() -> AdaptiveConfig {
        AdaptiveConfig {
            enabled: true,
            enforce: true,
            initial_rate_rps: 1.0,
            min_rate_rps: 0.1,
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
    async fn test_fail_aloud_local_throttled() {
        let mut cfg = test_cfg();
        cfg.local_queue_timeout = Duration::from_millis(100);
        cfg.initial_rate_rps = 0.1;
        cfg.open_429_threshold = 100;
        let lim = AdaptiveLimiter::new(cfg);
        match lim.acquire().await {
            AcquireOutcome::Proceed(_) => {}
            other => panic!("第1个应 Proceed, got {other:?}"),
        }
        match lim.acquire().await {
            AcquireOutcome::LocalThrottled { reason, .. } => {
                assert_eq!(reason, "upstream_throttle_storm");
            }
            other => panic!("应 LocalThrottled, got {other:?}"),
        }
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

    #[test]
    fn test_registry_isolates_scopes() {
        let reg = LimiterRegistry::new(test_cfg(), None);
        let a = reg.for_scope(&ThrottleScope::UserCredential(17));
        let b = reg.for_scope(&ThrottleScope::UserCredential(20));
        assert!(!Arc::ptr_eq(&a, &b));
    }
}

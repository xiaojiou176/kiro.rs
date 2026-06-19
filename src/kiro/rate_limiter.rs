//! 自适应限速器（解决 AWS 429）。
//!
//! 设计：user-scope 发送前令牌桶闸门 + AIMD 自适应调速 + 全局 429 冷却 + Fail Aloud。
//! 详见 docs/superpowers/plans/2026-06-19-kiro-adaptive-ratelimit.md。
//!
//! 真账依据（2026-06-19 runtime 实证）：
//! - AWS 429 不返回任何 Retry-After，只回 x-amzn-requestid。
//! - 单号约 1 req/s 安全（0% 429）；2/s 起 ~85% 撞；在飞 >1.5 升 429。
//! - 天花板随时段浮动（同节奏 0%↔94%）→ 只能自适应、不能写死固定速率。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, sleep};

use crate::model::config::AdaptiveLimitConfig;

/// 限速作用域。第一版只启用 [`ThrottleScope::UserCredential`]；
/// [`ThrottleScope::ServiceProfile`] 为 v2 预留（profileArn 级），本版不接逻辑。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThrottleScope {
    /// 按凭据 id 限速（v1 启用）。
    UserCredential(u64),
    /// 按 profileArn 限速（v2 预留，本版不启用）。
    ServiceProfile(String),
}

impl ThrottleScope {
    /// 容器 key（稳定字符串）。
    fn key(&self) -> String {
        match self {
            ThrottleScope::UserCredential(id) => format!("user:{id}"),
            ThrottleScope::ServiceProfile(arn) => format!("service:{arn}"),
        }
    }
}

/// 上游 429 的类型。决定减速/冷却策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleReason {
    /// USER_REQUEST_RATE_EXCEEDED：用户/凭据级速率。
    UserRate,
    /// SERVICE_REQUEST_RATE_EXCEEDED：服务/profile 级（v2 才区别对待，本版按 UserRate 处理）。
    ServiceRate,
    /// "suspicious activity" 风控软封：不是普通速率限流。
    Suspicious,
    /// 其它/未知 429。
    Unknown,
}

/// 把上游响应体分类成 [`ThrottleReason`]。
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

/// acquire 的结果。
#[derive(Debug)]
pub enum AcquireOutcome {
    /// 拿到许可，可发请求。permit 在请求（含 streaming 转发）结束后再 drop。
    Proceed(OwnedSemaphorePermit),
    /// Fail Aloud 🔴：预计排队过久，本地直接失败（不再压队列、不熔断停服）。
    LocalThrottled {
        est_wait_ms: u64,
        current_rps: f64,
        reason: &'static str,
    },
    /// shadow 模式：不拦截，只记录"本应等多久 / 本应什么速率"。
    ShadowProceed { would_wait_ms: u64, would_rps: f64 },
}

/// 自适应配置（从 [`AdaptiveLimitConfig`] 映射的强类型版本）。
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    pub enabled: bool,
    pub enforce: bool,
    pub initial_rate_rps: f64,
    pub min_rate_rps: f64,
    pub max_rate_rps: f64,
    pub burst: f64,
    pub max_inflight: usize,
    pub additive_step_rps: f64,
    pub increase_interval: Duration,
    pub successes_per_increase: u64,
    pub beta_user: f64,
    pub user_cooldown_base: Duration,
    pub cooldown_cap: Duration,
    pub local_queue_timeout: Duration,
}

impl AdaptiveConfig {
    /// 从外部 JSON 配置映射，并做基本健壮性钳制（避免非法值导致死锁/恐慌）。
    pub fn from_cfg(c: &AdaptiveLimitConfig) -> Self {
        let min_rate = c.min_rate_rps.max(0.001);
        let max_rate = c.max_rate_rps.max(min_rate);
        let initial = c.initial_rate_rps.clamp(min_rate, max_rate);
        Self {
            enabled: c.enabled,
            enforce: c.enforce,
            initial_rate_rps: initial,
            min_rate_rps: min_rate,
            max_rate_rps: max_rate,
            burst: c.burst.max(1.0),
            max_inflight: c.max_inflight_per_scope.max(1),
            additive_step_rps: c.additive_step_rps.max(0.0),
            increase_interval: Duration::from_secs(c.increase_interval_secs),
            successes_per_increase: c.successes_per_increase.max(1),
            beta_user: c.beta_user.clamp(0.05, 0.95),
            user_cooldown_base: Duration::from_secs(c.user_cooldown_base_secs.max(1)),
            cooldown_cap: Duration::from_secs(c.cooldown_cap_secs.max(1)),
            local_queue_timeout: Duration::from_secs(c.local_queue_timeout_secs.max(1)),
        }
    }
}

struct State {
    rate_rps: f64,
    tokens: f64,
    last_refill: Instant,
    cooldown_until: Option<Instant>,
    consecutive_throttles: u32,
    successes_since_increase: u64,
    last_increase: Instant,
}

/// 单个 scope 的自适应限速状态机。
pub struct AdaptiveLimiter {
    cfg: AdaptiveConfig,
    state: Mutex<State>,
    inflight: Arc<Semaphore>,
    notify: Notify,
}

impl AdaptiveLimiter {
    pub fn new(cfg: AdaptiveConfig) -> Self {
        let now = Instant::now();
        let inflight = Arc::new(Semaphore::new(cfg.max_inflight));
        let state = State {
            rate_rps: cfg.initial_rate_rps,
            tokens: cfg.burst.min(1.0),
            last_refill: now,
            cooldown_until: None,
            consecutive_throttles: 0,
            successes_since_increase: 0,
            last_increase: now,
        };
        Self {
            cfg,
            state: Mutex::new(state),
            inflight,
            notify: Notify::new(),
        }
    }

    /// 当前速率（rps），用于观测/响应头。
    pub fn current_rate_rps(&self) -> f64 {
        self.state.lock().rate_rps
    }

    /// 强制 shadow 语义：只计算"本应等多久 / 本应什么速率"，不阻塞、不占并发许可。
    /// 用于灰度 retry_only 阶段对初始请求（attempt 0）的观测。
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

    /// 发送前闸门。返回 [`AcquireOutcome`]。
    ///
    /// - shadow（enforce=false）：永远 [`AcquireOutcome::ShadowProceed`]，不阻塞。
    /// - enforce：cooldown 中等待；无 token 按当前速率排队；预计排队超 `local_queue_timeout`
    ///   则 [`AcquireOutcome::LocalThrottled`]（Fail Aloud 🔴）。
    pub async fn acquire(&self) -> AcquireOutcome {
        // shadow 模式：只算"本应等多久"，不阻塞、不占并发许可。
        if !self.cfg.enforce {
            return self.acquire_shadow();
        }

        // enforce 模式：先占一个在飞许可（限制并发）。
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

            // Fail Aloud 🔴：预计还要等到超过队列超时 → 本地失败（释放 permit）。
            let now = Instant::now();
            if now + wait_dur > deadline {
                let est_wait_ms = wait_dur.as_millis() as u64;
                drop(permit);
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

    /// 成功回写：慢加性增速（满足间隔+累计成功阈值才 +step）。
    pub async fn on_success(&self) {
        let mut st = self.state.lock();
        Self::refill_locked(&self.cfg, &mut st);
        let now = Instant::now();
        st.consecutive_throttles = 0;
        st.successes_since_increase += 1;

        let cooled = st.cooldown_until.map(|t| now >= t).unwrap_or(true);
        let can_increase = cooled
            && now.duration_since(st.last_increase) >= self.cfg.increase_interval
            && st.successes_since_increase >= self.cfg.successes_per_increase;
        if can_increase {
            st.rate_rps = (st.rate_rps + self.cfg.additive_step_rps).min(self.cfg.max_rate_rps);
            st.successes_since_increase = 0;
            st.last_increase = now;
            self.notify.notify_waiters();
        }
    }

    /// 429 回写：乘性减速 + tokens 清零 + 进入冷却。
    ///
    /// `retry_after` 仅在配置 `respect_retry_after=true` 时由调用方传入（AWS 实证不返回，故通常 None）。
    pub async fn on_throttle(&self, reason: ThrottleReason, retry_after: Option<Duration>) {
        let mut st = self.state.lock();
        Self::refill_locked(&self.cfg, &mut st);
        let now = Instant::now();
        st.consecutive_throttles = st.consecutive_throttles.saturating_add(1);
        st.successes_since_increase = 0;

        let beta = match reason {
            ThrottleReason::Suspicious => 0.1,
            // ServiceRate 本版按 UserRate 同等处理（v2 才做 profile 级）。
            _ => self.cfg.beta_user,
        };
        st.rate_rps = (st.rate_rps * beta).max(self.cfg.min_rate_rps);
        st.tokens = 0.0;

        let local_cd = exp_cooldown(
            self.cfg.user_cooldown_base,
            self.cfg.cooldown_cap,
            st.consecutive_throttles,
        );
        let cooldown = retry_after
            .map(|d| d.min(self.cfg.cooldown_cap))
            .unwrap_or(local_cd);
        let until = now + cooldown;
        st.cooldown_until = Some(match st.cooldown_until {
            Some(old) if old > until => old,
            _ => until,
        });
        self.notify.notify_waiters();
    }

    fn refill_locked(cfg: &AdaptiveConfig, st: &mut State) {
        let now = Instant::now();
        let elapsed = now.duration_since(st.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            st.tokens = (st.tokens + elapsed * st.rate_rps).min(cfg.burst);
            st.last_refill = now;
        }
    }
}

fn exp_cooldown(base: Duration, cap: Duration, n: u32) -> Duration {
    let pow = 2u32.saturating_pow(n.saturating_sub(1).min(6));
    let raw = base.saturating_mul(pow).min(cap);
    add_small_jitter(raw)
}

/// ±20% jitter，避免多个等待者同时醒来形成 thundering herd。
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

/// 多 scope limiter 容器。留多号口：按 scope key 存多个 limiter，
/// 第一版默认只出现 1 个 UserCredential 条目。
pub struct LimiterRegistry {
    cfg: AdaptiveConfig,
    map: Mutex<HashMap<String, Arc<AdaptiveLimiter>>>,
}

impl LimiterRegistry {
    pub fn new(cfg: AdaptiveConfig) -> Self {
        Self {
            cfg,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// 总开关。false 时调用方应完全跳过 limiter（行为等同改造前）。
    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// 取（或按 cfg 新建）对应 scope 的 limiter。
    pub fn for_scope(&self, scope: &ThrottleScope) -> Arc<AdaptiveLimiter> {
        let key = scope.key();
        let mut map = self.map.lock();
        if let Some(l) = map.get(&key) {
            return l.clone();
        }
        let limiter = Arc::new(AdaptiveLimiter::new(self.cfg.clone()));
        map.insert(key, limiter.clone());
        limiter
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
            max_inflight: 4,
            additive_step_rps: 0.5,
            increase_interval: Duration::from_millis(0),
            successes_per_increase: 1,
            beta_user: 0.5,
            user_cooldown_base: Duration::from_secs(2),
            cooldown_cap: Duration::from_secs(60),
            local_queue_timeout: Duration::from_secs(90),
        }
    }

    // 单测1：token 发放 —— burst=1、rate=1/s，第 1 个立即 Proceed，第 2 个需等待（不立即放行）。
    #[tokio::test]
    async fn test_token_bucket_gates_second_request() {
        let lim = AdaptiveLimiter::new(test_cfg());
        let start = Instant::now();
        match lim.acquire().await {
            AcquireOutcome::Proceed(_) => {}
            other => panic!("第1个应 Proceed, got {other:?}"),
        }
        // 第 2 个：桶里没 token，需按 1/s 速率等待 ~1s。给它 0.5s 上限，应拿不到。
        let r = tokio::time::timeout(Duration::from_millis(500), lim.acquire()).await;
        assert!(r.is_err(), "第2个不该在 0.5s 内拿到（被限速排队）");
        assert!(start.elapsed() >= Duration::from_millis(500));
    }

    // 单测2：AIMD 减速 —— on_throttle 后 rate 砍半、tokens 清零、进 cooldown。
    #[tokio::test]
    async fn test_on_throttle_halves_rate_and_cools_down() {
        let lim = AdaptiveLimiter::new(test_cfg());
        let before = lim.current_rate_rps();
        lim.on_throttle(ThrottleReason::UserRate, None).await;
        let after = lim.current_rate_rps();
        assert!(
            (after - before * 0.5).abs() < 1e-9,
            "rate 应砍半: {before}->{after}"
        );
        let st = lim.state.lock();
        assert_eq!(st.tokens, 0.0, "tokens 应清零");
        assert!(st.cooldown_until.is_some(), "应进入 cooldown");
    }

    // 单测3：AIMD 加速 —— 满足条件后 rate += step，不超 maxRate。
    #[tokio::test]
    async fn test_on_success_increases_rate_capped() {
        let lim = AdaptiveLimiter::new(test_cfg()); // initial=1.0, step=0.5, interval=0, per_increase=1
        lim.on_success().await; // 1.0 -> 1.5
        assert!((lim.current_rate_rps() - 1.5).abs() < 1e-9);
        lim.on_success().await; // 1.5 -> 2.0 (cap)
        assert!((lim.current_rate_rps() - 2.0).abs() < 1e-9);
        lim.on_success().await; // 仍 2.0，不超 max
        assert!((lim.current_rate_rps() - 2.0).abs() < 1e-9);
    }

    // 单测4：cooldown 指数增长 —— 连撞 N 次，cooldown 随 2^(n-1) 增长（封顶 cap）。
    #[test]
    fn test_exp_cooldown_grows_and_caps() {
        let base = Duration::from_secs(2);
        let cap = Duration::from_secs(60);
        let c1 = exp_cooldown(base, cap, 1); // ~2s
        let c2 = exp_cooldown(base, cap, 2); // ~4s
        let c3 = exp_cooldown(base, cap, 3); // ~8s
        // 带 ±20% jitter，用宽松区间断言趋势。
        assert!(c1.as_millis() < c2.as_millis() + 1000);
        assert!(c2.as_millis() < c3.as_millis() + 1000);
        let c_big = exp_cooldown(base, cap, 20); // 应被 cap 封顶
        assert!(c_big.as_secs() <= 60 + 12, "应封顶在 cap 附近: {c_big:?}");
    }

    // 单测5：Fail Aloud —— 排队预计超 timeout → LocalThrottled，不 Proceed。
    #[tokio::test]
    async fn test_fail_aloud_local_throttled() {
        let mut cfg = test_cfg();
        cfg.local_queue_timeout = Duration::from_millis(100); // 极短超时
        cfg.initial_rate_rps = 0.1; // 极慢，token 补充要 10s
        cfg.min_rate_rps = 0.1;
        let lim = AdaptiveLimiter::new(cfg);
        // 第 1 个消耗掉初始 token
        match lim.acquire().await {
            AcquireOutcome::Proceed(_p) => {}
            other => panic!("第1个应 Proceed, got {other:?}"),
        }
        // 第 2 个：补 1 token 要 ~10s，远超 100ms timeout → LocalThrottled
        match lim.acquire().await {
            AcquireOutcome::LocalThrottled { reason, .. } => {
                assert_eq!(reason, "upstream_throttle_storm");
            }
            other => panic!("应 LocalThrottled, got {other:?}"),
        }
    }

    // 单测6：shadow 模式 —— enforce=false 永远 ShadowProceed，不阻塞。
    #[tokio::test]
    async fn test_shadow_never_blocks() {
        let mut cfg = test_cfg();
        cfg.enforce = false;
        cfg.burst = 1.0;
        let lim = AdaptiveLimiter::new(cfg);
        for _ in 0..5 {
            match lim.acquire().await {
                AcquireOutcome::ShadowProceed { .. } => {}
                other => panic!("shadow 应永远 ShadowProceed, got {other:?}"),
            }
        }
    }

    // 单测7：reason 分类。
    #[test]
    fn test_classify_reason() {
        assert_eq!(
            classify_throttle_reason(r#"{"reason":"SERVICE_REQUEST_RATE_EXCEEDED"}"#),
            ThrottleReason::ServiceRate
        );
        assert_eq!(
            classify_throttle_reason(r#"{"reason":"USER_REQUEST_RATE_EXCEEDED"}"#),
            ThrottleReason::UserRate
        );
        assert_eq!(
            classify_throttle_reason("Due to suspicious activity we ..."),
            ThrottleReason::Suspicious
        );
        assert_eq!(
            classify_throttle_reason("some other error"),
            ThrottleReason::Unknown
        );
    }

    // 单测8：多号留口 —— 两个不同 UserCredential 得到两个独立 limiter。
    #[test]
    fn test_registry_isolates_scopes() {
        let reg = LimiterRegistry::new(test_cfg());
        let a = reg.for_scope(&ThrottleScope::UserCredential(17));
        let b = reg.for_scope(&ThrottleScope::UserCredential(20));
        let a2 = reg.for_scope(&ThrottleScope::UserCredential(17));
        assert!(!Arc::ptr_eq(&a, &b), "不同号应是不同 limiter");
        assert!(Arc::ptr_eq(&a, &a2), "同号应复用同一 limiter");
    }
}

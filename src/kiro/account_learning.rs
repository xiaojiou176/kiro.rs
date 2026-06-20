//! 每账号在线学习引擎：瓶颈维度 / safe_rps / 最优静养 T。
//! 状态落盘到 cache_dir，重启继承。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::model::config::LearningConfig;

/// 429 时优先收缩的旋钮维度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum BottleneckDimension {
    Inflight,
    #[default]
    SendRate,
    Rpm,
    Mixed,
}

/// 单次发送上下文样本（成功或 429 均记录）。
#[derive(Debug, Clone, Copy)]
pub struct SendContextSample {
    pub inflight: usize,
    pub sends_last_1s: u32,
    pub rpm_last_60s: usize,
    pub send_rate_rps: f64,
    pub was_429: bool,
}

/// 分桶统计：桶索引 → (总样本, 429 次数)。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BucketStats {
    /// 每个桶 (总样本数, 429 次数)。用 f64 以支持指数时间衰减（旧样本随时间被遗忘）。
    buckets: Vec<(f64, f64)>,
}

impl BucketStats {
    fn new(n: usize) -> Self {
        Self {
            buckets: vec![(0.0, 0.0); n],
        }
    }

    fn record(&mut self, bucket: usize, was_429: bool) {
        if bucket >= self.buckets.len() {
            return;
        }
        self.buckets[bucket].0 += 1.0;
        if was_429 {
            self.buckets[bucket].1 += 1.0;
        }
    }

    /// 按经过的「半衰期数」对所有桶计数做指数衰减：count *= 0.5^half_lives。
    /// 旧 429 样本随时间淡出，避免「学死」——某号几小时前撞过墙就被永久按慢号对待。
    fn decay_by_half_lives(&mut self, half_lives: f64) {
        if half_lives <= 0.0 {
            return;
        }
        let factor = 0.5_f64.powf(half_lives);
        for b in &mut self.buckets {
            b.0 *= factor;
            b.1 *= factor;
        }
    }

    fn monotonic_score(&self) -> f64 {
        let n = self.buckets.len();
        if n < 2 {
            return 0.0;
        }
        let mut score = 0.0;
        let mut weight = 0.0;
        for i in 0..n - 1 {
            let (t_lo, th_lo) = self.buckets[i];
            let (t_hi, th_hi) = self.buckets[i + 1];
            if t_lo <= 0.0 || t_hi <= 0.0 {
                continue;
            }
            let r_lo = th_lo / t_lo;
            let r_hi = th_hi / t_hi;
            let w = t_lo + t_hi;
            score += (r_hi - r_lo).max(0.0) * w;
            weight += w;
        }
        if weight > 0.0 {
            score / weight
        } else {
            0.0
        }
    }

    fn total_samples(&self) -> f64 {
        self.buckets.iter().map(|(t, _)| *t).sum()
    }
}

/// 单账号学习状态（可序列化部分）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLearningPersisted {
    pub safe_rps_lo: f64,
    pub safe_rps_hi: f64,
    pub p80_held_ms: u64,
    pub optimal_quarantine_secs: u64,
    pub bottleneck_dimension: BottleneckDimension,
    /// 真实请求样本数（每个 record_sample +1）。用于成熟度判定，避免「三维桶样本之和」
    /// 把 1 个真实请求算成 3 个、令 min_samples 门槛被 3× 稀释。
    #[serde(default)]
    real_sample_count: u64,
    #[serde(default)]
    inflight_buckets: BucketStats,
    #[serde(default)]
    send_rate_buckets: BucketStats,
    #[serde(default)]
    rpm_buckets: BucketStats,
}

impl Default for AccountLearningPersisted {
    fn default() -> Self {
        Self {
            safe_rps_lo: 0.5,
            safe_rps_hi: 1.0,
            p80_held_ms: 30_000,
            optimal_quarantine_secs: 30,
            bottleneck_dimension: BottleneckDimension::SendRate,
            real_sample_count: 0,
            inflight_buckets: BucketStats::new(5),
            send_rate_buckets: BucketStats::new(5),
            rpm_buckets: BucketStats::new(5),
        }
    }
}

/// 运行时可变部分（held 时长在线分位数）。
#[derive(Debug, Default)]
struct AccountLearningRuntime {
    held_samples: Vec<u64>,
    last_stable_success: Option<Instant>,
    /// 磁盘加载时已收敛的 safe_rps（无分桶样本的旧数据）；运行时新 429 不会置位。
    legacy_converged: bool,
}

struct AccountLearningEntry {
    persisted: AccountLearningPersisted,
    runtime: AccountLearningRuntime,
}

fn bucket_index(value: f64, max_value: f64, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let v = value.max(0.0);
    let idx = ((v / max_value.max(1.0)) * n as f64) as usize;
    idx.min(n - 1)
}

const MIN_SAMPLES_FOR_BOTTLENECK: u64 = 20;
const BUCKET_COUNT: usize = 5;
pub(crate) const DEFAULT_SAFE_RPS_LO: f64 = 0.5;
pub(crate) const DEFAULT_SAFE_RPS_HI: f64 = 1.0;

fn persisted_deviates_from_factory(p: &AccountLearningPersisted) -> bool {
    (p.safe_rps_lo - DEFAULT_SAFE_RPS_LO).abs() > f64::EPSILON
        || (p.safe_rps_hi - DEFAULT_SAFE_RPS_HI).abs() > f64::EPSILON
}

/// 进程内学习存储 + 落盘。
pub struct LearningStore {
    cfg: LearningConfig,
    accounts: Mutex<HashMap<u64, AccountLearningEntry>>,
    dirty: AtomicBool,
    path: Option<PathBuf>,
    last_save_at: Mutex<Option<Instant>>,
    /// 上次衰减时刻，用于把「经过的秒数」换算成「半衰期数」。
    last_decay_at: Mutex<Instant>,
}

const LEARNING_SAVE_DEBOUNCE: Duration = Duration::from_secs(30);

impl LearningStore {
    pub fn new(cfg: LearningConfig, path: Option<PathBuf>) -> Arc<Self> {
        let store = Arc::new(Self {
            cfg,
            accounts: Mutex::new(HashMap::new()),
            dirty: AtomicBool::new(false),
            path,
            last_save_at: Mutex::new(None),
            last_decay_at: Mutex::new(Instant::now()),
        });
        store.load();
        store
    }

    fn entry(&self, id: u64) -> AccountLearningEntry {
        let mut map = self.accounts.lock();
        map.entry(id)
            .or_insert_with(|| AccountLearningEntry {
                persisted: AccountLearningPersisted::default(),
                runtime: AccountLearningRuntime::default(),
            })
            .clone_entry()
    }

    fn with_entry<F, R>(&self, id: u64, f: F) -> R
    where
        F: FnOnce(&mut AccountLearningPersisted, &mut AccountLearningRuntime) -> R,
    {
        let mut map = self.accounts.lock();
        let entry = map.entry(id).or_insert_with(|| AccountLearningEntry {
            persisted: AccountLearningPersisted::default(),
            runtime: AccountLearningRuntime::default(),
        });
        let r = f(&mut entry.persisted, &mut entry.runtime);
        self.dirty.store(true, Ordering::Relaxed);
        r
    }

    pub fn record_sample(&self, id: u64, sample: SendContextSample) {
        self.with_entry(id, |p, _rt| {
            let inflight_b = bucket_index(sample.inflight as f64, 32.0, BUCKET_COUNT);
            let send_b = bucket_index(sample.sends_last_1s as f64, 10.0, BUCKET_COUNT);
            let rpm_b = bucket_index(sample.rpm_last_60s as f64, 120.0, BUCKET_COUNT);

            p.real_sample_count = p.real_sample_count.saturating_add(1);
            p.inflight_buckets.record(inflight_b, sample.was_429);
            p.send_rate_buckets.record(send_b, sample.was_429);
            p.rpm_buckets.record(rpm_b, sample.was_429);

            let alpha = self.cfg.ewma_alpha.clamp(0.01, 1.0);
            if sample.was_429 {
                p.safe_rps_hi = p.safe_rps_hi.min(sample.send_rate_rps * 0.85);
                p.safe_rps_lo = p.safe_rps_lo.min(sample.send_rate_rps * 0.7);
            } else {
                p.safe_rps_lo = p.safe_rps_lo * (1.0 - alpha) + sample.send_rate_rps * alpha;
                if sample.send_rate_rps > p.safe_rps_hi * 0.95 {
                    p.safe_rps_hi = p.safe_rps_hi * (1.0 - alpha * 0.5) + sample.send_rate_rps * alpha * 0.5;
                }
            }

            p.bottleneck_dimension = compute_bottleneck(p);
            if p.safe_rps_lo > p.safe_rps_hi {
                std::mem::swap(&mut p.safe_rps_lo, &mut p.safe_rps_hi);
            }
        });
        self.save_debounced();
    }

    pub fn record_held_ms(&self, id: u64, held_ms: u64) {
        self.with_entry(id, |p, rt| {
            rt.held_samples.push(held_ms);
            if rt.held_samples.len() > 200 {
                rt.held_samples.drain(0..100);
            }
            if !rt.held_samples.is_empty() {
                let mut sorted = rt.held_samples.clone();
                sorted.sort_unstable();
                let idx = ((sorted.len() as f64) * 0.8).ceil() as usize;
                let idx = idx.saturating_sub(1).min(sorted.len() - 1);
                p.p80_held_ms = sorted[idx];
            }
        });
        self.save_debounced();
    }

    pub fn on_quarantine_probe_failed(&self, id: u64, max_secs: u64) {
        self.with_entry(id, |p, _| {
            p.optimal_quarantine_secs = (p.optimal_quarantine_secs * 2).min(max_secs);
        });
        self.save_debounced();
    }

    pub fn on_quarantine_probe_stable(&self, id: u64, min_secs: u64) {
        self.with_entry(id, |p, rt| {
            rt.last_stable_success = Some(Instant::now());
            let shrunk = (p.optimal_quarantine_secs as f64 * 0.85) as u64;
            p.optimal_quarantine_secs = shrunk.max(min_secs);
        });
        self.save_debounced();
    }

    pub fn optimal_quarantine(&self, id: u64, initial_secs: u64) -> Duration {
        let p = self.snapshot(id);
        Duration::from_secs(p.map(|s| s.optimal_quarantine_secs).unwrap_or(initial_secs))
    }

    pub fn snapshot(&self, id: u64) -> Option<AccountLearningPersisted> {
        self.accounts
            .lock()
            .get(&id)
            .map(|e| e.persisted.clone())
    }

    /// 对所有账号的分桶统计做指数时间衰减（H1：旧 429 随时间被遗忘）。
    /// `half_lives` = 距上次衰减经过的「半衰期数」。由后台 tick 周期调用，
    /// 也供测试直接驱动。real_sample_count 同步衰减以保持成熟度门槛与桶规模一致。
    pub fn decay_all(&self, half_lives: f64) {
        if half_lives <= 0.0 {
            return;
        }
        let mut map = self.accounts.lock();
        for entry in map.values_mut() {
            let p = &mut entry.persisted;
            p.inflight_buckets.decay_by_half_lives(half_lives);
            p.send_rate_buckets.decay_by_half_lives(half_lives);
            p.rpm_buckets.decay_by_half_lives(half_lives);
            // ⚠️ real_sample_count（成熟度门）**绝不衰减**：它代表「这个号一共从多少真实请求
            // 学过」，是单调 latch。若它随空闲衰减，低流量号会在第一个 idle tick 就从「已成熟」
            // 跌回「未成熟」(20×0.9885=19<20) → effective_floor 退回静态 min_rate → 重新引入
            // 「卡 min_rate 地板」的 #19 病（P2-a）。桶统计衰减(让旧 429 随时间淡出)归桶统计，
            // 成熟度归成熟度，两者解耦。
        }
        drop(map);
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// 后台 tick 入口：按「距上次衰减经过的真实时间 / 配置半衰期」自动换算半衰期数并衰减。
    /// 半衰期 ≤0（未配置或关闭）时不衰减。返回是否实际执行了衰减。
    pub fn decay_tick_now(&self) -> bool {
        let half_life_secs = self.cfg.bucket_decay_half_life_secs;
        if half_life_secs == 0 {
            return false;
        }
        let elapsed = {
            let mut last = self.last_decay_at.lock();
            let now = Instant::now();
            let dt = now.duration_since(*last);
            *last = now;
            dt
        };
        let half_lives = elapsed.as_secs_f64() / half_life_secs as f64;
        if half_lives <= 0.0 {
            return false;
        }
        self.decay_all(half_lives);
        true
    }

    pub fn learned_safe_rps(&self, id: u64) -> (f64, f64) {
        match self.snapshot(id) {
            Some(p) => {
                if p.safe_rps_lo <= p.safe_rps_hi {
                    (p.safe_rps_lo, p.safe_rps_hi)
                } else {
                    (p.safe_rps_hi, p.safe_rps_lo)
                }
            }
            None => (0.5, 1.0),
        }
    }

    /// 累计真实请求样本数（每个 record_sample 计 1，不是三维分桶之和）。
    pub fn learning_sample_count(&self, id: u64) -> u64 {
        self.snapshot(id).map(|p| p.real_sample_count).unwrap_or(0)
    }

    /// 真实请求样本足够，或磁盘加载时已收敛的 legacy safe_rps 时视为成熟。
    pub fn learning_is_mature(&self, id: u64, min_samples: u64) -> bool {
        let map = self.accounts.lock();
        let Some(entry) = map.get(&id) else {
            return false;
        };
        if entry.persisted.real_sample_count >= min_samples {
            return true;
        }
        entry.runtime.legacy_converged
    }

    pub fn p80_held_ms(&self, id: u64) -> u64 {
        self.snapshot(id).map(|p| p.p80_held_ms).unwrap_or(30_000)
    }

    pub fn bottleneck(&self, id: u64) -> BottleneckDimension {
        self.snapshot(id)
            .map(|p| p.bottleneck_dimension)
            .unwrap_or(BottleneckDimension::SendRate)
    }

    fn save_debounced(&self) {
        let should = {
            let last = *self.last_save_at.lock();
            match last {
                Some(t) => t.elapsed() >= LEARNING_SAVE_DEBOUNCE,
                None => true,
            }
        };
        if should {
            self.save();
        }
    }

    pub fn flush_if_dirty(&self) {
        if self.dirty.load(Ordering::Relaxed) {
            self.save();
        }
    }

    pub fn save(&self) {
        let path = match &self.path {
            Some(p) => p.clone(),
            None => return,
        };
        let accounts: HashMap<String, AccountLearningPersisted> = self
            .accounts
            .lock()
            .iter()
            .map(|(id, e)| (id.to_string(), e.persisted.clone()))
            .collect();
        let wrapper = LearningFile { accounts };
        match serde_json::to_string_pretty(&wrapper) {
            Ok(json) => {
                if let Err(e) = crate::observability::write_atomic(&path, json.as_bytes()) {
                    tracing::warn!("保存 account_learning 失败: {}", e);
                } else {
                    *self.last_save_at.lock() = Some(Instant::now());
                    self.dirty.store(false, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!("序列化 account_learning 失败: {}", e),
        }
    }

    fn load(&self) {
        let path = match &self.path {
            Some(p) => p.clone(),
            None => return,
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return,
        };
        let file: LearningFile = match serde_json::from_str(&content) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("解析 account_learning 失败: {}", e);
                return;
            }
        };
        let mut map = self.accounts.lock();
        let mut repaired = false;
        for (k, mut v) in file.accounts {
            if let Ok(id) = k.parse::<u64>() {
                if v.safe_rps_lo > v.safe_rps_hi {
                    std::mem::swap(&mut v.safe_rps_lo, &mut v.safe_rps_hi);
                    repaired = true;
                }
                // 旧盘可能没有 realSampleCount（serde default=0）但 safe_rps 已收敛——
                // 用真实样本数判定，不足且偏离出厂值则视为 legacy 已收敛。
                let legacy_converged = v.real_sample_count < MIN_SAMPLES_FOR_BOTTLENECK
                    && persisted_deviates_from_factory(&v);
                map.insert(
                    id,
                    AccountLearningEntry {
                        persisted: v,
                        runtime: AccountLearningRuntime {
                            legacy_converged,
                            ..AccountLearningRuntime::default()
                        },
                    },
                );
            }
        }
        drop(map);
        if repaired {
            self.dirty.store(true, Ordering::Relaxed);
            tracing::info!("account_learning 落盘数据已修复 inverted safe_rps bounds");
        }
        tracing::info!("已加载 {} 条账号学习状态", self.accounts.lock().len());
    }

    pub fn all_snapshots(&self) -> HashMap<u64, AccountLearningPersisted> {
        self.accounts
            .lock()
            .iter()
            .map(|(id, e)| (*id, e.persisted.clone()))
            .collect()
    }
}

impl AccountLearningEntry {
    fn clone_entry(&self) -> AccountLearningEntry {
        AccountLearningEntry {
            persisted: self.persisted.clone(),
            runtime: AccountLearningRuntime {
                held_samples: self.runtime.held_samples.clone(),
                last_stable_success: self.runtime.last_stable_success,
                legacy_converged: self.runtime.legacy_converged,
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LearningFile {
    accounts: HashMap<String, AccountLearningPersisted>,
}

fn compute_bottleneck(p: &AccountLearningPersisted) -> BottleneckDimension {
    if p.real_sample_count < MIN_SAMPLES_FOR_BOTTLENECK {
        return BottleneckDimension::SendRate;
    }
    let mut scores = [
        (BottleneckDimension::Inflight, p.inflight_buckets.monotonic_score()),
        (BottleneckDimension::SendRate, p.send_rate_buckets.monotonic_score()),
        (BottleneckDimension::Rpm, p.rpm_buckets.monotonic_score()),
    ];
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    if scores[0].1 < 0.05 {
        return BottleneckDimension::SendRate;
    }
    if scores.len() >= 2 && scores[0].1 - scores[1].1 < scores[0].1 * 0.3 {
        BottleneckDimension::Mixed
    } else {
        scores[0].0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn store() -> Arc<LearningStore> {
        let path = temp_dir().join(format!("account_learning_test_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        LearningStore::new(LearningConfig::default(), Some(path))
    }

    #[test]
    fn test_bottleneck_inflight_when_high_inflight_429s() {
        let s = store();
        for i in 0..30 {
            let bucket = (i / 6).min(4);
            let inflight = [3, 9, 15, 22, 28][bucket];
            s.record_sample(
                1,
                SendContextSample {
                    inflight,
                    sends_last_1s: 1,
                    rpm_last_60s: 5,
                    send_rate_rps: 1.0,
                    was_429: bucket >= 3,
                },
            );
        }
        assert_eq!(s.bottleneck(1), BottleneckDimension::Inflight);
    }

    #[test]
    fn test_bottleneck_send_rate_when_high_send_429s() {
        let s = store();
        for i in 0..30 {
            s.record_sample(
                2,
                SendContextSample {
                    inflight: 2,
                    sends_last_1s: if i > 15 { 9 } else { 1 },
                    rpm_last_60s: 5,
                    send_rate_rps: if i > 15 { 3.0 } else { 0.5 },
                    was_429: i > 15,
                },
            );
        }
        assert_eq!(s.bottleneck(2), BottleneckDimension::SendRate);
    }

    #[test]
    fn test_safe_rps_ewma() {
        let s = store();
        for _ in 0..10 {
            s.record_sample(
                3,
                SendContextSample {
                    inflight: 1,
                    sends_last_1s: 1,
                    rpm_last_60s: 3,
                    send_rate_rps: 1.2,
                    was_429: false,
                },
            );
        }
        let (_, hi) = s.learned_safe_rps(3);
        assert!(hi >= 1.0, "无 429 时 safe_hi 应上抬: {hi}");
        s.record_sample(
            3,
            SendContextSample {
                inflight: 1,
                sends_last_1s: 2,
                rpm_last_60s: 3,
                send_rate_rps: 1.0,
                was_429: true,
            },
        );
        let (_, hi2) = s.learned_safe_rps(3);
        assert!(hi2 < hi, "429 后 safe_hi 应回落: {hi} -> {hi2}");
    }

    #[test]
    fn test_quarantine_t_doubles_on_fail_shortens_on_stable() {
        let s = store();
        let initial = s.optimal_quarantine(9, 30).as_secs();
        assert_eq!(initial, 30);
        s.on_quarantine_probe_failed(9, 1800);
        assert_eq!(s.optimal_quarantine(9, 30).as_secs(), 60);
        s.on_quarantine_probe_stable(9, 5);
        assert!(s.optimal_quarantine(9, 30).as_secs() < 60);
    }

    #[test]
    fn test_persist_roundtrip() {
        let path = temp_dir().join(format!("account_learning_rt_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let s = LearningStore::new(LearningConfig::default(), Some(path.clone()));
            s.record_held_ms(17, 42_000);
            s.save();
        }
        let s2 = LearningStore::new(LearningConfig::default(), Some(path.clone()));
        let snap = s2.snapshot(17).expect("应加载 id=17");
        assert_eq!(snap.p80_held_ms, 42_000);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_repairs_inverted_bounds() {
        let path = temp_dir().join(format!("account_learning_inv_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            r#"{"accounts":{"17":{"safeRpsLo":0.101,"safeRpsHi":0.075,"p80HeldMs":30000,"optimalQuarantineSecs":30,"bottleneckDimension":"SendRate"}}}"#,
        )
        .expect("write inverted learning file");
        let s = LearningStore::new(LearningConfig::default(), Some(path.clone()));
        let (lo, hi) = s.learned_safe_rps(17);
        assert!(lo <= hi, "loaded bounds must be normalized: lo={lo} hi={hi}");
        assert!((lo - 0.075).abs() < 1e-9);
        assert!((hi - 0.101).abs() < 1e-9);
        let _ = std::fs::remove_file(&path);
    }

    // ---- Task 2: H2 成熟度真实化（单维真实请求计数，不再三维 ×3） ----

    #[test]
    fn test_maturity_uses_real_request_count_not_tripled() {
        // H2 回归：每个 record_sample 是 1 个真实请求。旧实现把 inflight+sendRate+rpm
        // 三维样本数相加 → 7 个真请求被算成 21 → min_samples=20 时误判「成熟」。
        // 修复后：7 个真请求 NOT mature，20 个真请求才 mature。
        let s = store();
        for _ in 0..7 {
            s.record_sample(
                1,
                SendContextSample {
                    inflight: 2,
                    sends_last_1s: 1,
                    rpm_last_60s: 5,
                    send_rate_rps: 1.0,
                    was_429: false,
                },
            );
        }
        assert!(
            !s.learning_is_mature(1, 20),
            "7 个真实请求不应判成熟（旧 bug 会因三维 ×3=21 误判成熟）"
        );
        for _ in 0..13 {
            s.record_sample(
                1,
                SendContextSample {
                    inflight: 2,
                    sends_last_1s: 1,
                    rpm_last_60s: 5,
                    send_rate_rps: 1.0,
                    was_429: false,
                },
            );
        }
        assert!(
            s.learning_is_mature(1, 20),
            "20 个真实请求应判成熟"
        );
    }

    #[test]
    fn test_learning_sample_count_is_per_request() {
        let s = store();
        for _ in 0..10 {
            s.record_sample(
                2,
                SendContextSample {
                    inflight: 2,
                    sends_last_1s: 1,
                    rpm_last_60s: 5,
                    send_rate_rps: 1.0,
                    was_429: false,
                },
            );
        }
        assert_eq!(
            s.learning_sample_count(2),
            10,
            "样本计数应等于真实请求数（10），不是三维之和（30）"
        );
    }

    // ---- Task 2: H1 桶时间衰减（旧 429 随时间被遗忘） ----

    #[test]
    fn test_bucket_decay_halves_counts_after_one_half_life() {
        // 一个 bucket 累计若干样本，经过 1 个半衰期后计数应减半（误差容忍 10%）。
        let mut b = BucketStats::new(5);
        for _ in 0..100 {
            b.record(2, true);
        }
        let (total_before, th_before) = b.buckets[2];
        assert!((total_before - 100.0).abs() < 1e-6);
        assert!((th_before - 100.0).abs() < 1e-6);
        b.decay_by_half_lives(1.0);
        let (total_after, th_after) = b.buckets[2];
        assert!(
            (total_after - 50.0).abs() < 5.0,
            "1 个半衰期后 total 应约减半: {total_before} -> {total_after}"
        );
        assert!(
            (th_after - 50.0).abs() < 5.0,
            "1 个半衰期后 throttle 应约减半: {th_before} -> {th_after}"
        );
    }

    #[test]
    fn test_decay_fades_bucket_429_but_preserves_maturity() {
        // H1 回归 + P2-a 防回归：衰减让桶里的旧 429「绝对计数」淡出（旧账不永久压制），
        // 但 real_sample_count（成熟度门）**绝不衰减**——否则低流量号会在 idle 时跌回未成熟、
        // floor 退回 min_rate（#19 病复活）。
        let s = store();
        for _ in 0..40 {
            s.record_sample(
                3,
                SendContextSample {
                    inflight: 2,
                    sends_last_1s: 9,
                    rpm_last_60s: 5,
                    send_rate_rps: 3.0,
                    was_429: true,
                },
            );
        }
        assert_eq!(s.learning_sample_count(3), 40, "衰减前 40 真实样本");
        assert!(s.learning_is_mature(3, 20), "40 样本应成熟");
        // 模拟「过了很多个半衰期」。
        s.decay_all(20.0);
        // ① 桶里的旧 429 绝对计数应趋近 0（旧账淡出，不再永久压制 monotonic_score/瓶颈判定）。
        let snap = s.snapshot(3).expect("account exists");
        let bucket_total: f64 = snap.send_rate_buckets.buckets.iter().map(|(t, _)| t).sum();
        assert!(
            bucket_total < 5.0,
            "衰减 20 个半衰期后桶样本绝对计数应趋近 0: {bucket_total}"
        );
        // ② 但成熟度门(real_sample_count)绝不衰减——仍是 40、仍成熟（P2-a 防回归）。
        assert_eq!(
            s.learning_sample_count(3),
            40,
            "real_sample_count 不应随衰减下降（成熟度是单调 latch）"
        );
        assert!(
            s.learning_is_mature(3, 20),
            "衰减后仍应保持成熟，不能跌回未成熟导致 floor 退回 min_rate"
        );
    }
}

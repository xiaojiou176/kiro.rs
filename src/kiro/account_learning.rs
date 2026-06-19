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
    buckets: Vec<(u64, u64)>,
}

impl BucketStats {
    fn new(n: usize) -> Self {
        Self {
            buckets: vec![(0, 0); n],
        }
    }

    fn record(&mut self, bucket: usize, was_429: bool) {
        if bucket >= self.buckets.len() {
            return;
        }
        self.buckets[bucket].0 += 1;
        if was_429 {
            self.buckets[bucket].1 += 1;
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
            if t_lo == 0 || t_hi == 0 {
                continue;
            }
            let r_lo = th_lo as f64 / t_lo as f64;
            let r_hi = th_hi as f64 / t_hi as f64;
            let w = (t_lo + t_hi) as f64;
            score += (r_hi - r_lo).max(0.0) * w;
            weight += w;
        }
        if weight > 0.0 {
            score / weight
        } else {
            0.0
        }
    }

    fn total_samples(&self) -> u64 {
        self.buckets.iter().map(|(t, _)| t).sum()
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

    /// 累计学习样本数（三维度分桶之和）。
    pub fn learning_sample_count(&self, id: u64) -> u64 {
        self.snapshot(id)
            .map(|p| {
                p.inflight_buckets.total_samples()
                    + p.send_rate_buckets.total_samples()
                    + p.rpm_buckets.total_samples()
            })
            .unwrap_or(0)
    }

    /// 分桶样本足够，或磁盘加载时已收敛的 legacy safe_rps 时视为成熟。
    pub fn learning_is_mature(&self, id: u64, min_samples: u64) -> bool {
        let map = self.accounts.lock();
        let Some(entry) = map.get(&id) else {
            return false;
        };
        let samples = entry.persisted.inflight_buckets.total_samples()
            + entry.persisted.send_rate_buckets.total_samples()
            + entry.persisted.rpm_buckets.total_samples();
        if samples >= min_samples {
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
                let samples = v.inflight_buckets.total_samples()
                    + v.send_rate_buckets.total_samples()
                    + v.rpm_buckets.total_samples();
                let legacy_converged =
                    samples < MIN_SAMPLES_FOR_BOTTLENECK && persisted_deviates_from_factory(&v);
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
    let total = p.inflight_buckets.total_samples()
        + p.send_rate_buckets.total_samples()
        + p.rpm_buckets.total_samples();
    if total < MIN_SAMPLES_FOR_BOTTLENECK {
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
}

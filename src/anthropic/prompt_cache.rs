//! 中转层 prompt cache（无外部依赖）
//!
//! Kiro 上游不下发 cache_creation / cache_read token 字段（实测 meteringEvent
//! 只给 credit 计费量），所以这里在中转层基于请求体里的 `cache_control` 断点
//! 自行做"提示词缓存"，按 Anthropic 协议（最多 4 个断点、每个断点累加哈希
//! 形成一个前缀段）逐段判断命中：
//!
//! - 命中最深的某段 → 该段及之前所有段 token 总数 = `cache_read_input_tokens`
//! - 比命中段更深的、本次出现的新段 → 它们的 token 总数 = `cache_creation_input_tokens`
//! - 完全 miss → cache_creation = 全部段 tokens，cache_read = 0
//!
//! 内存 + JSON 落盘：每分钟一次写到 `cache_dir/prompt_cache.json`，启动时读
//! 回过期记录会被丢掉。**不依赖 Redis 或任何外部 KV**。

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// 默认条目上限（防止内存无限增长）
const DEFAULT_CAPACITY: usize = 4096;
/// 最长 TTL（1h，与 Anthropic ttl="1h" 对齐）
const MAX_TTL_SECS: i64 = 3600;
/// 默认 TTL（5min，ephemeral 默认值）
const DEFAULT_TTL_SECS: i64 = 5 * 60;

/// 单个缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// 该前缀段累计的估算 token 数
    pub tokens: u32,
    /// 过期时间戳（unix 秒）
    pub expires_at: i64,
    /// 上次命中时间（用于 LRU 淘汰）
    pub last_hit_at: i64,
}

/// 一次查询的结果（每段一份）
#[derive(Debug, Clone, Copy)]
pub struct SegmentResult {
    /// 该段是否命中
    pub hit: bool,
    /// 该段累计 tokens（保留供调试 / 调用方扩展，dead_code 抑制）
    #[allow(dead_code)]
    pub tokens: u32,
}

/// 进程内提示词缓存
pub struct PromptCache {
    inner: Mutex<Inner>,
    persist_path: Option<PathBuf>,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<u64, CacheEntry>,
    /// 自上次落盘后是否有变化
    dirty: bool,
}

impl PromptCache {
    /// 创建一个空 cache。`persist_path` 为 `Some` 时会自动从该文件加载历史。
    pub fn new(persist_path: Option<PathBuf>) -> Self {
        let mut inner = Inner::default();
        if let Some(path) = persist_path.as_ref() {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(entries) = serde_json::from_slice::<HashMap<u64, CacheEntry>>(&bytes) {
                    let now = now_secs();
                    for (k, v) in entries {
                        if v.expires_at > now {
                            inner.entries.insert(k, v);
                        }
                    }
                    tracing::info!(
                        "PromptCache 重建：从 {} 加载 {} 条有效记录",
                        path.display(),
                        inner.entries.len()
                    );
                }
            }
        }
        Self {
            inner: Mutex::new(inner),
            persist_path,
        }
    }

    /// 查询一组前缀段哈希，返回每段命中情况；命中段会刷新 last_hit_at。
    ///
    /// `segment_hashes` 顺序必须与请求中 cache_control 断点顺序一致；
    /// `segment_tokens` 是每段累计 tokens（即 segment_hashes[i] 对应的整段累加值）。
    pub fn lookup(&self, segment_hashes: &[u64], segment_tokens: &[u32]) -> Vec<SegmentResult> {
        debug_assert_eq!(segment_hashes.len(), segment_tokens.len());
        let now = now_secs();
        let mut inner = self.inner.lock();
        let mut out = Vec::with_capacity(segment_hashes.len());
        for (h, t) in segment_hashes.iter().zip(segment_tokens.iter()) {
            let hit = match inner.entries.get_mut(h) {
                Some(entry) if entry.expires_at > now => {
                    entry.last_hit_at = now;
                    true
                }
                _ => false,
            };
            out.push(SegmentResult { hit, tokens: *t });
        }
        out
    }

    /// 把一组前缀段写入缓存（用于 miss 后登记 / 续期）。`ttl_secs` clip 到 [60, MAX_TTL_SECS]。
    pub fn record(&self, segment_hashes: &[u64], segment_tokens: &[u32], ttl_secs: i64) {
        debug_assert_eq!(segment_hashes.len(), segment_tokens.len());
        let ttl = ttl_secs.clamp(60, MAX_TTL_SECS);
        let now = now_secs();
        let expires_at = now + ttl;
        let mut inner = self.inner.lock();
        for (h, t) in segment_hashes.iter().zip(segment_tokens.iter()) {
            inner.entries.insert(
                *h,
                CacheEntry {
                    tokens: *t,
                    expires_at,
                    last_hit_at: now,
                },
            );
        }
        inner.dirty = true;
        // 容量超限：按 last_hit_at 淘汰最旧的若干条
        if inner.entries.len() > DEFAULT_CAPACITY {
            let drop_n = inner.entries.len() - DEFAULT_CAPACITY;
            let mut victims: Vec<(u64, i64)> = inner
                .entries
                .iter()
                .map(|(k, v)| (*k, v.last_hit_at))
                .collect();
            victims.sort_by_key(|x| x.1);
            for (k, _) in victims.into_iter().take(drop_n) {
                inner.entries.remove(&k);
            }
        }
    }

    /// 把当前快照写到 persist_path（仅在 dirty 时实际落盘）
    pub fn flush_to_disk(&self) {
        let path = match self.persist_path.clone() {
            Some(p) => p,
            None => return,
        };
        let snapshot = {
            let mut inner = self.inner.lock();
            if !inner.dirty {
                return;
            }
            inner.dirty = false;
            inner.entries.clone()
        };
        let json = match serde_json::to_vec(&snapshot) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("PromptCache 序列化失败: {}", e);
                return;
            }
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&path, json) {
            tracing::warn!("PromptCache 落盘失败 {}: {}", path.display(), e);
        }
    }

    /// 启动后台周期任务：定期 flush + 清理过期条目
    pub fn spawn_background(self: Arc<Self>) {
        let weak = Arc::downgrade(&self);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(60);
            loop {
                tokio::time::sleep(interval).await;
                let Some(cache) = weak.upgrade() else { return };
                cache.evict_expired();
                cache.flush_to_disk();
            }
        });
    }

    /// 删除已过期条目（lookup 不命中过期时只是返回 miss，不会顺手清理；
    /// 这里在后台周期里清一次，避免内存膨胀）。
    pub fn evict_expired(&self) {
        let now = now_secs();
        let mut inner = self.inner.lock();
        let before = inner.entries.len();
        inner.entries.retain(|_, v| v.expires_at > now);
        if inner.entries.len() != before {
            inner.dirty = true;
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 解析 cache_control 的 ttl 字符串（"5m" / "1h"）→ 秒
pub fn parse_ttl(ttl: Option<&str>) -> i64 {
    match ttl {
        Some(s) if s.eq_ignore_ascii_case("1h") => 3600,
        Some(s) if s.eq_ignore_ascii_case("5m") => 300,
        _ => DEFAULT_TTL_SECS,
    }
}

/// `Arc<PromptCache>` 别名
pub type SharedPromptCache = Arc<PromptCache>;

// ============================================================================
// 与请求体协议层的接线
// ============================================================================

use super::stream::estimate_tokens;
use super::types::{CacheControl, ContentBlock, MessagesRequest, SystemMessage, Tool};

/// 协议层提取出来的一个"段"（segment）：从请求开头累计到本断点的所有内容。
///
/// `tokens` 是该前缀**累计**的估算 token 数；`hash` 由前缀文本的累加 SHA-256
/// 折叠得到（取低 64 位作 key，与 PromptCache 的 u64 key 兼容）。
#[derive(Debug, Clone, Copy)]
struct Segment {
    hash: u64,
    cumulative_tokens: u32,
    /// 该段单独的 ttl（秒）
    ttl_secs: i64,
}

/// 调用 PromptCache 计算本次请求的 cache_creation / cache_read token，
/// 并在最后把所有断点（含命中段）记录回 cache，刷新 TTL。
///
/// **完全按 Anthropic 协议**：取最深命中的段索引 i*，那么
/// - `cache_read = segments[i*].cumulative_tokens`
/// - `cache_creation = segments.last().cumulative_tokens - segments[i*].cumulative_tokens`
/// 全部 miss 时 cache_read = 0，cache_creation = 最深段累计 tokens。
///
/// 没有任何 cache_control 断点时，直接返回 (0, 0) 且不写入。
/// 调用 PromptCache 计算本次请求的 cache_creation / cache_read token，
/// 并在最后把所有断点（含命中段）记录回 cache，刷新 TTL。
///
/// **完全按 Anthropic 协议**：取最深命中的段索引 i*，那么
/// - `cache_read = segments[i*].cumulative_tokens`
/// - `cache_creation = segments.last().cumulative_tokens - segments[i*].cumulative_tokens`
/// 全部 miss 时 cache_read = 0，cache_creation = 最深段累计 tokens。
///
/// 返回 `(cache_creation, cache_read)`。没有任何 cache_control 断点时
/// 直接返回 `(0, 0)` 且不写入。
pub fn compute_cache_usage(cache: &PromptCache, req: &MessagesRequest) -> (i32, i32) {
    let segments = extract_segments(req);
    if segments.is_empty() {
        return (0, 0);
    }

    let hashes: Vec<u64> = segments.iter().map(|s| s.hash).collect();
    let cum_tokens: Vec<u32> = segments.iter().map(|s| s.cumulative_tokens).collect();
    let results = cache.lookup(&hashes, &cum_tokens);

    let deepest_hit = results.iter().rposition(|r| r.hit);
    let total = *cum_tokens.last().unwrap();
    let (cache_creation, cache_read) = match deepest_hit {
        Some(i) => (total.saturating_sub(cum_tokens[i]), cum_tokens[i]),
        None => (total, 0u32),
    };

    // 把所有段都写回（命中段会刷新 last_hit_at；未命中段会被插入）
    for (idx, seg) in segments.iter().enumerate() {
        cache.record(&[seg.hash], &[cum_tokens[idx]], seg.ttl_secs);
    }

    (cache_creation as i32, cache_read as i32)
}

/// 从请求体里按顺序提取断点段：tools → system → messages
///
/// 这个顺序与 Anthropic 拼接 prompt 的顺序对齐：tools 在最前，system 次之，
/// 然后才是 messages。每遇到一个 cache_control 断点就产生一个 Segment。
/// 累计 token 数随处理顺序累加，永远是当前位置的"前缀总量"。
fn extract_segments(req: &MessagesRequest) -> Vec<Segment> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut cum_tokens: u32 = 0;
    let mut segments: Vec<Segment> = Vec::new();

    let feed = |hasher: &mut Sha256, text: &str, cum: &mut u32| {
        hasher.update(text.as_bytes());
        *cum = cum.saturating_add(estimate_tokens(text).max(0) as u32);
    };

    let commit = |hasher: &Sha256,
                  cum: u32,
                  segments: &mut Vec<Segment>,
                  cc: &CacheControl| {
        let digest = hasher.clone().finalize();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&digest[..8]);
        let hash = u64::from_be_bytes(buf);
        segments.push(Segment {
            hash,
            cumulative_tokens: cum,
            ttl_secs: parse_ttl(cc.ttl.as_deref()),
        });
    };

    // 1. tools
    if let Some(tools) = req.tools.as_ref() {
        for t in tools {
            feed(&mut hasher, &tool_signature(t), &mut cum_tokens);
            if let Some(cc) = t.cache_control.as_ref() {
                commit(&hasher, cum_tokens, &mut segments, cc);
            }
        }
    }

    // 2. system
    if let Some(systems) = req.system.as_ref() {
        for sys in systems {
            feed(&mut hasher, &system_signature(sys), &mut cum_tokens);
            if let Some(cc) = sys.cache_control.as_ref() {
                commit(&hasher, cum_tokens, &mut segments, cc);
            }
        }
    }

    // 3. messages（每条消息的 content 可能是 string / array）
    for msg in req.messages.iter() {
        feed(&mut hasher, &msg.role, &mut cum_tokens);
        match &msg.content {
            serde_json::Value::String(s) => {
                feed(&mut hasher, s, &mut cum_tokens);
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    if let Ok(block) = serde_json::from_value::<ContentBlock>(v.clone()) {
                        feed(&mut hasher, &block_signature(&block), &mut cum_tokens);
                        if let Some(cc) = block.cache_control.as_ref() {
                            commit(&hasher, cum_tokens, &mut segments, cc);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    segments
}

fn tool_signature(t: &Tool) -> String {
    // 把 name + description + input_schema 序列化为稳定文本
    let schema = serde_json::to_string(&t.input_schema).unwrap_or_default();
    format!("tool:{}|{}|{}", t.name, t.description, schema)
}

fn system_signature(s: &SystemMessage) -> String {
    format!("sys:{}", s.text)
}

fn block_signature(b: &ContentBlock) -> String {
    // 仅 text 块参与签名；image 等块的二进制不加进估算（避免大 base64 把估算撑爆）
    let text = b.text.as_deref().unwrap_or("");
    let thinking = b.thinking.as_deref().unwrap_or("");
    format!("block:{}|{}|{}", b.block_type, text, thinking)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_miss_then_record_then_hit() {
        let cache = PromptCache::new(None);
        let hashes = [1u64, 2u64];
        let tokens = [10u32, 25u32];
        let r1 = cache.lookup(&hashes, &tokens);
        assert!(r1.iter().all(|s| !s.hit));

        cache.record(&hashes, &tokens, 300);
        let r2 = cache.lookup(&hashes, &tokens);
        assert!(r2.iter().all(|s| s.hit));
    }

    #[test]
    fn ttl_expiry_makes_entry_miss() {
        let cache = PromptCache::new(None);
        cache.record(&[42], &[100], 60);
        // 手动让条目过期
        {
            let mut inner = cache.inner.lock();
            if let Some(e) = inner.entries.get_mut(&42) {
                e.expires_at = now_secs() - 1;
            }
        }
        let r = cache.lookup(&[42], &[100]);
        assert!(!r[0].hit);
    }

    #[test]
    fn evict_expired_removes_dead_entries() {
        let cache = PromptCache::new(None);
        cache.record(&[1, 2], &[5, 5], 60);
        {
            let mut inner = cache.inner.lock();
            for (_, v) in inner.entries.iter_mut() {
                v.expires_at = now_secs() - 1;
            }
        }
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn parse_ttl_handles_known_values() {
        assert_eq!(parse_ttl(Some("1h")), 3600);
        assert_eq!(parse_ttl(Some("5m")), 300);
        assert_eq!(parse_ttl(None), 300);
        assert_eq!(parse_ttl(Some("garbage")), 300);
    }

    #[test]
    fn flush_and_reload_round_trip() {
        let tmp = std::env::temp_dir().join(format!("kiro-pc-{}.json", now_secs()));
        let cache = PromptCache::new(Some(tmp.clone()));
        cache.record(&[7], &[42], 600);
        cache.flush_to_disk();

        let cache2 = PromptCache::new(Some(tmp.clone()));
        let r = cache2.lookup(&[7], &[42]);
        assert!(r[0].hit);

        let _ = std::fs::remove_file(&tmp);
    }

    fn build_request_with_system_breakpoint() -> super::super::types::MessagesRequest {
        use super::super::types::{CacheControl, Message, MessagesRequest, SystemMessage};
        MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 32,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::Value::String("Hello".to_string()),
            }],
            stream: false,
            system: Some(vec![SystemMessage {
                text: "You are a helpful assistant. ".repeat(100),
                cache_control: Some(CacheControl {
                    cache_type: "ephemeral".to_string(),
                    ttl: None,
                }),
            }]),
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        }
    }

    #[test]
    fn compute_cache_usage_first_miss_then_hit() {
        let cache = PromptCache::new(None);
        let req = build_request_with_system_breakpoint();

        // 第一次：所有段都 miss → cache_creation > 0, cache_read == 0
        let (cc1, cr1) = compute_cache_usage(&cache, &req);
        assert!(cc1 > 0, "first call should write cache, cc={}", cc1);
        assert_eq!(cr1, 0);

        // 第二次：相同请求 → cache_read > 0, cache_creation == 0
        let (cc2, cr2) = compute_cache_usage(&cache, &req);
        assert_eq!(cc2, 0, "second call should not record creation, got {}", cc2);
        assert!(cr2 > 0, "second call should hit, cr={}", cr2);
        // 两次的 read 应等于第一次的 creation（同一个最深段累计 tokens）
        assert_eq!(cc1, cr2);
    }

    #[test]
    fn compute_cache_usage_no_breakpoints_returns_zero() {
        use super::super::types::{Message, MessagesRequest};
        let cache = PromptCache::new(None);
        let req = MessagesRequest {
            model: "x".to_string(),
            max_tokens: 8,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::Value::String("Hello".to_string()),
            }],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        };
        assert_eq!(compute_cache_usage(&cache, &req), (0, 0));
    }
}

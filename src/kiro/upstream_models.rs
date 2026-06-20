//! 上游真实可用模型缓存
//!
//! 缓存上游 `ListAvailableModels` 返回的真实 `model_id` 集合，供两处复用：
//! - `converter::should_emit_output_config` 的 effort 门动态判定（模型上游存在即放行）；
//! - `handlers::available_models` 的模型列表动态生成（只暴露上游真实模型，零虚标）。
//!
//! 模式照抄 `kiro_version.rs`：进程内 `OnceLock<RwLock<Option<...>>>` 缓存 + 后台
//! 定时刷新。拉取失败仅告警、保留旧缓存、不阻塞服务（调用方走各自的 fallback）。
//!
//! 存储归一化：所有 `model_id` 一律以小写存入；查询时也转小写，避免大小写抖动。

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use parking_lot::RwLock;

use crate::kiro::model::available_models::ListAvailableModelsResponse;

/// 进程内缓存：上游真实 model_id 集合（小写归一化）。后台刷新成功前为 `None`。
static UPSTREAM_MODELS: OnceLock<RwLock<Option<HashSet<String>>>> = OnceLock::new();

fn cell() -> &'static RwLock<Option<HashSet<String>>> {
    UPSTREAM_MODELS.get_or_init(|| RwLock::new(None))
}

/// 归一化 model_id 作为缓存键：小写 + 把版本号分隔符统一（`4-8` 与 `4.8` 视为同一模型）。
///
/// 上游 `ListAvailableModels` 真机实测返回点号形态（`claude-opus-4.8`），而对外/客户端常用
/// dash 形态（`claude-opus-4-8`）。统一成「点号」单一形态做键，存取两侧都归一，彻底消除
/// 「上游若改用 dash 形态 → 交集全空 → effort/列表静默降级」这一类形态错配风险。
fn normalize_model_key(model_id: &str) -> String {
    // 仅折叠「数字-数字」里的连字符为点号（版本分隔），不动模型名里其它连字符
    // （如 `claude-opus`）。例：`claude-opus-4-8` -> `claude-opus-4.8`。
    let lower = model_id.to_lowercase();
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(lower.len());
    for (i, ch) in lower.char_indices() {
        if ch == '-'
            && i > 0
            && i + 1 < bytes.len()
            && bytes[i - 1].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
        {
            out.push('.');
        } else {
            out.push(ch);
        }
    }
    out
}

/// 当前缓存快照（已小写归一化的 model_id 集合）。后台刷新成功前为 `None`。
pub fn cached() -> Option<HashSet<String>> {
    cell().read().clone()
}

/// 同步判定：给定一个**已 `map_model` 归一化后的** model_id（如 `"claude-opus-4.8"`），
/// 它是否在上游真实清单里。缓存为空（还没拉到）时返回 `fallback`。查询大小写不敏感。
pub fn contains_or(model_id: &str, fallback: bool) -> bool {
    match cell().read().as_ref() {
        Some(set) => set.contains(&normalize_model_key(model_id)),
        None => fallback,
    }
}

/// 返回缓存里全部 model_id（小写）。缓存空时 `None`。给模型列表动态生成用。
pub fn snapshot() -> Option<Vec<String>> {
    cell()
        .read()
        .as_ref()
        .map(|set| set.iter().cloned().collect())
}

/// 判定某个（任意形态的）model_id 是否在上游缓存里；缓存为空时返回 `fallback`。
/// 查询侧同样走 `normalize_model_key`，保证与存储侧形态一致（dot/dash 等价）。
/// 供 `handlers::available_models` 做交集时复用，避免两处归一化口径不一致。
pub fn contains_normalized(model_id: &str) -> bool {
    match cell().read().as_ref() {
        Some(set) => set.contains(&normalize_model_key(model_id)),
        None => false,
    }
}

/// 用一个已取得的 `ListAvailableModelsResponse` 刷新缓存（小写归一化后写入）。
pub fn store_from_response(resp: &ListAvailableModelsResponse) {
    let set: HashSet<String> = resp
        .models
        .iter()
        .map(|m| normalize_model_key(&m.model_id))
        .collect();
    if !set.is_empty() {
        // 诊断观测：打印上游真实 model_id 原始形态 + 归一化后键，便于核对交集匹配
        // （effort 门 / 模型列表都依赖这份缓存与裸目录的交集）。
        let raw: Vec<&str> = resp.models.iter().map(|m| m.model_id.as_str()).collect();
        tracing::info!(
            count = set.len(),
            raw_model_ids = ?raw,
            normalized_keys = ?set,
            "上游 ListAvailableModels 真实返回（已写入缓存）"
        );
        *cell().write() = Some(set);
    }
}

/// 启动期 bootstrap：在后台 refresher 第一次成功拉到上游清单之前，先用一份「已知真实存在的
/// 上游模型」种子填充缓存，**仅当缓存还为空时生效**（不覆盖已被 refresher 写入的真实数据）。
///
/// 目的：避免冷启动窗口（或上游拉取一直失败时）effort 门 / 模型列表退化——effort 必须能立即
/// 工作。种子来自 `handlers` 的裸模型目录（都是有抓包/清单证据的真实上游模型，非虚标）。
/// refresher 一旦成功就用上游真实清单覆盖，种子只是「拉到之前的合理默认」。
pub fn bootstrap_if_empty<I, S>(seed: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut guard = cell().write();
    if guard.is_some() {
        return;
    }
    let set: HashSet<String> = seed
        .into_iter()
        .map(|s| normalize_model_key(s.as_ref()))
        .collect();
    if !set.is_empty() {
        *guard = Some(set);
    }
}

/// 拉取器类型：返回上游 `ListAvailableModels` 响应。由调用方（持有 `TokenManager`/凭据）注入，
/// 让本模块与具体取 token / 选凭据的逻辑解耦、可独立编译与测试。
pub type FetchFn = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = anyhow::Result<ListAvailableModelsResponse>> + Send>>
        + Send
        + Sync,
>;

/// 拉取一次并写入缓存。成功返回 `Ok(())`，失败返回错误（不改动现有缓存）。
pub async fn fetch_once(fetch: &FetchFn) -> anyhow::Result<()> {
    let resp = fetch().await?;
    store_from_response(&resp);
    Ok(())
}

/// 启动后台任务：立即拉取一次，之后每 `interval` 刷新一次。
///
/// 失败仅记录告警，不影响服务（调用方走各自 fallback）。照抄 `kiro_version::spawn_refresher`。
pub fn spawn_refresher(fetch: FetchFn, interval: Duration) {
    tokio::spawn(async move {
        loop {
            match fetch_once(&fetch).await {
                Ok(()) => {
                    let n = cached().map(|s| s.len()).unwrap_or(0);
                    tracing::info!("已刷新上游可用模型缓存: {} 个模型", n);
                }
                Err(e) => {
                    tracing::warn!("刷新上游可用模型缓存失败（继续使用旧缓存/fallback）: {}", e);
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// 测试注入口：直接设置缓存内容（小写归一化后写入）。
#[cfg(test)]
pub fn set_cache_for_test(set: HashSet<String>) {
    let lowered: HashSet<String> = set.iter().map(|s| normalize_model_key(s)).collect();
    *cell().write() = Some(lowered);
}

/// 测试注入口：清空缓存（回到 `None`）。
#[cfg(test)]
pub fn clear_cache_for_test() {
    *cell().write() = None;
}

/// 测试串行锁：`UPSTREAM_MODELS` 是进程级全局缓存，多个测试并发
/// `set_cache_for_test`/`clear_cache_for_test` 会互相污染（一个测试的 clear 擦掉
/// 另一个刚 set 的内容）。任何读写该全局缓存的测试都必须在函数体开头持有此锁，
/// 把这组测试串行化。纯 std，零外部依赖。
///
/// 中毒处理：某个持锁测试 panic 会让 `Mutex` 进入 poisoned 状态；用
/// `lock_test()` 统一恢复 inner guard，避免一个 panic 连累整组测试。
#[cfg(test)]
pub static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 取测试串行锁，自动从 poisoned 状态恢复。
#[cfg(test)]
pub fn lock_test() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_or_empty_cache_returns_fallback() {
        let _g = lock_test();
        clear_cache_for_test();
        assert!(contains_or("claude-opus-4.8", true));
        assert!(!contains_or("claude-opus-4.8", false));
        clear_cache_for_test();
    }

    #[test]
    fn test_contains_or_after_seed() {
        let _g = lock_test();
        set_cache_for_test(
            ["claude-opus-4.8", "claude-opus-4.7"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        assert!(contains_or("claude-opus-4.8", false));
        assert!(!contains_or("claude-opus-9.9", false));
        clear_cache_for_test();
    }

    #[test]
    fn test_snapshot_empty_then_seeded() {
        let _g = lock_test();
        clear_cache_for_test();
        assert!(snapshot().is_none());
        set_cache_for_test(["claude-opus-4.8".to_string()].into_iter().collect());
        let snap = snapshot().expect("seeded cache should snapshot");
        assert_eq!(snap, vec!["claude-opus-4.8".to_string()]);
        clear_cache_for_test();
    }

    #[test]
    fn test_case_insensitive_lookup() {
        let _g = lock_test();
        set_cache_for_test(["Claude-Opus-4.8".to_string()].into_iter().collect());
        assert!(contains_or("claude-opus-4.8", false));
        assert!(contains_or("CLAUDE-OPUS-4.8", false));
        clear_cache_for_test();
    }

    #[test]
    fn test_dash_dot_form_equivalence() {
        let _g = lock_test();
        // 上游若返回 dash 形态，查询用点号形态（或反之）必须仍命中。
        set_cache_for_test(["claude-opus-4-8".to_string()].into_iter().collect());
        assert!(contains_or("claude-opus-4.8", false), "dash-stored must match dot-query");
        assert!(contains_or("claude-opus-4-8", false), "dash-stored must match dash-query");
        clear_cache_for_test();
        set_cache_for_test(["claude-opus-4.8".to_string()].into_iter().collect());
        assert!(contains_or("claude-opus-4-8", false), "dot-stored must match dash-query");
        // 模型名里的非版本连字符不被折叠
        assert!(!contains_or("claude.opus.4.8", false), "non-version separators stay literal");
        clear_cache_for_test();
    }

    #[test]
    fn test_store_from_response_ignores_empty() {
        let _g = lock_test();
        clear_cache_for_test();
        let empty = ListAvailableModelsResponse { models: vec![] };
        store_from_response(&empty);
        assert!(cached().is_none(), "empty response must not overwrite cache");
        clear_cache_for_test();
    }

    #[test]
    fn test_bootstrap_if_empty_seeds_only_when_empty() {
        let _g = lock_test();
        clear_cache_for_test();
        // 空缓存 → bootstrap 种子生效
        bootstrap_if_empty(["claude-opus-4.8", "claude-opus-4.7"]);
        assert!(contains_or("claude-opus-4.8", false));
        assert!(contains_or("claude-opus-4.7", false));
        // 已有缓存（模拟 refresher 已写入真实数据）→ bootstrap 不覆盖
        set_cache_for_test(["claude-opus-4.8".to_string()].into_iter().collect());
        bootstrap_if_empty(["claude-sonnet-9.9"]);
        assert!(!contains_or("claude-sonnet-9.9", false), "bootstrap must not overwrite existing cache");
        assert!(contains_or("claude-opus-4.8", false));
        clear_cache_for_test();
    }
}

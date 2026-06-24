//! Codex thread 真名映射器。
//!
//! `metadata.user_id` 里的 `_session_<UUID>` == Codex thread id ==
//! `~/.codex/session_index.jsonl` 每行的 `id` 字段。该索引每行形如：
//! `{"id":"019e...","thread_name":"🤖【代码】...","updated_at":"2026-..Z"}`，
//! 同一个 id 会出现多行（名字改过），**取 `updated_at` 最新那行的 `thread_name`**。
//!
//! 这里提供一个进程内单例 [`ThreadNameResolver`]：按文件 mtime 做缓存，
//! mtime 没变就直接复用上次解析好的 `session_id -> thread_name` 映射，
//! 变了才重新逐行解析整个文件。解析鲁棒：文件缺失 / 坏行一律跳过、不 panic。

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::SystemTime;

/// 缓存内容：上次解析时的文件 mtime + 解析出的 `id -> thread_name` 映射。
#[derive(Default)]
struct CacheInner {
    /// 上次成功解析时文件的修改时间；`None` 表示尚未解析过 / 上次文件不存在。
    mtime: Option<SystemTime>,
    /// `session_id -> thread_name`（已按 `updated_at` 取最新）。
    map: HashMap<String, String>,
    /// 是否已经做过至少一次「读取尝试」（区分「从没读过」与「读过但文件缺失」）。
    primed: bool,
    /// 累计真正重新解析文件的次数（仅供测试验证 mtime 缓存命中，不对外暴露）。
    parse_count: u64,
}

/// Codex thread 真名映射器（按 mtime 缓存，线程安全）。
pub struct ThreadNameResolver {
    path: PathBuf,
    inner: Mutex<CacheInner>,
}

impl ThreadNameResolver {
    /// 用显式路径构造（测试与自定义用）。
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: Mutex::new(CacheInner::default()),
        }
    }

    /// 默认路径：`$HOME/.codex/session_index.jsonl`。
    ///
    /// 拿不到 `HOME` 时回退成相对路径 `.codex/session_index.jsonl`（解析时大概率读不到，
    /// 走「文件缺失返回空 map」的鲁棒分支，调用方回退显示 UUID）。
    pub fn default_path() -> PathBuf {
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".codex").join("session_index.jsonl"),
            None => PathBuf::from(".codex").join("session_index.jsonl"),
        }
    }

    /// 取某个 session_id 的真名；没有则返回 `None`（调用方回退 UUID）。
    pub fn name_for(&self, session_id: &str) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();
        self.refresh_if_needed(&mut inner);
        inner.map.get(session_id).cloned()
    }

    /// 若文件 mtime 与缓存不一致（或从未解析过）则重新解析；否则直接用缓存。
    fn refresh_if_needed(&self, inner: &mut CacheInner) {
        // 读不到 metadata（文件不存在等）→ 视为「无 mtime」。
        let current_mtime = fs::metadata(&self.path).and_then(|m| m.modified()).ok();

        // 已经读过、且 mtime 与上次一致 → 缓存命中，直接返回。
        // 注意：文件一直缺失时 current_mtime == None == 缓存 mtime，也算命中（不会反复读盘）。
        if inner.primed && inner.mtime == current_mtime {
            return;
        }

        let map = match fs::read_to_string(&self.path) {
            Ok(content) => Self::parse(&content),
            // 文件缺失 / 读失败 → 空 map（不 panic、不报错）。
            Err(_) => HashMap::new(),
        };

        inner.map = map;
        inner.mtime = current_mtime;
        inner.primed = true;
        inner.parse_count += 1;
    }

    /// 逐行解析 JSONL：按 `id` 聚合，取 `updated_at` 字符串最大（RFC3339 字典序==时间序）那行的 `thread_name`。
    /// 坏行（JSON 解析失败 / 缺字段）直接跳过。
    fn parse(content: &str) -> HashMap<String, String> {
        // id -> (best_updated_at, thread_name)
        let mut best: HashMap<String, (String, String)> = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let val: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue, // 坏行跳过
            };
            let id = match val.get("id").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            let name = match val.get("thread_name").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            // updated_at 缺失时用空串兜底（仍可被任何带 updated_at 的同 id 行覆盖）。
            let updated_at = val
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            match best.get(&id) {
                Some((cur_ua, _)) if *cur_ua >= updated_at => { /* 已有更新的，保留 */ }
                _ => {
                    best.insert(id, (updated_at, name));
                }
            }
        }
        best.into_iter().map(|(id, (_, name))| (id, name)).collect()
    }
}

/// 进程内全局单例（默认路径 `$HOME/.codex/session_index.jsonl`）。
pub fn resolver() -> &'static ThreadNameResolver {
    static RESOLVER: OnceLock<ThreadNameResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| ThreadNameResolver::new(ThreadNameResolver::default_path()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 进程内唯一的临时文件路径（避免并行测试撞名），用完即删。
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let mut path = std::env::temp_dir();
            path.push(format!("kiro_thread_names_{tag}_{pid}_{n}.jsonl"));
            Self { path }
        }

        fn write(&self, content: &str) {
            let mut f = fs::File::create(&self.path).unwrap();
            f.write_all(content.as_bytes()).unwrap();
            f.flush().unwrap();
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    /// ① 同一个 id 多行，取 updated_at 最新那行的 thread_name。
    #[test]
    fn picks_latest_updated_at_for_same_id() {
        let tmp = TempFile::new("latest");
        // 故意让「旧名」行排在「新名」行之后，验证靠的是 updated_at 而非行序。
        tmp.write(
            r#"{"id":"abc","thread_name":"旧名","updated_at":"2026-01-01T00:00:00Z"}
{"id":"abc","thread_name":"新名","updated_at":"2026-06-01T00:00:00Z"}
{"id":"abc","thread_name":"更旧","updated_at":"2025-12-01T00:00:00Z"}
"#,
        );
        let r = ThreadNameResolver::new(tmp.path.clone());
        assert_eq!(r.name_for("abc"), Some("新名".to_string()));
    }

    /// ② mtime 没变 → 走缓存（第二次调用不应重新解析；用 parse_count 验证）。
    #[test]
    fn cache_hit_when_mtime_unchanged() {
        let tmp = TempFile::new("cache");
        tmp.write(r#"{"id":"x","thread_name":"名","updated_at":"2026-06-01T00:00:00Z"}"#);
        let r = ThreadNameResolver::new(tmp.path.clone());

        assert_eq!(r.name_for("x"), Some("名".to_string()));
        assert_eq!(r.inner.lock().unwrap().parse_count, 1, "首次必解析一次");

        // 再查几次，文件没动 → parse_count 不应增长。
        assert_eq!(r.name_for("x"), Some("名".to_string()));
        assert_eq!(r.name_for("不存在"), None);
        assert_eq!(
            r.inner.lock().unwrap().parse_count,
            1,
            "mtime 未变应命中缓存、不重解析"
        );
    }

    /// ③ 文件缺失 → 返回 None，不 panic。
    #[test]
    fn missing_file_returns_none() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "kiro_thread_names_missing_{}_{}.jsonl",
            std::process::id(),
            "nope"
        ));
        let _ = fs::remove_file(&path); // 确保不存在
        let r = ThreadNameResolver::new(path);
        assert_eq!(r.name_for("anything"), None);
    }

    /// ④ 坏行被跳过，同文件里的好行仍能取到。
    #[test]
    fn bad_lines_skipped_good_lines_kept() {
        let tmp = TempFile::new("badline");
        tmp.write(
            r#"this is not json
{"id":"good","thread_name":"好名","updated_at":"2026-06-01T00:00:00Z"}
{"id": broken json here
{"missing_id":true,"thread_name":"无id"}
{"id":"good2","thread_name":"好名2","updated_at":"2026-06-02T00:00:00Z"}
"#,
        );
        let r = ThreadNameResolver::new(tmp.path.clone());
        assert_eq!(r.name_for("good"), Some("好名".to_string()));
        assert_eq!(r.name_for("good2"), Some("好名2".to_string()));
        assert_eq!(r.name_for("无id"), None);
    }
}

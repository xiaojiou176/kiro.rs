//! Observability primitives: request ID, traceparent, error archive, outbound capture.
//!
//! Provides:
//! - Task-local `REQUEST_ID` and `TRACE_PARENT` propagated through tokio await points
//! - `init_logging` that wires:
//!     * stdout: human-readable, NO ANSI (so `stdout.log` is grep-friendly)
//!     * `logs/structured/info.jsonl.YYYY-MM-DD`: JSON, level >= INFO, daily rotated
//!     * `logs/structured/error.jsonl.YYYY-MM-DD`: JSON, level == ERROR, daily rotated
//! - `archive_error_body`: persists raw upstream failure bodies to `logs/errors/`
//! - `capture_outbound`: dumps outbound request bodies to `logs/captures/` when
//!   the `KIRO_RS_CAPTURE` env var is `1` / `true` / `yes`
//!
//! Quick usage from any async context:
//!     let rid = observability::current_request_id();
//!     observability::archive_error_body("upstream-400", body);

use chrono::Utc;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tokio::task_local;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

task_local! {
    /// Per-request UUID. `current_request_id()` returns `"no-rid"` when not set.
    pub static REQUEST_ID: String;
    /// W3C `traceparent` header value for the current request (00-trace-parent-flags).
    pub static TRACE_PARENT: String;
}

/// Returns the current request id or `"no-rid"` if running outside a request scope.
pub fn current_request_id() -> String {
    REQUEST_ID
        .try_with(|id| id.clone())
        .unwrap_or_else(|_| "no-rid".to_string())
}

/// Returns the current traceparent or an empty string if absent.
pub fn current_traceparent() -> String {
    TRACE_PARENT.try_with(|tp| tp.clone()).unwrap_or_default()
}

/// Process-wide observability paths. Set once at startup by `init_logging`.
static OBS_DIRS: OnceLock<ObsDirs> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct ObsDirs {
    pub log_dir: PathBuf,
    pub structured_dir: PathBuf,
    pub errors_dir: PathBuf,
    pub captures_dir: PathBuf,
}

/// Read the singleton observability dirs (must be called after `init_logging`).
pub fn dirs() -> Option<&'static ObsDirs> {
    OBS_DIRS.get()
}

/// Whether outbound capture is enabled (`KIRO_RS_CAPTURE=1` / `true` / `yes`).
pub fn capture_enabled() -> bool {
    matches!(
        std::env::var("KIRO_RS_CAPTURE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Returned by `init_logging`; **must** be kept alive for the program's lifetime —
/// dropping it stops the background writer threads and silences the JSON logs.
pub struct LoggingGuards {
    _info: WorkerGuard,
    _error: WorkerGuard,
    _stdout: WorkerGuard,
}

/// Wire up tracing subscribers:
/// - stdout: pretty, no ANSI codes (start.sh redirects stdout to a file)
/// - `<log_dir>/structured/info.jsonl.YYYY-MM-DD`: JSON, INFO+, daily rotated
/// - `<log_dir>/structured/error.jsonl.YYYY-MM-DD`: JSON, ERROR only, daily rotated
/// - prepares `<log_dir>/errors/` and `<log_dir>/captures/` for sidecar artefacts
///
/// Respects `RUST_LOG` (`EnvFilter`); defaults to `info`.
pub fn init_logging(log_dir: impl Into<PathBuf>) -> anyhow::Result<LoggingGuards> {
    let log_dir = log_dir.into();
    let structured_dir = log_dir.join("structured");
    let errors_dir = log_dir.join("errors");
    let captures_dir = log_dir.join("captures");
    std::fs::create_dir_all(&structured_dir)?;
    std::fs::create_dir_all(&errors_dir)?;
    std::fs::create_dir_all(&captures_dir)?;

    let info_appender = tracing_appender::rolling::daily(&structured_dir, "info.jsonl");
    let error_appender = tracing_appender::rolling::daily(&structured_dir, "error.jsonl");
    let (info_writer, info_guard) = tracing_appender::non_blocking(info_appender);
    let (error_writer, error_guard) = tracing_appender::non_blocking(error_appender);
    let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());

    let info_layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_thread_ids(false)
        .with_writer(info_writer)
        .with_filter(LevelFilter::INFO);

    let error_layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(true)
        .with_writer(error_writer)
        .with_filter(LevelFilter::ERROR);

    // Human-readable stdout for live tail and start.sh redirection.
    // `with_ansi(false)` keeps the file free of `\x1b[..m` noise.
    let stdout_layer = fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(stdout_writer);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(info_layer)
        .with(error_layer)
        .init();

    let dirs = ObsDirs {
        log_dir: log_dir.clone(),
        structured_dir,
        errors_dir,
        captures_dir,
    };
    // Best-effort singleton; multiple calls in tests are tolerated.
    let _ = OBS_DIRS.set(dirs);

    Ok(LoggingGuards {
        _info: info_guard,
        _error: error_guard,
        _stdout: stdout_guard,
    })
}

/// Persist a raw upstream failure body so it can be replayed offline.
///
/// `kind` is a short slug like `"upstream-400"` / `"context-window-full"`.
/// Writes to `<log_dir>/errors/{ts}-{request_id}-{kind}.json`.
/// Silently no-ops if `init_logging` was not called.
pub fn archive_error_body(kind: &str, raw_body: &str) {
    let Some(d) = OBS_DIRS.get() else { return };
    let rid = current_request_id();
    let ts = Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    let safe_kind: String = kind
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = d.errors_dir.join(format!("{ts}-{rid}-{safe_kind}.json"));

    let payload = json!({
        "ts": Utc::now().to_rfc3339(),
        "request_id": rid,
        "traceparent": current_traceparent(),
        "kind": kind,
        "body": raw_body,
    });

    if let Err(e) = write_atomic(&path, payload.to_string().as_bytes()) {
        tracing::warn!(target: "observability", error = %e, path = %path.display(), "archive_error_body failed");
    } else {
        tracing::warn!(target: "observability", path = %path.display(), kind = kind, "archived error body");
    }
}

/// Dump an outbound HTTP request when `KIRO_RS_CAPTURE` is enabled.
///
/// Skipped (without I/O cost) when capture is off, so it's cheap to leave wired.
/// Writes to `<log_dir>/captures/{ts}-{request_id}.json`.
pub fn capture_outbound(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
    direction: &str,
) {
    if !capture_enabled() {
        return;
    }
    let Some(d) = OBS_DIRS.get() else { return };
    let rid = current_request_id();
    let ts = Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    let path = d.captures_dir.join(format!("{ts}-{rid}-{direction}.json"));

    // Redact obvious auth in captures so they're safe to share / mail.
    let headers_redacted: Vec<_> = headers
        .iter()
        .map(|(k, v)| {
            let lk = k.to_ascii_lowercase();
            let value = if lk == "authorization" || lk == "x-api-key" || lk == "cookie" {
                "<redacted>".to_string()
            } else {
                v.clone()
            };
            json!({"name": k, "value": value})
        })
        .collect();

    let body_value = serde_json::from_str::<serde_json::Value>(body)
        .unwrap_or_else(|_| serde_json::Value::String(body.to_string()));

    let payload = json!({
        "ts": Utc::now().to_rfc3339(),
        "request_id": rid,
        "traceparent": current_traceparent(),
        "direction": direction,
        "method": method,
        "url": url,
        "headers": headers_redacted,
        "body": body_value,
    });

    if let Err(e) = write_atomic(&path, payload.to_string().as_bytes()) {
        tracing::warn!(target: "observability", error = %e, path = %path.display(), "capture_outbound failed");
    }
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 唯一 tmp 名（pid + 单调计数）：防止多个并发 write_atomic 写同一个 `.tmp`
    // 导致内容交错撕裂 / rename 竞争。每次写各用各的临时文件，再原子 rename。
    let unique = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("tmp.{}.{}", std::process::id(), n)
    };
    let tmp = path.with_extension(unique);
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        // rename 失败时清理临时文件，避免残留垃圾。
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Parse a W3C `traceparent` and return its 32-hex `trace_id`, if any.
pub fn extract_trace_id(traceparent: &str) -> Option<String> {
    // Format: 00-<trace_id 32 hex>-<parent_id 16 hex>-<flags 2 hex>
    let parts: Vec<&str> = traceparent.split('-').collect();
    if parts.len() == 4 && parts[1].len() == 32 && parts[1].chars().all(|c| c.is_ascii_hexdigit()) {
        Some(parts[1].to_ascii_lowercase())
    } else {
        None
    }
}

/// Produce a fresh `traceparent` for this hop. If `inherited_trace_id` is
/// supplied (from an incoming `traceparent`), it's reused so a single thread
/// across Codex / CPA / kiro-rs / AWS Q shares one trace.
pub fn generate_traceparent(inherited_trace_id: Option<&str>) -> String {
    let trace_id = match inherited_trace_id {
        Some(tid) if tid.len() == 32 && tid.chars().all(|c| c.is_ascii_hexdigit()) => {
            tid.to_ascii_lowercase()
        }
        _ => {
            let mut buf = [0u8; 16];
            fastrand::fill(&mut buf);
            hex::encode(buf)
        }
    };
    let mut span_buf = [0u8; 8];
    fastrand::fill(&mut span_buf);
    let span_id = hex::encode(span_buf);
    format!("00-{trace_id}-{span_id}-01")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_trace_id_ok() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(
            extract_trace_id(tp).as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
    }

    #[test]
    fn extract_trace_id_bad() {
        assert_eq!(extract_trace_id("garbage"), None);
        assert_eq!(extract_trace_id("00-short-00f067aa0ba902b7-01"), None);
    }

    #[test]
    fn generate_traceparent_reuses_trace_id() {
        let tp = generate_traceparent(Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert!(tp.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(tp.ends_with("-01"));
    }

    // M3-a 回归：并发 write_atomic 写同一目标文件不应互相撕裂。
    // 每次写用唯一 tmp 名 + 原子 rename，最终内容必须是某一次的完整写入，
    // 不能是两次交错的半截。
    #[test]
    fn write_atomic_concurrent_no_tear() {
        let dir = std::env::temp_dir().join(format!("kiro_wa_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let target = dir.join("concurrent.json");
        // 两种长度差异明显的内容，撕裂会产生既非 A 也非 B 的混合体。
        let payload_a = vec![b'A'; 20_000];
        let payload_b = vec![b'B'; 20_000];
        let t = target.clone();
        let (a, b) = (payload_a.clone(), payload_b.clone());
        let h1 = std::thread::spawn(move || {
            for _ in 0..50 {
                write_atomic(&t, &a).unwrap();
            }
        });
        let t2 = target.clone();
        let h2 = std::thread::spawn(move || {
            for _ in 0..50 {
                write_atomic(&t2, &b).unwrap();
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();
        // 最终文件必须是 A 或 B 的完整内容之一，绝不能是撕裂/混合。
        let got = std::fs::read(&target).unwrap();
        assert!(
            got == payload_a || got == payload_b,
            "并发写后文件被撕裂：len={}, 既非全 A 也非全 B",
            got.len()
        );
        // 不应残留 tmp 文件（rename 成功路径会清掉）。
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftover.is_empty(), "残留了 {} 个 tmp 文件", leftover.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_enabled_respects_env() {
        // SAFETY: tests run in the same process; restore env after asserting.
        unsafe { std::env::set_var("KIRO_RS_CAPTURE", "1") };
        assert!(capture_enabled());
        unsafe { std::env::set_var("KIRO_RS_CAPTURE", "off") };
        assert!(!capture_enabled());
        unsafe { std::env::remove_var("KIRO_RS_CAPTURE") };
    }

    #[test]
    fn archive_error_body_writes_disk() {
        // Spin up a self-contained log dir so we don't depend on prod state.
        let tmp =
            std::env::temp_dir().join(format!("kiro-rs-obs-test-{}", Utc::now().format("%s%9f")));
        std::fs::create_dir_all(&tmp).unwrap();
        let dirs = ObsDirs {
            log_dir: tmp.clone(),
            structured_dir: tmp.join("structured"),
            errors_dir: tmp.join("errors"),
            captures_dir: tmp.join("captures"),
        };
        std::fs::create_dir_all(&dirs.errors_dir).unwrap();
        // best-effort singleton; if a previous test already set it, just verify
        // the call still doesn't panic.
        let _ = OBS_DIRS.set(dirs.clone());

        archive_error_body("smoke-archive-test", "upstream 503 boom");

        let real_dirs = OBS_DIRS.get().expect("OBS_DIRS set");
        let entries: Vec<_> = std::fs::read_dir(&real_dirs.errors_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("smoke-archive-test")
            })
            .collect();
        assert!(
            !entries.is_empty(),
            "archive_error_body did not produce a file in {}",
            real_dirs.errors_dir.display()
        );
        let body = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(body.contains("upstream 503 boom"));
        assert!(body.contains("\"kind\":\"smoke-archive-test\""));
    }

    #[test]
    fn capture_outbound_writes_disk_when_enabled() {
        // SAFETY: serialized via --test-threads=1 in CI; restore env after.
        unsafe { std::env::set_var("KIRO_RS_CAPTURE", "1") };
        let tmp =
            std::env::temp_dir().join(format!("kiro-rs-cap-test-{}", Utc::now().format("%s%9f")));
        std::fs::create_dir_all(&tmp).unwrap();
        let dirs = ObsDirs {
            log_dir: tmp.clone(),
            structured_dir: tmp.join("structured"),
            errors_dir: tmp.join("errors"),
            captures_dir: tmp.join("captures"),
        };
        std::fs::create_dir_all(&dirs.captures_dir).unwrap();
        let _ = OBS_DIRS.set(dirs.clone());
        capture_outbound(
            "POST",
            "https://example/test",
            &[("authorization".to_string(), "Bearer secret".to_string())],
            r#"{"effort":"max"}"#,
            "smoke-cap",
        );
        unsafe { std::env::remove_var("KIRO_RS_CAPTURE") };

        let real_dirs = OBS_DIRS.get().unwrap();
        let entries: Vec<_> = std::fs::read_dir(&real_dirs.captures_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("smoke-cap"))
            .collect();
        assert!(!entries.is_empty(), "capture_outbound produced no file");
        let body = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(
            body.contains("\"value\":\"<redacted>\""),
            "authorization not redacted"
        );
        assert!(body.contains("\"effort\":\"max\""), "body not preserved");
    }
}

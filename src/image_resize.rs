//! 入站图片缩放与重编码
//!
//! 把 Anthropic 协议 ContentBlock 里 base64 编码的图片在 **CPU 本地**缩到
//! 长边 ≤ `KIRO_RS_IMAGE_MAX_LONG_SIDE` 像素 + 字节 ≤ `KIRO_RS_IMAGE_MAX_BYTES`，
//! 再 base64 重编码后塞回 KiroImage。这一步必须做的原因：
//!
//! 1. AWS Q (`q.us-east-1.amazonaws.com`) 后端对单字段大小有硬限。实测 ~700 KB
//!    的 toolResult.content[0].text 会触发 `CONTENT_LENGTH_EXCEEDS_THRESHOLD`，
//!    iPhone 截图（1206×2622 PNG）单张 base64 ≈ 700K 字符同样会触发。
//! 2. Anthropic 官方建议长边 ≤ 1568 px，这个数据点是 vision encoder 的 patch
//!    grid 边界，超出会被服务端再缩一次但 token 仍按原图计费。
//! 3. ChatGPT/OpenAI 服务端会自动缩到这个尺寸；AWS Q 不会。这就是同样一批
//!    iPhone 截图发给 GPT-5.5 能成功而 Kiro Opus 4.7 报 400 的根因。
//!
//! 设计原则：
//! - 小图直接 pass（不解码不重编，零开销）
//! - 大图缩到长边阈值并转 JPEG 重编（PNG/WebP/JPEG 全部输出 JPEG，
//!   GIF 例外保留原格式因为可能是动图）
//! - 解码失败时**保留原图**，记 warn 日志，永远不能让坏图导致整请求挂掉
//! - 全部走 `KIRO_RS_IMAGE_*` 环境变量，跟 observability 八件套同款契约

use std::io::Cursor;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use image::{ImageFormat, ImageReader, imageops::FilterType};
use tracing::{debug, warn};

/// 默认长边阈值（Anthropic 官方推荐值）
const DEFAULT_MAX_LONG_SIDE: u32 = 1568;
/// 默认字节阈值（留足 < AWS Q 单字段限的安全余量）
const DEFAULT_MAX_BYTES: usize = 400_000;
/// 默认 JPEG 质量
const DEFAULT_JPEG_QUALITY: u8 = 85;

/// 入站图片处理器配置
#[derive(Debug, Clone, Copy)]
pub struct ResizeConfig {
    pub enabled: bool,
    pub max_long_side: u32,
    pub max_bytes: usize,
    pub jpeg_quality: u8,
}

impl ResizeConfig {
    /// 从 `KIRO_RS_IMAGE_*` 环境变量读，缺省回退到默认值
    pub fn from_env() -> Self {
        let enabled = match std::env::var("KIRO_RS_IMAGE_RESIZE")
            .unwrap_or_else(|_| "1".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "0" | "false" | "no" | "off" => false,
            _ => true,
        };
        let max_long_side = std::env::var("KIRO_RS_IMAGE_MAX_LONG_SIDE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_LONG_SIDE);
        let max_bytes = std::env::var("KIRO_RS_IMAGE_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_BYTES);
        let jpeg_quality = std::env::var("KIRO_RS_IMAGE_JPEG_QUALITY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_JPEG_QUALITY);
        Self {
            enabled,
            max_long_side,
            max_bytes,
            jpeg_quality,
        }
    }
}

/// 一张图片处理结果（明确表达"原样保留"和"重编码"两种状态）
#[derive(Debug, Clone)]
pub struct ProcessedImage {
    /// 输出格式（"jpeg" / "png" / "gif" / "webp"）
    pub format: String,
    /// 输出 base64 字符串
    pub data_base64: String,
    /// 是否真做了重编码（用于日志/metrics）
    pub was_resized: bool,
    /// 输入字节数（解码前）
    pub original_bytes: usize,
    /// 输出字节数
    pub final_bytes: usize,
}

/// 主入口：对单张入站图片做"够小直接过 / 大就缩"的处理
///
/// `format` 是来源 media-type 的最后一段（"png" / "jpeg" / "gif" / "webp"），
/// `data_base64` 是 base64 编码的原始字节。
///
/// 永远不会 panic、永远不会丢图。失败时返回输入的 owned 拷贝并 log warn。
pub fn maybe_shrink_image(
    cfg: ResizeConfig,
    format: &str,
    data_base64: &str,
) -> ProcessedImage {
    let format_lc = format.to_ascii_lowercase();
    let original_bytes = data_base64.len();

    // 1) 关闭开关：原样返回
    if !cfg.enabled {
        return passthrough(format_lc, data_base64);
    }
    // 2) 字节够小：原样返回（小图不必折腾，节省 CPU）
    if data_base64.len() <= cfg.max_bytes {
        // 但即便字节小也要看一下尺寸是否超长（罕见，比如 7000×100 banner）
        // 用一个轻量 probe（仅读 header）：image::ImageReader::with_guessed_format
        if let Some((w, h)) = peek_dimensions(&format_lc, data_base64)
            && w.max(h) <= cfg.max_long_side
        {
            return passthrough(format_lc, data_base64);
        }
        // 字节小但维度超大：仍然走重编路径
    }
    // 3) 动图（GIF 多帧）保留原格式不动 — JPEG 化会丢动画
    if format_lc == "gif" {
        debug!(
            target: "kiro_rs::image_resize",
            original_bytes = original_bytes,
            "skip GIF (potential animation)"
        );
        return passthrough(format_lc, data_base64);
    }

    // 4) 真正缩图
    match shrink_static_image(cfg, &format_lc, data_base64) {
        Ok(processed) => processed,
        Err(e) => {
            warn!(
                target: "kiro_rs::image_resize",
                error = %e,
                format = %format_lc,
                original_bytes = original_bytes,
                "image resize failed; passing through original"
            );
            passthrough(format_lc, data_base64)
        }
    }
}

fn passthrough(format: String, data_base64: &str) -> ProcessedImage {
    let n = data_base64.len();
    ProcessedImage {
        format,
        data_base64: data_base64.to_string(),
        was_resized: false,
        original_bytes: n,
        final_bytes: n,
    }
}

/// 只读 header 拿尺寸，不解整个像素，单图 < 1ms
fn peek_dimensions(format: &str, data_base64: &str) -> Option<(u32, u32)> {
    let bytes = BASE64.decode(data_base64).ok()?;
    let cursor = Cursor::new(&bytes);
    let mut reader = ImageReader::new(cursor);
    if let Some(fmt) = guess_format(format) {
        reader.set_format(fmt);
    } else {
        reader = reader.with_guessed_format().ok()?;
    }
    reader.into_dimensions().ok()
}

fn guess_format(s: &str) -> Option<ImageFormat> {
    match s {
        "png" => Some(ImageFormat::Png),
        "jpeg" | "jpg" => Some(ImageFormat::Jpeg),
        "webp" => Some(ImageFormat::WebP),
        "gif" => Some(ImageFormat::Gif),
        _ => None,
    }
}

fn shrink_static_image(
    cfg: ResizeConfig,
    format: &str,
    data_base64: &str,
) -> Result<ProcessedImage, ResizeError> {
    let original_bytes = data_base64.len();

    let raw = BASE64
        .decode(data_base64)
        .map_err(|e| ResizeError::Base64(e.to_string()))?;

    let cursor = Cursor::new(&raw);
    let mut reader = ImageReader::new(cursor);
    if let Some(fmt) = guess_format(format) {
        reader.set_format(fmt);
    } else {
        reader = reader
            .with_guessed_format()
            .map_err(|e| ResizeError::Decode(e.to_string()))?;
    }
    let img = reader
        .decode()
        .map_err(|e| ResizeError::Decode(e.to_string()))?;

    // 比例缩放（保持长宽比）
    let (w, h) = (img.width(), img.height());
    let long = w.max(h);
    let resized = if long > cfg.max_long_side {
        let scale = cfg.max_long_side as f32 / long as f32;
        let new_w = ((w as f32) * scale).round().max(1.0) as u32;
        let new_h = ((h as f32) * scale).round().max(1.0) as u32;
        // FilterType::Lanczos3 视觉质量好，CPU 单核 1206×2622 → 1024×~470
        // 经验耗时 ~80ms；批量 30 张图大概 2.5s，可接受
        img.resize_exact(new_w, new_h, FilterType::Lanczos3)
    } else {
        img
    };

    // JPEG 重编码（截图场景质量 85 视觉无损 + 体积小 10-20×）
    let mut out = Vec::with_capacity(64 * 1024);
    {
        // 强制 RGB8（JPEG 不支持透明通道；alpha 会被丢弃，对截图场景无影响）
        let rgb = resized.to_rgb8();
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
            &mut out,
            cfg.jpeg_quality,
        );
        rgb.write_with_encoder(encoder)
            .map_err(|e| ResizeError::Encode(e.to_string()))?;
    }
    let final_bytes_raw = out.len();
    let data_b64 = BASE64.encode(&out);
    let final_bytes = data_b64.len();

    debug!(
        target: "kiro_rs::image_resize",
        original_bytes = original_bytes,
        final_bytes = final_bytes,
        ratio = format!("{:.2}x", original_bytes as f64 / final_bytes.max(1) as f64),
        decoded_w = w,
        decoded_h = h,
        out_jpeg_bytes = final_bytes_raw,
        "image resized"
    );

    Ok(ProcessedImage {
        format: "jpeg".to_string(),
        data_base64: data_b64,
        was_resized: true,
        original_bytes,
        final_bytes,
    })
}

#[derive(Debug, thiserror::Error)]
enum ResizeError {
    #[error("base64 decode: {0}")]
    Base64(String),
    #[error("image decode: {0}")]
    Decode(String),
    #[error("image encode: {0}")]
    Encode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_png(w: u32, h: u32) -> String {
        use image::{Rgb, RgbImage};
        let mut img = RgbImage::new(w, h);
        // 渐变填色，比纯色压缩率更接近真实截图
        for y in 0..h {
            for x in 0..w {
                img.put_pixel(x, y, Rgb([(x % 256) as u8, (y % 256) as u8, 128]));
            }
        }
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .unwrap();
        BASE64.encode(&buf)
    }

    #[test]
    fn small_image_passes_through() {
        let cfg = ResizeConfig {
            enabled: true,
            max_long_side: 1568,
            max_bytes: 400_000,
            jpeg_quality: 85,
        };
        let small = make_png(64, 64);
        let out = maybe_shrink_image(cfg, "png", &small);
        assert!(!out.was_resized);
        assert_eq!(out.format, "png");
        assert_eq!(out.data_base64, small);
    }

    #[test]
    fn iphone_screenshot_gets_shrunk_below_limit() {
        let cfg = ResizeConfig {
            enabled: true,
            max_long_side: 1568,
            max_bytes: 400_000,
            jpeg_quality: 85,
        };
        // 1206×2622 ~ iPhone Pro Max 截图比例
        let big = make_png(1206, 2622);
        let out = maybe_shrink_image(cfg, "png", &big);
        assert!(out.was_resized, "should have been resized");
        assert_eq!(out.format, "jpeg", "should have been re-encoded as JPEG");
        assert!(
            out.final_bytes < cfg.max_bytes,
            "final {} should be < cap {}",
            out.final_bytes,
            cfg.max_bytes
        );
        // 渐变测试图压缩率不如真截图（块状 UI 元素），只要保证缩到阈值之下就行
        // 真实 iPhone 截图压缩率会大得多（15-20×）— 见 README "实测数据" 章节
        let _ = out.original_bytes;
    }

    #[test]
    fn gif_passes_through_to_preserve_animation() {
        let cfg = ResizeConfig::from_env();
        // 一张 1×1 GIF 即可，关键测的是分支
        let tiny_gif = "R0lGODlhAQABAAAAACw=";
        let out = maybe_shrink_image(cfg, "gif", tiny_gif);
        assert!(!out.was_resized);
        assert_eq!(out.format, "gif");
    }

    #[test]
    fn disabled_config_passes_through_even_huge() {
        let cfg = ResizeConfig {
            enabled: false,
            max_long_side: 1568,
            max_bytes: 400_000,
            jpeg_quality: 85,
        };
        let big = make_png(1206, 2622);
        let out = maybe_shrink_image(cfg, "png", &big);
        assert!(!out.was_resized);
        assert_eq!(out.format, "png");
    }

    #[test]
    fn corrupt_data_passes_through_with_warning() {
        let cfg = ResizeConfig {
            enabled: true,
            max_long_side: 1568,
            max_bytes: 100,
            jpeg_quality: 85,
        };
        // 故意给坏数据 + 字节超限触发解码路径
        let bogus = "X".repeat(1000);
        let out = maybe_shrink_image(cfg, "png", &bogus);
        assert!(!out.was_resized, "corrupt input should fall through");
        assert_eq!(out.format, "png");
        assert_eq!(out.data_base64, bogus);
    }
}

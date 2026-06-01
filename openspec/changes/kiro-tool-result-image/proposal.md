# Kiro lane 工具结果图像穿透（view_image 看图）

## Why

愿景：**Kiro 模型在 Codex 宿主内能真正"看"通过 view_image 工具读入的图片**（截图、UI、设计稿等），而不是图被丢成文本、上下文爆炸。

现状（全部 Live 实锤）：
- Codex 宿主 view_image 读图后，图放在 `function_call_output.output[]` 数组里的 `input_image` 元素。
- CPA `claude_openai-responses_request.go:356` `function_call_output` 分支用 `output.String()` 把整个 output **拍平成 JSON 文本字符串**，图的 base64 变成一坨文本塞进 `tool_result.content`。
- 结果：到 kiro-rs 时 `image_count=0`（图没了），`message_count` 暴涨到 1081，子代理上下文爆炸卡死。
- kiro-rs 即便收到 tool_result 里的 image，`extract_tool_result_content`（converter.rs:546）也只抓 text，图被二次丢弃。
- Amazon Q 后端 `ToolResult` 结构无图字段，图只能走 `UserInputMessage.images` 独立通道（Kiro CLI 原生抓包实锤：toolResults 放占位文字 `See images data supplied` + 顶层 images）。

Live 一正一反实弹已钉死：图**上提到顶层 images** → 模型准确描述真图；图**只留 tool_result.content** → 模型回"图没传过来看不到"。

## What Changes

让 Kiro lane 在 view_image 看图场景下真正把图传到 Amazon Q，对宿主透明。两处协同：

1. **CPA 请求侧（识别图，不拍平）**：`function_call_output` 分支不再 `output.String()` 整体拍平。遍历 output 数组，`input_image` 转成 Anthropic `image` block 放进 `tool_result.content`（复用 message 分支 :213-241 现成逻辑），text 放 text block。
2. **kiro-rs converter（抽图上提）**：处理 tool_result 时，text 留占位、`image` block 抽出转成 `KiroImage` 上提到该 user 消息顶层 `images` 字段（复用现有 `with_images`）。终点形态 = Kiro CLI 原生格式（toolResults 占位 + 顶层 images），Amazon Q 已实锤认。

明确**不做**：
- 不限制图片数量/不做激进缩图（用户决策：只修传输，图能正确识别为图即可，多了爆就爆）。kiro-rs 现有 resize（1024px/250KB）保留。
- 不改 GPT lane。
- 不动顶层 message.input_image 通路（已通，仅修工具结果通路）。

## Capabilities

### New Capabilities
- `kiro-tool-result-image`: Kiro lane 把 view_image 工具结果里的图像正确穿透到 Amazon Q——CPA 识别 function_call_output 里的 input_image 转 image block，kiro-rs 把 tool_result 内的 image 抽出上提到顶层 images 通道，使 Kiro 模型真正能看到工具读入的图。

## Impact

- **CPA**（`~/.proxies/cliproxyapi/src`，魔改源码）：`claude_openai-responses_request.go` `function_call_output` 分支重写（约 30 行，抄 message 分支模板）。
- **kiro-rs**（`~/.proxies/kiro-rs/src`，魔改源码）：`anthropic/converter.rs` tool_result 处理 + `extract_tool_result_content`（识别并抽出 image block 上提 images）。
- 两处均需重编译重启，记入部署流程防官方 build 覆盖。
- 当前 CPA 生产 binary 含临时 ws-dump 调试代码（env 控制无害），本次在干净源码重编译时清除。

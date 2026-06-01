## Context

链路：Codex 宿主 view_image 读图 → CPA(8317) 翻译 OpenAI→Anthropic → kiro-rs(8318) 翻译 Anthropic→Amazon Q。两处魔改源码，改后需重编译重启。

### 三重证据链（全部实锤，无剩余推断）
1. **抓包 Codex 入站**：view_image 的图在 `function_call_output.output[]`（数组）里的 `input_image` 元素，`image_url=data:image/png;base64,...`。
2. **Kiro CLI 原生抓包**：官方客户端工具读图时 `toolResults` 放占位文字 `"See images data supplied"`，真图放 `userInputMessage.images`（顶层独立通道，`{format,source:{bytes}}`）。
3. **Live 一正一反实弹**（直打 8318）：图上提顶层 images → 模型准确描述真图；图只留 tool_result.content → 模型回"图没传过来看不到"。

### Amazon Q 协议结构（researcher 实锤）
- `ToolResult{tool_use_id, content:Vec<Map>, status, is_error}` —— content 构造器只塞 `{text}`，**无图字段**。
- `UserInputMessage{..., images:Vec<KiroImage>}` —— 图的唯一通道，`KiroImage{format, source:{bytes}}`。

## Goals / Non-Goals

**Goals:**
- view_image 工具读入的图，Kiro 模型能真正看到。
- 对宿主透明（不改宿主、不改 catalog）。
- 终点格式 = Kiro CLI 原生格式（toolResults 占位 + 顶层 images）。

**Non-Goals:**
- 不限图数、不做激进缩图（用户决策：只修传输）。
- 不改 GPT lane、不动顶层 message.input_image 通路。

## Decisions

**D1 — 方案选型：抽图上提（方案A），不是图留 tool_result（方案甲）**
方案甲被 Live 反向实弹否决（图留 tool_result.content = 模型看不到）。Amazon Q ToolResult 结构无图字段。唯一正确路径 = 把图从 tool_result 抽出、上提到 UserInputMessage.images，tool_result 留占位文字。这正是 Kiro CLI 原生做法。

**D2 — CPA 改 function_call_output 分支（request.go:356）**
现状 `output.String()` 把 output 数组拍平成文本。改为：遍历 output 数组，`input_image` 用 message 分支(:213-241)同款逻辑转成 Anthropic `{type:image,source:{base64}}` block，text 转 text block，组装成 `tool_result.content` 数组（而非字符串）。

**D3 — kiro-rs converter 抽图上提**
`extract_tool_result_content`(converter.rs:546) 现在只抓 text。改为：text 留作 tool_result content（占位）、image block 抽出转 KiroImage，收集后通过 `with_images` 挂到该 user 消息顶层 images。复用现有 `with_images`（converter.rs:386/915）。

**D4 — 清除临时调试代码**
CPA `openai_responses_websocket.go:306` 有探测期加的 ws-dump（CPA_INBOUND_DUMP）。本次在干净源码重编译时删除，不留调试痕迹。

## Risks / Trade-offs

- **R1 图与工具结果的关联弱化**：图上提顶层后，模型看到"消息里有张图"但与"哪个 tool_use 的结果"关联变松。可在 tool_result 占位文字里点明（如 `[image attached below]`）。Kiro CLI 原生也是这么做的（占位文字），可接受。
- **R2 多图爆炸仍在**：用户已决策只修传输不限量，多图仍会爆 950K（Amazon Q cache=0 每轮重发）。本次不处理。
- **R3 补丁被官方 build 覆盖**：CPA+kiro-rs 均魔改，需记入部署流程 + 备份。
- **R4 stream vs non-stream**：CPA 对 kiro-rs 恒发 stream。两条 handler 路径都要覆盖图穿透。

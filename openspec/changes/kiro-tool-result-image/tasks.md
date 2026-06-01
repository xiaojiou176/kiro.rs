## 1. CPA 请求侧：识别 function_call_output 里的图

- [x] 1.1 改 `cliproxyapi/src/internal/translator/claude/openai/responses/claude_openai-responses_request.go` 的 `function_call_output` 分支(:356)：不再 `output.String()` 拍平；遍历 output 数组，input_image→Anthropic image block(抄 message 分支 :213-241)，text→text block，组装成 tool_result.content 数组
- [x] 1.2 保留纯文本 output 的兼容(output 是字符串或纯文本元素时仍走文本)
- [x] 1.3 清除临时调试代码：删 `openai_responses_websocket.go:306` 的 CPA_INBOUND_DUMP ws-dump 块 + 多余的 os import
- [x] 1.4 单测：function_call_output 含 input_image → tool_result.content 数组含 image block；纯文本 output 回归不变
- [x] 1.5 `go build ./cmd/server` 通过

## 2. kiro-rs converter：抽图上提到顶层 images

- [x] 2.1 改 `kiro-rs/src/src/anthropic/converter.rs` tool_result 处理 + `extract_tool_result_content`(:546)：识别 content 数组里的 image block，抽出转 KiroImage
- [x] 2.2 把抽出的 KiroImage 通过现有 `with_images` 上提到该 user 消息顶层 images；tool_result content 保留文本占位
- [x] 2.3 单测：tool_result 含 image → 图进顶层 images + tool_result 留文本；纯文本 tool_result 回归不变
- [x] 2.4 `cargo build --release` 通过

## 3. 部署 + 端到端 Live 验证

- [x] 3.1 干净源码重编译 CPA(无 dump) + kiro-rs，备份旧 binary，部署(用户重启)
- [x] 3.2 Live：Codex 宿主内 Kiro 模型用 view_image 读 1 张真实截图，确认模型准确描述内容(不再"图没传过来")
- [x] 3.3 回归：纯文本工具(exec)结果正常；GPT lane web_search 不受影响
- [x] 3.4 记入部署流程文档(DEPLOY_NOTES)，防官方 build 覆盖

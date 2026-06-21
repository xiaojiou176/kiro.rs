## 1. CPA 请求侧放行（最小、先行）

- [x] 1.1 改 `cliproxyapi/src/internal/translator/claude/openai/responses/claude_openai-responses_request.go` 的 `shouldSuppressClaudeBuiltinWebSearch`：对 `kiro-api/` 不再 return true（改为 return false 保留函数壳）
- [x] 1.2 重编译 CPA（`go build -o ... ./cmd/server`）+ 备份旧 binary + 重启
- [x] 1.3 Live 验证：经 CPA 发 kiro 混合工具请求，确认转发给 8318 的请求体 tools 含 web_search_20250305（开 CPA_INBOUND_DUMP 或 KIRO_RS_CAPTURE 抓包对照）

## 2. kiro-rs 局部 agentic loop（核心，非流式 MVP）

- [x] 2.1 在 `kiro-rs/src/src/anthropic/handlers.rs` 的 `handle_non_stream_request` 包一层 loop：收完上游响应后检测 `stop_reason==tool_use` 且存在 name==web_search 的 tool_use
- [x] 2.2 命中时取 input.query，调 `websearch::call_mcp_api` + `parse_search_results`（复用现成件），拼 ToolResult 追加进 messages
- [x] 2.3 重新 `convert_request` + `call_api` 再发一轮；设最大轮次上限（防死循环）
- [x] 2.4 非 web_search 的 tool_use（exec 等）维持原样返回客户端，不进 loop
- [x] 2.5 错误处理：/mcp 失败时透传错误，不静默成 "No results found"（修 R2）
- [x] 2.6 工具名匹配考虑 CPA toolNameMap 别名（修 R6）
- [x] 2.7 单测：混合工具命中 web_search loop / 非 web_search 不进 loop / 达上限退出 / 搜索失败透传

## 3. kiro-rs web_search block 呈现（流式，第二阶段）

- [x] 3.1 loop 内每轮搜索向客户端 emit `server_tool_use`(name=web_search,input.query) + `web_search_tool_result` block（复用 `generate_websearch_events` 风格）
- [x] 3.2 流式路径（create_sse_stream）支持：buffer 上游一轮 → loop 完再续 SSE block
- [x] 3.3 单测：block 结构与契约A 一致（server_tool_use + web_search_tool_result 字段）

## 4. CPA 响应侧翻译（让宿主渲染）

- [x] 4.1 改 `claude_openai-responses_response.go` 流式翻译函数：`content_block_start` 加 `server_tool_use`(web_search) 分支 → emit OpenAI `web_search_call` item（status=in_progress, action.queries=[query]）
- [x] 4.2 加 `web_search_tool_result` 分支 → web_search_call status=completed + result 数组（title/url/encrypted_content/page_age 映射进 result，不丢弃）
- [x] 4.3 非流式聚合函数同步加对应 case
- [x] 4.4 重编译 CPA + 重启

## 5. 端到端 Live 验证 + 收尾

- [x] 5.1 在 Codex 宿主内用 Kiro 模型发"先搜后干活"请求，确认宿主 UI 渲染出 web_search_call 且搜到真实结果
- [x] 5.2 验证 GPT lane web_search 不受影响（回归）
- [x] 5.3 验证"边干活边搜"：同一请求 web_search 被内部消化 + exec 正常回客户端执行
- [x] 5.4 把 CPA + kiro-rs 两处改动记入部署流程文档 + 备份 binary（防官方 build 覆盖，修 R5）

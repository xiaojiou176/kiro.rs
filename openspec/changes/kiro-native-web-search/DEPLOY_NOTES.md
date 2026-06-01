# 部署记录：kiro-native-web-search

> ⚠️ CPA + kiro-rs 均为本地魔改源码。官方 `build` 会覆盖，重装后必须重做并重启。

## 改动文件（两个 git repo）

### kiro-rs (`~/.proxies/kiro-rs/src`)
- `src/anthropic/websearch_loop.rs`（新增 ~575 行，loop + 8 单测）
- `src/anthropic/handlers.rs`（map_provider_error→pub(super)；两个 handler 各插 gate）
- `src/anthropic/websearch.rs`（加 has_web_search_among_tools；call_mcp_api/generate_search_summary→pub(crate)）
- `src/anthropic/mod.rs`（mod websearch_loop;）

### CPA (`~/.proxies/cliproxyapi/src`)
- `internal/translator/claude/openai/responses/claude_openai-responses_request.go`（shouldSuppressClaudeBuiltinWebSearch → return false）
- `internal/translator/claude/openai/responses/claude_openai-responses_response.go`（server_tool_use/web_search_tool_result → web_search_call 翻译，流式+非流式）
- `..._response_websearch_test.go`（新增 3 单测）

## 重新部署步骤
```bash
# 1. kiro-rs
cd ~/.proxies/kiro-rs/src && cargo build --release
cp -a target/release/kiro-rs ~/.proxies/kiro-rs/bin/kiro-rs
# 2. CPA
cd ~/.proxies/cliproxyapi/src && go build -o ~/.proxies/cliproxyapi/bin/cli-proxy-api ./cmd/server
# 3. 重启（kiro-rs 先于 CPA）
cd ~/.proxies && bash bin/stop.sh && bash bin/start.sh
```

## 本次部署证据（Live, 2026-05-29 22:11）
- kiro-rs md5 `0ef970756ee3d5254a520f46cb23af33` / CPA md5 `00394d8b6a9bbb580ca2603c2fb8f0af`
- 备份: `kiro-rs/bin/kiro-rs.bak-pre-websearch-loop-20260529-221101`、`cliproxyapi/bin/cli-proxy-api.bak-pre-websearch-20260529-221101`
- Test1 (kiro-rs 8318 混合工具): loop 触发, 10 真实结果, 最终答 "Python 3.14.0" ✅
- Test3 (/v1/responses 宿主入口): emit web_search_call item (status=completed, action.search), Rust 真实结果 ✅
- Test4 (GPT lane 回归): gpt-5.4 正常 response.completed ✅

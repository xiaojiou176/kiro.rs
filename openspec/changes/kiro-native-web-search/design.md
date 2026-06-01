## Context

链路：`Codex 宿主 → CPA(8317) → kiro-rs(8318) → Amazon Q /mcp`。
全部为本地魔改源码（CPA Go、kiro-rs Rust），改后需重编译重启。

Live 抓包已钉死的三个关键契约（不再是推断）：

**契约A — kiro-rs 纯单工具 web_search 响应 SSE 结构**（直打 8318 实测）：
```
index1: {"type":"server_tool_use","id":"srvtoolu_...","name":"web_search","input":{"query":"..."}}
index2: {"type":"web_search_tool_result","content":[
          {"type":"web_search_result","title":..,"url":..,"encrypted_content":<明文snippet>,"page_age":"October 7, 2025"|null}]}
index3: text 摘要（多个 text_delta）
```
注：`encrypted_content` 是明文摘要（命名为兼容 Anthropic 格式）。

**契约B — 混合工具请求上游回包**（web_search+exec 流式实测）：
上游回 `{"type":"tool_use","name":"web_search","input":{...}}`，input 经 `input_json_delta` 流式拼装，`stop_reason=tool_use`。即上游把 web_search 当**客户端工具**踢回，不自己搜。

**契约C — Amazon Q /mcp 鉴权**：`Authorization: Bearer <kiroApiKey>` + `tokentype: API_KEY`，API Key 凭据无需 profileArn。

## Goals / Non-Goals

**Goals:**
- Kiro lane 在混合工具（边干活边搜）场景下真正用上 Amazon Q web_search。
- 对 Codex 宿主透明、对模型无感知（模型照常声明 web_search，无需特殊提示）。
- 复用 kiro-rs 现有 `/mcp` 调用 + 结果解析 + tool_result 回灌能力，不造轮子。

**Non-Goals:**
- 不改 GPT lane。
- 不改宿主二进制 / catalog。
- 不新建独立 MCP server。
- 不删除 kiro-rs 现有"纯单工具 web_search 快路径"。

## Decisions

**D1 — 分流落点：CPA 按模型前缀，kiro-rs 按工具名**
CPA 翻译层已能读 modelName（`kiro-api/` 前缀）。GPT lane 不经 claude 翻译、直连 OpenAI，天然不受影响。仅 kiro lane 需要新行为。

**D2 — 核心 loop 放 kiro-rs，不放 CPA**
理由：死结（单工具限制 + 无 agentic）本就在 kiro-rs；CPA 无"请求生命周期内发子请求/缝 SSE"先例，放 CPA 风险高。kiro-rs 已有 `call_mcp_api`（websearch.rs:523）+ `parse_search_results`（:205）+ `with_tool_results`（converter.rs:373），回灌能力齐备。

**D3 — loop 算法**（落点 `handlers.rs` 普通对话路径）：
```
发请求给 Amazon Q generateAssistantResponse
loop (上限 N 轮, 防死循环):
  收上游响应
  if stop_reason==tool_use 且存在 name==web_search 的 tool_use:
     取 input.query → 调 websearch::call_mcp_api → parse_search_results
     拼成 tool_result 追加进 messages → 重新 convert_request → 再发一轮
     (向客户端 emit server_tool_use + web_search_tool_result block, 复用 generate_websearch_events 风格)
  else:
     正常转发响应给客户端 (其他 tool_use 如 exec 照常回客户端执行), break
```

**D4 — 分阶段：先非流式 MVP，再流式呈现**
非流式路径（handle_non_stream_request）"先收完再转"，能一次拿到完整 tool_use，最契合 loop，约百行。流式呈现（server_tool_use block）作为第二阶段，约 +150~250 行。

**D5 — CPA 响应翻译表**（response.go 两个函数各加 case，基于契约A）：
```
Anthropic block                     → OpenAI web_search_call item
server_tool_use(name=web_search)    → web_search_call, status=in_progress, action.queries=[input.query]
web_search_tool_result              → web_search_call, status=completed, result=结果数组
  result[].{title,url,encrypted_content,page_age} → action/result 字段
```
encrypted_content/page_age 在 OpenAI 侧无直接对应位 → 塞进 result 文本，不丢弃。

## Risks / Trade-offs

- **R1 死循环**：上游反复要搜索 → loop 必须设最大轮次上限（如 5）。
- **R2 错误吞掉**：kiro-rs 现有逻辑把 /mcp 失败静默成 "No results found"（websearch.rs:500-506）。loop 内调用要区分"真没结果"vs"上游报错"，建议加超时 + 失败时把错误透传而非吞掉。
- **R3 流式复杂度**：create_sse_stream 是 unfold 边流边发，中途插 loop 需 buffer 一轮再续，复杂度集中在这。MVP 先非流式规避。
- **R4 字段映射缺位**：encrypted_content/page_age 无 OpenAI 原生对应，映射为近似（塞 result）。需 Live 端到端验证宿主渲染表现。
- **R5 补丁被覆盖**：CPA+kiro-rs 均本地魔改，官方 build 会冲掉，必须记入部署流程 + 备份。
- **R6 工具名别名**：CPA 有 toolNameMap 改名机制，loop 内匹配 web_search 要考虑别名映射，不能只硬比字符串。

**D7 — 流式路径是真实流量唯一目标（实现期实锤）**
CPA `claude_executor.go:146` `stream := from != to`，Codex(openai-responses)→kiro(claude) 恒为 true，所以 CPA 永远对 kiro-rs 发 stream:true。非流式 handler 只被直连非流式客户端（如 curl 调试）命中。结论：agentic loop 必须实现在流式路径才能让 Codex 真受益；kiro-rs 已有 `BufferedStreamContext` + `handle_stream_request_buffered`（缓冲整轮上游再发），是 loop 的理想地基——缓冲一轮 → 检测 web_search tool_use → 内部 /mcp → 回灌重发 → 续缓冲，直到无搜索请求再一次性 flush。非流式 handler 也实现同样 loop 以保证 curl 等直连场景一致。

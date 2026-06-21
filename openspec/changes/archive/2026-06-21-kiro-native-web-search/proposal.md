# Kiro 原生 Web Search 接入 Codex 宿主

## Why

愿景：**Kiro 模型在 Codex 宿主内用 Amazon Q 真实搜索接口，GPT 模型继续用 OpenAI 真实搜索接口**，两条 lane 各走各的真实后端，按模型自动分流。

现状（全部 Live 实锤）：
- GPT lane（Codex → CPA → OpenAI）的 web_search 已正常工作。
- Kiro lane（Codex → CPA → kiro-rs → Amazon Q）的 web_search **被 CPA 主动丢弃**：`shouldSuppressClaudeBuiltinWebSearch` 对 `kiro-api/` 前缀 `return nil`。
- kiro-rs 后端有真 web_search 能力：直打 `8318` 纯单工具请求，0.88s 返回 10 条真实结果（Amazon Q `/mcp` 端点）。
- 但 kiro-rs 的 web_search 有"单工具"硬限制：`tools.len()==1 && name=="web_search"` 才触发；混合工具请求（实际干活场景）落入普通对话路径，上游把 web_search 当客户端工具回 `tool_use`，没人执行 → 搜索落空。
- CPA 响应翻译器对 `server_tool_use` / `web_search_tool_result` block **零覆盖**，会被静默吞掉 → 即使搜到结果，宿主也渲染不出来。

## What Changes

让 Kiro lane 在"边干活边搜"（混合工具）场景下也能真正用上 Amazon Q web_search，对 Codex 宿主透明、对模型无感知。三处协同改动：

1. **CPA 请求侧（放行）**：去掉 `shouldSuppressClaudeBuiltinWebSearch` 对 `kiro-api/` 的丢弃，让 web_search 工具声明随请求转发到 kiro-rs。
2. **kiro-rs 局部 agentic loop（核心）**：普通对话路径收到上游回的 `tool_use{name:web_search, input:{query}}` 时，kiro-rs 内部调已验证可用的 `/mcp` 搜索，把结果拼成 `tool_result` 回灌、再发一轮给 Amazon Q，循环直到上游不再要搜索；期间以 `server_tool_use` + `web_search_tool_result` block 向客户端呈现搜索过程。
3. **CPA 响应侧（翻译）**：新增 `server_tool_use` / `web_search_tool_result` block → OpenAI `web_search_call` item 的翻译，让宿主能渲染。

明确**不做**：
- 不改 GPT lane（已工作）。
- 不改 Codex 宿主二进制 / model-catalog 注入逻辑（catalog 字段已满足）。
- 不新建独立 MCP server（用 kiro-rs 内部 loop 解决，避免多进程维护 + 双暴露问题）。
- 不动 kiro-rs 现有"纯单工具 web_search"快路径（保留，作为已验证基线）。

## Capabilities

### New Capabilities
- `kiro-web-search`: Kiro lane 在 Codex 宿主内通过 Amazon Q `/mcp` 端点执行真实 web search，支持与其他工具混用（边干活边搜），并以 Anthropic web_search block 格式呈现、经 CPA 翻译回 OpenAI `web_search_call` 供宿主渲染。

### Modified Capabilities
<!-- 无现有 spec 的需求级变更（此前无 openspec 工作区，CPA/kiro-rs 改动属新增行为） -->

## Impact

- **kiro-rs**（`~/.proxies/kiro-rs/src`，主战场）：`anthropic/handlers.rs` 普通对话路径新增 agentic loop（复用 `websearch.rs` 的 `call_mcp_api`/`parse_search_results`、`converter.rs` 的 `with_tool_results`）。改动量约百行（非流式 MVP）~两三百行（含流式 buffered 呈现）。
- **CPA**（`~/.proxies/cliproxyapi/src`，魔改源码，未提交补丁需重编译）：① `claude_openai-responses_request.go` 去掉 1 行丢弃；② `claude_openai-responses_response.go` 两个翻译函数各新增 web_search block → web_search_call 的 case。
- **凭据**：现有 API Key 凭据（11 条 `kiroApiKey`）已足够，Amazon Q `/mcp` 鉴权 = `Authorization: Bearer <kiroApiKey>` + `tokentype: API_KEY`，无需 profileArn、无需额外配置。
- **风险**：两处都是本地魔改源码，改完需重编译 + 重启，且记入部署流程防官方 build 覆盖（历史教训）。

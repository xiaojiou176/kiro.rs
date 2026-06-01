## ADDED Requirements

### Requirement: CPA 放行 Kiro lane 的 web_search 工具声明

CPA 在把 OpenAI Responses 请求翻译成 Claude 格式时，对 `kiro-api/` 前缀的模型，MUST 保留 web_search 工具声明并转换为 `web_search_20250305` 格式转发给 kiro-rs，而非丢弃。GPT lane 行为不受影响。

#### Scenario: kiro 模型混合工具请求保留 web_search
- **WHEN** 请求模型为 `kiro-api/claude-*` 且 tools 数组包含 web_search 与其他工具
- **THEN** CPA 转发给 kiro-rs 的请求体 tools 数组 MUST 包含 `{"type":"web_search_20250305","name":"web_search"}`，且其他工具保持不变

#### Scenario: GPT lane 不受影响
- **WHEN** 请求模型为 gpt-5.x
- **THEN** web_search 仍走 OpenAI 原生路径，行为与改动前一致

### Requirement: kiro-rs 在混合工具场景内部执行 web_search

当 Amazon Q 普通对话路径返回 `name=web_search` 的 `tool_use` 时，kiro-rs MUST 内部调用 Amazon Q `/mcp` 端点执行搜索，将结果作为 tool_result 回灌后再发一轮，循环直到上游不再请求搜索；非 web_search 的 tool_use（如 exec_command）MUST 照常返回给客户端执行。循环 MUST 设最大轮次上限以防死循环。

#### Scenario: 边干活边搜——web_search 被内部消化
- **WHEN** Kiro 模型在含 exec_command 等工具的请求中触发 web_search tool_use
- **THEN** kiro-rs 内部完成 `/mcp` 搜索并回灌，最终响应基于真实搜索结果生成，**WHEN** 同一请求还触发 exec_command **THEN** 该 tool_use 正常返回客户端执行

#### Scenario: 达到轮次上限安全退出
- **WHEN** 上游连续 N 轮（达到上限）都请求 web_search
- **THEN** kiro-rs 停止循环并返回当前已生成内容，不无限循环

#### Scenario: /mcp 搜索失败不伪装成空结果
- **WHEN** Amazon Q `/mcp` 调用返回错误或超时
- **THEN** kiro-rs MUST 将错误信息透传或明确标注，而非静默返回 "No results found"

### Requirement: kiro-rs 以 Anthropic web_search block 呈现搜索过程

kiro-rs 向客户端呈现搜索时，MUST 输出 `server_tool_use`（name=web_search, input.query）与 `web_search_tool_result`（含 web_search_result 数组）block，字段结构与现有纯单工具 web_search 路径一致。

#### Scenario: 搜索过程可见
- **WHEN** kiro-rs 内部执行了一次 web_search
- **THEN** 客户端收到 `server_tool_use` block（含 query）与 `web_search_tool_result` block（含 title/url/encrypted_content/page_age 的结果数组）

### Requirement: CPA 翻译 web_search block 为 OpenAI web_search_call

CPA 响应翻译器（流式与非流式两条路径）MUST 将 Anthropic `server_tool_use`(web_search) 与 `web_search_tool_result` block 翻译为 OpenAI Responses 的 `web_search_call` item，使 Codex 宿主能渲染；不得静默吞掉这些 block。

#### Scenario: server_tool_use 翻译为进行中的搜索
- **WHEN** CPA 收到 Anthropic `server_tool_use` block（name=web_search）
- **THEN** 输出 OpenAI `web_search_call` item，status=in_progress，action.queries 取自 input.query

#### Scenario: web_search_tool_result 翻译为已完成的搜索
- **WHEN** CPA 收到 Anthropic `web_search_tool_result` block
- **THEN** 输出 `web_search_call` item status=completed，结果数组（title/url/snippet）映射进 result，不丢弃

#### Scenario: 宿主能渲染 kiro lane 搜索结果
- **WHEN** kiro lane 完成一次 web_search 并经 CPA 翻译
- **THEN** Codex 宿主 UI 显示 web_search_call（与 GPT lane 体验一致）

### Requirement: 鉴权与凭据零额外配置

kiro-rs 调用 Amazon Q `/mcp` 执行 web_search MUST 复用现有 API Key 凭据机制（`Authorization: Bearer <kiroApiKey>` + `tokentype: API_KEY`），不要求 profileArn，不引入新凭据配置。

#### Scenario: API Key 凭据直接可用
- **WHEN** 当前 credentials.json 中的 api_key 凭据用于 web_search
- **THEN** `/mcp` 调用鉴权通过，无需补充 profileArn 或其他字段

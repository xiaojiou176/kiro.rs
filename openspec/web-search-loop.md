> ⚠️ **已被取代（2026-06-23 compress §9.5 文档漂移标注）**：本草稿内容已被正式 spec `openspec/specs/kiro-web-search/spec.md` 吸收，全仓零引用，仅作历史草稿留存，**勿据此施工**。

# Spec: web_search 局部 agentic loop (kiro-rs)

## 1. 问题
混合工具(web_search + exec...)落 Amazon Q 普通对话后, Q 把 web_search 当客户端工具踢回
(tool_use name=web_search, stop_reason=tool_use); kiro-rs 当前直接透传给客户端, Codex 不会
自己搜 -> web_search 在混合工具场景下失效。

## 2. 目标
上游一轮返回 name==web_search 的 tool_use 时, kiro-rs 内部调 /mcp 搜索, 把结果当 tool_result
回灌再发一轮, 循环到上游不再要搜索; 非 web_search 的 tool_use(exec)照常返回客户端; 期间向客户端
emit server_tool_use + web_search_tool_result block。

## 3. 不做
- 不动纯单工具 web_search 快路径(has_web_search_tool 分支)。
- 不动无 web_search 工具请求的现有流式/非流式路径(零回归)。
- 不动 converter.rs / token_manager.rs 现有历史改动; 不碰 cliproxyapi。

## 4. 完成标准
- gate: 请求 tools 含 web_search 且非纯单工具时, 流式/非流式都走 loop。
- 每轮缓冲解码; 仅 web_search tool_use(无其它 tool_use)且未达上限 -> 搜索+回灌+重发; 否则终止 flush。
- MAX_WEB_SEARCH_ROUNDS=5; 达上限 flush 当前内容。
- 非 web_search tool_use 终止时原样返回客户端, 不被吞。
- /mcp 调用 Err -> 透传错误(error response), 绝不静默成 "No results found"。
- cargo build --release 通过; loop 单测(命中/不命中/达上限/搜索失败透传)通过。

## 5. 涉及
Tool=web_search; Runtime=anthropic handlers/websearch; 复用 websearch::call_mcp_api /
parse_search_results / create_mcp_request / 结果 block 字段 + converter::convert_request(回灌)。

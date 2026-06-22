# web_search/MCP 出站对齐真实 Kiro CLI V3 InvokeMCP

## Why
指纹核对发现 kiro-rs 的 web_search/MCP 出站与原生 Kiro CLI V3 不一致(真指纹泄露)：
- kiro-rs(旧): URL /mcp 子路径 + 裸 JSON-RPC + profileArn 走 header x-amzn-kiro-profile-arn + 无 x-amz-target/optout
- 真 V3(pty 抓包基线): URL 根路径 / + x-amz-target=AmazonCodeWhispererStreamingService.InvokeMCP + optout=true + profileArn 作为请求体顶层字段(AWS json-1.0 包装)
这 4 处差异可被上游识别为"非原生客户端"。owner 要求对齐(不怕工作量)。

## What Changes (仅 cli 端点)
- mcp_url: /mcp → 根路径 /
- decorate_mcp: 加 x-amz-target=InvokeMCP + x-amzn-codewhisperer-optout=true；删 x-amzn-kiro-profile-arn header(profileArn 移进 body)；保留 api_key 的 tokentype 头
- 新增 transform_mcp_body: 用 streaming_profile_arn() 把 profileArn 注入 body 顶层(IdC=占位符；api_key 返 None→body 不含 profileArn)

## Impact / 风险
- 受影响：src/kiro/endpoint/cli.rs。调用面单一(provider.rs:391/402 call_mcp_with_retry)。
- 🔴 历史风险 R9-F20：曾改 V3 形态破坏过 apikey(它靠 tokentype 免 profileArn)，已 revert。本次用 G2 fitness-function 焊死「api_key 的 MCP body 永不含 profileArn」+ 双认证 live 回归验证规避。

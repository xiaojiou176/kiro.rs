# kiro-web-search (delta: MCP wire 对齐 InvokeMCP)

## MODIFIED Requirements

### Requirement: web_search/MCP 出站对齐真实 Kiro CLI V3 InvokeMCP 形态
cli 端点的 web_search/MCP 调用 MUST 对齐原生 Kiro CLI V3：走 runtime 根路径 /、带 x-amz-target=AmazonCodeWhispererStreamingService.InvokeMCP + x-amzn-codewhisperer-optout=true、profileArn 作为请求体顶层字段注入(非 header)。

#### Scenario: Builder ID web_search 走 InvokeMCP 形态成功
- WHEN Builder ID 凭据发 web_search
- THEN 出站 URL=根路径/、x-amz-target=InvokeMCP、optout=true、body 顶层含占位符 profileArn；上游回 200 真结果

#### Scenario: api_key web_search 不被破坏(G2 不变量)
- WHEN api_key 凭据发 web_search
- THEN 出站带 tokentype=API_KEY、body **永不**含 profileArn；上游回 200 真结果(R9-F20 坑不复现)

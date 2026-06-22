# Tasks

- [x] GitNexus/rg 算爆炸半径(decorate_mcp/mcp_url 单一调用面 provider.rs call_mcp_with_retry)
- [x] 读真 V3 InvokeMCP 抓包确定目标 wire 形态(根路径+InvokeMCP+optout+body profileArn)
- [x] TDD: mcp_url 根路径 / decorate_mcp InvokeMCP+optout+无profileArn header / G2 fitness(apikey body无profileArn) / builderid body有占位符 — 4 测试绿
- [x] 实现 cli.rs 三处改动
- [x] cargo test 全绿(551 passed)
- [x] LIVE 双认证回归: builderid web_search HTTP200/上游InvokeMCP回200真结果; apikey web_search HTTP200/上游200真结果/body无profileArn(G2成立) — R9-F20 坑避开

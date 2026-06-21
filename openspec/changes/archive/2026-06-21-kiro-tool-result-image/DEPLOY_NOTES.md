# 部署记录：kiro-tool-result-image

> ⚠️ CPA + kiro-rs 均魔改源码，官方 build 会覆盖，重装后必须重做并重启。

## 改动文件
### CPA (~/.proxies/cliproxyapi/src)
- `internal/translator/claude/openai/responses/claude_openai-responses_request.go`：function_call_output 分支识别 input_image→image block(不再String拍平)
- `sdk/api/handlers/openai/openai_responses_websocket.go`：删除临时 ws-dump 调试代码
- `..._request_test.go`：+2 单测

### kiro-rs (~/.proxies/kiro-rs/src)
- `src/anthropic/converter.rs`：tool_result 里的 image 抽出转 KiroImage 上提到顶层 images(extract_kiro_image + 重写 extract_tool_result_content)，+2 单测

## 重新部署
```bash
cd ~/.proxies/cliproxyapi/src && go build -o ~/.proxies/cliproxyapi/bin/cli-proxy-api ./cmd/server
cd ~/.proxies/kiro-rs/src && cargo build --release && cp -a target/release/kiro-rs ~/.proxies/kiro-rs/bin/kiro-rs
cd ~/.proxies && bash bin/stop.sh && bash bin/start.sh
```

## 本次部署(2026-05-30)
- CPA md5 e8918bf764eaf0a57f4fe62dd536540c / kiro-rs md5 7affe8a911b2c80a4b7c099a43ce281b
- 备份: *.bak-pre-toolimg-20260530-002513
- 证据: 一正一反 Live 实弹(图上提=模型描述真图; 图留tool_result=看不到) + Kiro CLI原生格式吻合

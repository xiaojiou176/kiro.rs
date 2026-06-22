# kiro-web-search (delta: profileArn 解析去重)

## MODIFIED Requirements

### Requirement: profileArn 解析对"确定性不支持"只尝试一次
个人 Builder ID 等无 Enterprise profile 的凭据，上游对 ListAvailableProfiles 返回确定性 403「is not supported」时，kiro-rs MUST 视为"该账号无 profile"（回退占位符）并标记已尝试，**不得每个请求重复解析**。真瞬态网络错(5xx/429/连接失败)仍可重试。

#### Scenario: 个人 Builder ID 连发多次只解析一次
- WHEN 个人 Builder ID 凭据连发 N 次请求，上游所有区域端点对 profile 解析返回 403 is-not-supported
- THEN profile 解析只实际发生 1 次；后续请求直接回退占位符 profileArn，不再重打 403

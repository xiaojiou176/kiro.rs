# 个人 Builder ID profileArn 解析 403 去重

## Why
个人(纯) Builder ID 凭据没有 Enterprise profile。kiro-rs 的 ensure_profile_arn 会调 list_available_profiles 解析真 ARN；上游对这类账号所有区域端点返回 403「... is not supported for this operation.」。原实现：list_available_profiles 在"全端点 403、无一次 200-空"时 bail!(Err)；而 ensure_profile_arn 的 Err 分支故意不标去重锁(怕网络抖动永久卡死) → 个人 Builder ID **每个请求都重打一次 403**(live 日志实证 id22 每发一个 403 再降级占位符成功)。这是冗余上游调用 + 日志噪音。

## What Changes
区分「账号类型确定性不支持」与「真瞬态网络错」：
- 新增纯函数 is_definitive_profile_unsupported(status, body)：403(Forbidden) 或 body 含 "is not supported"/"not supported for this operation" → 确定性；5xx/429/连接错 → 瞬态。
- list_available_profiles：所有候选端点都确定性拒绝时返回 Ok(default)（=「无 Enterprise profile」），而非 bail!；让 ensure_profile_arn 走 Ok(None) 分支标已尝试、回退占位符、不再每请求重试。瞬态错仍 bail! 保留重试。

不做：不改 api_key 路径(它本就 return None early)；不改占位符回退逻辑本身。

## Impact
- 受影响：src/kiro/token_manager.rs (list_available_profiles + 新 helper)、间接 src/kiro/provider.rs (ensure_profile_arn 行为)。
- 风险：低。瞬态错仍重试；只把"确定性不支持"从无限重试改成试一次。

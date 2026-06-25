# 多号均衡负载 429 硬触发根治 + 调度器排序优先 + WebUI 四件

## Why
owner 反复抱怨「一堆 Thread 绑死同一个号、其他号空着、必须重启、过会又绑死」。R9 已写后台主动巡检调度器 `rebalance_tick`，但单人低流量场景下它**空转救不了被压垮的号**：
- 切号/疏散的主信号 `rebalance_rpm_gap` 默认 8.0，意为「某号 RPM 比最空号高 8 才疏散」。但单人用 9 个号、每号 RPM 常态 0-6、最高才 6 → **永远够不到门槛** → 调度器空转。
- 被 429 压垮的号「成功 RPM」往往更低（请求大多失败），调度器候选源**只按 RPM 降序排**时，最该救的限流号反而被沉到队尾、被高 RPM 健康号挤掉本 tick 疏散名额。
- 利用率前置门硬编码 `SATURATED=1.0`，「快撞墙但没撞满」的中间态永不触发疏散。

WebUI 侧：模式切换控件伪装成导航 Tab 一点就改 live 策略；失衡时不主动告警要人眼扫；孤儿 Pin 只能看不能清；账号卡区会话仍显裸 UUID。

## What Changes
kiro-rs 调度（`src/kiro/token_manager.rs` + `src/model/config.rs` + live `config/config.json`）：
- 新增「429 率硬触发疏散」信号 `rebalance_429_rate_threshold`（默认 0.05）：号最近 5 分钟上游 429 率 ≥ 阈值且持续撞墙（`consecutive_throttles>=2`，复用 `account_429_rate_sustained` 防瞬态 churn）→ 立刻把会话疏散到利用率最低的健康号，**绕过 RPM/util 门**；目标号自己 429 率 ≥ 阈值则不当落脚点。
- 调度器 `rebalance_tick` 候选源排序：从「只按 RPM 降序」改为「被限流(429硬触发)源优先 → 再按 RPM 降序 → id 稳定」，让最紧急的限流源先疏散。
- `default_rebalance_rpm_gap` 8.0 → 2.0（匹配单人真实流量）。
- 利用率前置门从硬编码 `1.0` 改为可配 `rebalance_util_saturated`（默认 0.8）。

WebUI（`src/admin-ui/src/components/`，编进 binary 的 rust_embed `admin-ui/dist`）：
- ~~topbar-tools.tsx：模式切换改 `Switch` 控件 + `useConfirm` 二次确认~~ **⮌ 已回退**（owner 决定不要此改动）：还原原 `LoadBalancingButton`、不在顶栏做开关/确认。本 change 的 WebUI 净改动只剩 observability-page.tsx 三件（#20/#21/#22）。
- observability-page.tsx：失衡判定（429率>5% 或 inflight 占满）→ 账号卡标红 + 失衡置顶 + 全局健康行变黄/红；孤儿 Pin 折叠态加「解绑」按钮（调既有 unpin 端点 + 自动刷新）；账号卡会话 chip 接 Thread 真名映射、回退 shortSessionId。

不做：不改 overflow-on-busy 既有逻辑（与 429 硬触发分层互补：overflow 走整-Thread 逃离三门全满，本信号走更轻的中间态疏散）；不动 Pin 写入/查询链路；不碰 push/重启/换 live（owner 红线）。

## Impact
- 受影响：`src/kiro/token_manager.rs`(429 硬触发信号 + 候选排序 + account_429_rate_sustained helper + 测试隔离修)、`src/model/config.rs`(2 新字段 + rpmGap 默认)、live `config/config.json`、`src/admin-ui/src/components/{topbar-tools,observability-page}.tsx`。
- 风险：低。429 硬触发有 consecutive>=2 + switch_debounce 防 churn；新 config 字段无 `deny_unknown_fields`、旧 binary 误读不崩；阈值改 live 配置重启即生效不必重编（但源码默认也已同步）。
- 验证：cargo test --release 619 passed / 0 failed（新增 5 个测试）；WebUI npm run build exit 0；dist 已含改动。
- 未验缺口（owner 红线）：均衡负载「高并发撞 429 紧急疏散」核心路径只过单测 + 低负载 live，**未真高并发压测**；WebUI 视觉未 live 验（需 owner 重编 binary）。

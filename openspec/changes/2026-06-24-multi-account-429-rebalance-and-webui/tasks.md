# Tasks

## kiro-rs 调度根治（#18）
- [x] config.rs 新增 `rebalance_429_rate_threshold`(默认 0.05) + `rebalance_util_saturated`(默认 0.8) 两字段 + 手写 Default impl 补字段
- [x] `default_rebalance_rpm_gap` 8.0 → 2.0
- [x] token_manager.rs 新增 helper `account_429_rate_sustained`(consecutive>=2 才返真 429 率，防瞬态)
- [x] rebalance_target_excl 新增「⓪′ 429 率硬触发」分支(绕过 RPM/util 门、目标也被 429 则跳过)
- [x] util 前置门硬编码 1.0 → 读 `ma.rebalance_util_saturated`
- [x] rebalance_tick 候选源排序：被限流源优先 → RPM 降序 → id 稳定(候选元组扩成 4 元)
- [x] live config/config.json 同步(rpmGap 2.0 + 两新字段)
- [x] TDD 测试：test_rebalance_by_429_rate_hard_trigger / test_scheduler_429_source_evacuated_before_high_rpm / test_429_trigger_skips_when_only_target_also_throttled / test_429_trigger_disabled_when_threshold_zero / test_util_saturated_gate_is_configurable
- [x] 测试隔离修：account_learning.rs store() 临时文件加进程内原子序号(根治并行 flaky)
- [x] cargo test --release 619 passed / 0 failed；全量连跑 3 次 0 flaky

## WebUI 四件（#19-22）
- [x] #19 topbar-tools.tsx：模式切换改 Switch + useConfirm 二次确认
- [x] #20 observability-page.tsx：失衡(429率>5%/inflight满)标红 + 置顶 + 全局健康变色
- [x] #21 observability-page.tsx：孤儿 Pin 折叠态加解绑按钮(调既有 unpin 端点)
- [x] #22 observability-page.tsx：账号卡会话 chip 接 Thread 真名映射
- [x] npm run build exit 0；dist 已含改动(grep「有号失衡」「切换负载均衡模式」命中产物)

## owner 红线（未做、留 owner）
- [ ] cargo build --release 重编 binary + cp 到 bin/（dist 已最新，不必再 npm build）
- [ ] stop.sh && start.sh 重启
- [ ] push 三仓
- [ ] 真高并发压测验证「峰值绑死紧急疏散」核心路径(本 change 最大未验缺口)
- [ ] 重编后肉眼验 WebUI 四处

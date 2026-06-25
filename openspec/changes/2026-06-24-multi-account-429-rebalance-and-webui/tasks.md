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
- [⮌] #19 topbar-tools.tsx：~~模式切换改 Switch + useConfirm 二次确认~~ **已回退**（owner 决定不要此改动）：还原原 `LoadBalancingButton`（导航 Tab 样按钮、点一下直接切、无确认），不在顶栏做开关/确认。
- [x] #20 observability-page.tsx：失衡(429率>5%/inflight满)标红 + 置顶 + 全局健康变色
- [x] #21 observability-page.tsx：孤儿 Pin 折叠态加解绑按钮(调既有 unpin 端点)
- [x] #22 observability-page.tsx：账号卡会话 chip 接 Thread 真名映射
- [x] npm run build exit 0；dist 已含改动(grep「有号失衡」「切换负载均衡模式」命中产物)

## 追加根治（2026-06-25 owner 拍板「最根治」后）
- [x] churn 根治：rebalance_tick victim 选择新增门「搬过且搬后无真实活动(last_seen<=last_switch_at)的会话不再搬」(token_manager.rs)，根除多号环形 churn(commit 771e915)
- [x] churn TDD：test_scheduler_idle_session_not_rechurned_after_move(修前 RED→修后 GREEN) + test_scheduler_active_session_still_movable_after_move(证不误伤真实负载会话)
- [x] 观测页吞吐根治：api.ts 补 goodputRps/appLimited + normalize 透传 + observability-page.tsx 顶部「实测吞吐(ΣgoodputRps)+容量上限」、卡里「实测吞吐/速率上限」拆分(commit 98afb20)
- [x] cargo test --release 621 passed / 0 failed(churn +2 测试)；连跑 3 次稳定绿；admin-ui npm run build exit 0、dist 含新标签(实测吞吐/速率上限/容量上限)
- [ ] 重编 binary + 部署让 churn 根治 + 观测页吞吐根治 live 生效(owner 红线，同上面那两条部署项一起做)

## owner 红线（未做、留 owner）
- [x] cargo build --release 重编 binary + cp 到 bin/（2026-06-25 fresh 核：live binary md5 `9a5deeb7`、PID 55426/55451；deploy-and-verify.sh 路径 bug 已修后部署成功）
- [x] stop.sh && start.sh 重启（live 已起、:8318+:8317 健康、含 #18+#19回退）
- [ ] push 三仓
- [~] 真高并发压测验证「峰值绑死紧急疏散」核心路径 — **部分 live 实证**：2026-06-25 日志抓到 #19 真撞 429（9 次 on_throttle，429率峰值 16.7%），撞墙后 27s 触发 affinity_switch 切号疏散（06:41:35 撞→06:42:02 切），**非绑死、自动切号生效**；但仍非"人为高并发压测"，留 owner 做满负载验证。
- [ ] 重编后肉眼验 WebUI 四处

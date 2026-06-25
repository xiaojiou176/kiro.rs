# Capability: multi-account-load-balancing

多号分流的负载均衡 / 切号 / 疏散行为契约。本 change 新增「按上游 429 率硬触发疏散」与「限流源排序优先」两条能力，并把利用率前置门参数化。

## ADDED Requirements

### Requirement: 按上游 429 率硬触发疏散
当某号最近探测窗口（probe_window，默认 300s）的上游 429 率达到或超过 `rebalance_429_rate_threshold`（默认 0.05）且处于持续撞墙状态（`consecutive_throttles >= 2`）时，系统 MUST 把该号名下一个可搬会话疏散到利用率最低的健康号，且此判定 MUST 优先于 RPM 差、利用率差、绑定数、会话数等其它再平衡信号。

#### Scenario: 被限流号在低 RPM 下仍被疏散
- **GIVEN** 某号 429 率 ≥ 阈值且持续撞墙，与最空号的 RPM 差不足 `rebalance_rpm_gap`
- **WHEN** 触发再平衡选号
- **THEN** 系统疏散该号的会话到一个 429 率低于阈值的健康号

#### Scenario: 目标号也在被限流则不选它
- **GIVEN** 唯一候选目标号自身 429 率也 ≥ 阈值
- **WHEN** 429 硬触发评估落脚点
- **THEN** 系统不把会话搬到该目标号（不从火坑挪进另一个火坑）

#### Scenario: 阈值为 0 关闭该信号
- **GIVEN** `rebalance_429_rate_threshold == 0`
- **WHEN** 某号被狂 429
- **THEN** 429 硬触发分支不触发（回退到其它再平衡信号）

### Requirement: 调度器候选源限流优先排序
后台主动巡检调度器在排「先疏散哪个源号」时，MUST 让被 429 硬触发判定为限流的源号排在仅按 RPM 排序的源之前，确保最紧急的限流源在本轮巡检优先获得疏散名额。

#### Scenario: 限流低 RPM 源先于健康高 RPM 源疏散
- **GIVEN** 源 A 被持续 429 但成功 RPM 低，源 B 健康但 RPM 高，二者都有可搬会话
- **WHEN** 调度器本 tick 执行一次疏散
- **THEN** 被疏散的是源 A 名下的会话，而非源 B

### Requirement: 利用率前置门可配置
按利用率差疏散的前置「饱和门」MUST 由配置项 `rebalance_util_saturated`（默认 0.8）提供，不再硬编码为 1.0，使「接近但未撞满天花板」的中间态也能触发利用率疏散。

#### Scenario: 下调饱和门让中间态触发
- **GIVEN** `rebalance_util_saturated` 配置为低值且某号利用率高于最空号
- **WHEN** 触发再平衡且仅利用率信号启用
- **THEN** 系统按利用率差把会话疏散到利用率最低的号

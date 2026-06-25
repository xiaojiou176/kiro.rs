# Design — 多号均衡负载 429 硬触发 + 排序优先

## 信号分层（为什么不和 overflow-on-busy 打架）
疏散/迁移现在有两条独立路径，分层互补、不重叠触发：

| 路径 | 触发条件 | 迁移粒度 | 默认阈值 | 何时跑 |
| :-- | :-- | :-- | :-- | :-- |
| overflow-on-busy(既有) | 三门全满：429率高 + goodput低 + 非app_limited | 整-Thread 逃离 | 0.1 | select-time 优先于 rebalance |
| 429 硬触发(本次新增) | 单门：429率 ≥ 阈值 + 持续撞墙 | 单会话疏散 | 0.05 | rebalance_target_excl 内最高优先 |

overflow 是「重」路径（整会话逃离正在烧的号、三门严判），429 硬触发是「轻」路径（catch overflow 三门没全满、但已被限流的中间态）。select-time 上 overflow 先判并 short-circuit，不会双触发；scheduler 路径只走 rebalance，429 硬触发是它唯一的限流感知来源。

## 候选排序为何要把限流源提前
被 429 压垮的号「成功 RPM」往往低于健康号（请求大量失败、没成功计数）。调度器 `rebalance_tick` 原来按 RPM 降序选「先疏散谁」，于是「RPM 3 / 429率 9.5%」这种最该救的号被排在「RPM 高但 0% 429」的健康号后面，本 tick 名额被健康号占掉。改为 `(throttled, rpm, id)` 三键排序，限流源恒排最前，确保最紧急的先疏散。

## churn 防护
- `account_429_rate_sustained` 要求 `consecutive_throttles >= 2`，单次瞬态 429 不算「持续撞墙」，不触发。
- select-time 路径外层有 `switch_debounce_secs`(默认 30s) + `last_evicted_from` 防回弹，已绑会话不会每请求被搬。
- 目标号自己 429 率 ≥ 阈值则不当落脚点——绝不把会话从一个火坑挪进另一个火坑。

## 利用率门可配
`account_utilization = current_rate/safe_rps_hi + (consecutive>=2 ? upstream_429_rate_5m : 0)`。前置门从硬编码 1.0（要真正贴满天花板）改为 `rebalance_util_saturated`(默认 0.8)，让「快撞墙但没撞满」的中间态也能按利用率差疏散。

## 部署安全
- 新 config 字段：config 结构体无 `#[serde(deny_unknown_fields)]`，旧 binary 读到新字段静默忽略、不崩；新 binary 读旧 config 走 `#[serde(default)]` 兜默认。两向兼容、重启顺序无所谓。
- WebUI：rust_embed 嵌 `admin-ui/dist`，无 build.rs 自动跑 npm → dist 必须先 `npm build`（本次已 build、产物含改动），owner 直接 `cargo build` 即嵌入。

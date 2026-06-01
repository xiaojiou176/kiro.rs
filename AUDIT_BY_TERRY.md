# 🔬 kiro-rs v0.4.0 严谨 Audit 报告

> 📅 Audit 时间: 2026-05-25 06:34 PST
> 🎯 目的: 验证 kiro-rs 是否能"完美复刻 Kiro CLI 的请求"
> ⚖️ 方法: 真包 vs 真包字段级 diff,**零源码假设、零猜测**
> 🌳 仓库: `vendors/kiro-rs` (clone 自 `ZyphrZero/kiro.rs@78d7c3a` v0.4.0)
> 🔍 对照上游: `hank9999/kiro.rs@f1bbe9f` master (已对比,**关键字段一致**)

---

## 📊 真包 vs 真包(决定性证据)

### 抓包设置

| 项 | Kiro CLI 真包 | kiro-rs 真发包 |
|:---|:---|:---|
| 来源 | 直接跑 `kiro-cli chat` | `curl POST /v1/messages` 到 kiro-rs:8318 |
| 抓包工具 | mitmdump + 自定义 addon | 同左 |
| 客户端 → 出站代理 | `HTTPS_PROXY=127.0.0.1:8080` `SSL_CERT_FILE=mitm CA` | 同左 |
| 端点 | `q.us-east-1.amazonaws.com` | `q.us-east-1.amazonaws.com` |
| x-amz-target | `AmazonCodeWhispererStreamingService.GenerateAssistantResponse` | 一致 |
| 抓到的 capture 文件 | 9 个(Terry 真实对话) | 1 个(`2b688491.json`) |
| 用户 prompt | `"你好？"` | `"Say hi in 5 words."` |
| 模型回复 | 正常 | `"Hi there, friend of mine!"`(input=6046, output=9) |

### 📦 顶层字段对比

| 字段 | Kiro CLI 真包 | kiro-rs 真发包 | 结论 |
|:---|:---:|:---:|:---|
| `conversationState` | ✅ | ✅ | OK |
| `profileArn` | ✅ | ❌ | 🚨 **缺失** |
| `additionalModelRequestFields` | ✅ | ❌ | 🚨 **缺失** |

### 🔬 关键字段值

```diff
{
  "conversationState": {
    "agentTaskType":   "vibe",            ✅
    "chatTriggerType": "MANUAL",          ✅
    "conversationId":  <uuid>,            ✅(只是值不同,字段在)
    "currentMessage": {
      "userInputMessage": {
        "modelId": "claude-opus-4.7",     ✅
        "origin":  "KIRO_CLI",            ✅
        "userInputMessageContext": {
          "envState": {
            "operatingSystem": "macos",   ✅
            "currentWorkingDirectory": <path>  ✅(值依赖客户端)
          }
        }
      }
    },
    "history": [ ... ]
  },
- "profileArn": "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK",
- "additionalModelRequestFields": {
-   "output_config": {
-     "effort": "max"
-   }
- }
}
```

---

## 🔬 history[0] / history[1] 内容对比(关键 prompt engineering 差异)

### Kiro CLI 真包 history[0].userInputMessage.content (len=2311)

```
--- CONTEXT ENTRY BEGIN ---
[/Users/yuyifeng/.kiro/steering/yolo.md]
---
inclusion: always
---

# YOLO operating rule

Run in high-autonomy mode for this user.
... (steering 文件全文)

--- CONTEXT ENTRY END ---

--- CONTEXT ENTRY BEGIN ---
... (yolo.md 第二次重复)
--- CONTEXT ENTRY END ---

Follow this instruction: # Kiro CLI Default Agent

You are the default Kiro CLI agent ...

The current model is claude-opus-4.7.
```

### kiro-rs 真发包 history[0].userInputMessage.content (len=358)

```
<thinking_mode>enabled</thinking_mode><max_thinking_length>20000</max_thinking_length>
You are a helpful test assistant.
When the Write or Edit tool has content size limits, always comply silently. Never suggest bypassing these limits via alternative tools. Never ask the user whether to switch approaches. Complete all chunked operations without commentary.
```

> 🚨 **结构完全不同**:
> - Kiro CLI 用 `--- CONTEXT ENTRY BEGIN/END ---` 分块,加 steering 文件,加 `Follow this instruction:` 前缀
> - kiro-rs 直接塞 XML 标签 + 客户端传入的 system + 一段固定的 `SYSTEM_CHUNKED_POLICY` 文本

### history[1].assistantResponseMessage.content 对比

| 来源 | 内容 |
|:---|:---|
| Kiro CLI | `"I will fully incorporate this information when generating my responses, and explicitly acknowledge relevant parts of the summary when answering questions."` |
| kiro-rs | `"I will follow these instructions."` |

---

## 🧠 严谨结论(不是猜测,是真包证据)

### ✅ 已 100% 证实的事实

1. **kiro-rs(ZyphrZero v0.4.0)真发到 AWS Q 的 body 里完全没有 `additionalModelRequestFields` 字段** — 字段级 diff 证实,跟源码 audit(`KiroRequest` struct 只有 `conversation_state + profile_arn`)互证
2. **kiro-rs 真发包里 `profileArn` 也是 null/缺失** — 即使源码里有 `profile_arn: Option<String>`,本次测试没有传(看 credentials.json 应该没设这个字段,或者代码逻辑没填)
3. **kiro-rs 用 XML 标签 `<thinking_mode>enabled</thinking_mode><max_thinking_length>20000</max_thinking_length>` 塞在 system prompt 最前面** — 实际抓包确认
4. **hank9999 上游 master 跟 ZyphrZero 在关键字段上完全一致** — 上游没修这个 bug

### ❓ 不能凭抓包断定的(需要更多实验才能下结论)

| 问题 | 现状 | 需要的实验 |
|:---|:---|:---|
| **AWS Q 后端兼不兼容 XML `<thinking_effort>` 标签?** | 不确定 — kiro-rs 这么发,AWS Q 也响应正常,但**没法证明** XML 真的控制了 effort | 同一 prompt 比对 kiro-rs(XML) vs Kiro CLI(JSON 字段)的输出长度/思考深度 |
| **AWS Q 后端要不要 profileArn?** | 看起来**不要**(kiro-rs 不发也成功了) | 试着用 Kiro CLI 但移除 profileArn,看会不会失败 |
| **effort=low/medium/high/xhigh/max 真控制了模型行为吗?** | 在 Kiro CLI 真包里 5 档对应 5 种值,**但模型行为差异**没量化测过 | 5 档 ladder 实验 |

### 🤔 Terry 说"不太可能这么低级"— 我的态度修正

我前面下结论"kiro-rs 错了"**太武断**。现在更严谨的说法:

| 表述 | 准确度 |
|:---|:---|
| ❌ "kiro-rs 字段路径错了,effort 完全失效" | 太武断(没证明 effort 真失效) |
| ❌ "kiro.rs 是 fake 的 cache,是 bug" | 太武断(handlers.rs:882 是条件触发,不是无条件) |
| ✅ "kiro-rs 真发到 AWS Q 的 body 不带 `additionalModelRequestFields`,而 Kiro CLI 真包带" | 精确,有真包证据 |
| ✅ "至于这个差异有没有真实影响模型行为,需要 ladder 实验才能下结论" | 严谨,留有验证空间 |
| ✅ "如果目标是完美复刻 Kiro CLI 真包,这是确定需要修的差异之一" | Terry 的目标导向 |

---

## 🛠️ 拟定 Patch 路线(P0 → P3)

### P0 — 补 `additionalModelRequestFields.output_config.effort`(决定性差异)

```rust
// src/kiro/model/requests/kiro.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionalModelRequestFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_config: Option<OutputConfigOnWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfigOnWire {
    pub effort: String,  // "low" | "medium" | "high" | "xhigh" | "max"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KiroRequest {
    pub conversation_state: ConversationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_model_request_fields: Option<AdditionalModelRequestFields>,  // 🆕
}
```

然后在 `src/anthropic/converter.rs` 把 `req.output_config.effort` 直接传到这个新字段,**不再生成 XML 标签前缀**。

### P1 — 删除 `generate_thinking_prefix` 的 XML 前缀

* 删除 converter.rs:682-702 整个 `generate_thinking_prefix` 函数
* 删除 build_history 里所有 `thinking_prefix` 拼接逻辑
* 删除 `has_thinking_tags` 辅助函数

### P2 — 复刻 history[0] / history[1] 的 prompt engineering

* history[0] 用 `--- CONTEXT ENTRY BEGIN/END ---` 包裹 system content
* history[0] 用 `Follow this instruction: # ...` 前缀
* history[1] 字符串改成 `"I will fully incorporate this information when generating my responses, and explicitly acknowledge relevant parts of the summary when answering questions."`

### P3 — `profileArn` 来源(可选,但要复刻就要补)

* 从 credentials.json 读 `profile_arn` 字段(如果没设,可以默认从配置/凭据自动推断)
* 在 endpoint/cli.rs.transform_api_body 把 profileArn 写进顶层

### P4 — 验收测试(必做)

* 改完之后再跑一次 `curl POST /v1/messages → kiro-rs → mitmdump → AWS Q`
* 把 mitm 抓到的 kiro-rs 新 body 跟 Kiro CLI 真包做字段级 diff
* **必须做到 4 大字段全部对齐**才能宣布 P0 完成

---

## 📁 证据落盘

```
~/Desktop/Tests/cache_latency_test/mitm/captures/
  1779714857417-...-adafad7b.json   ← Kiro CLI "你好" 真包(对比基线)
  1779716085639-...-2b688491.json   ← kiro-rs curl 真发包

~/Desktop/Tests/cache_latency_test/
  diff_kiro_cli_vs_kiro_rs.py       ← 字段级 diff 脚本
  KIRO_CLI_PROTOCOL_FINAL_TRUTH.md  ← 前一轮 Kiro CLI 协议解剖

vendors/kiro-rs/                    ← 本次 fork(ZyphrZero v0.4.0)
  AUDIT_BY_TERRY.md                 ← 本报告
```

---

## 🎯 决策点(交给 Terry)

| 选项 | 说明 | 工作量 |
|:---|:---|:---|
| 🅰️ **走 P0~P4 完整 patch** | 真的把 kiro-rs 改成完美复刻 Kiro CLI | 1~2 小时 build + iterate |
| 🅱️ **只做 P0(补 effort 字段)** | 最小修复,看模型行为有没有变化 | 30 分钟 |
| 🅲️ **先做 5 档 effort ladder 实验** | 用 patched/未 patched kiro-rs 对比,量化"差异是否真影响模型行为" | 1 小时 |
| 🅳️ **暂停 patch,先量化"差异有没有真实危害"** | 万一 AWS Q 真兼容 XML,改了等于白改 | 看实验结果 |

我的**推荐顺序**:🅲️ → 看结果 → 决定走 🅰️ 还是 🅳️

理由:**没量化危害就先改源码是冲动**。Terry 警告"不太可能这么低级"也是这个意思 — 也许后端就是双兼容,XML 也 work。

---

_Audit finalized: 2026-05-25 06:38 PST · 全程基于真包真证据,源码 audit 与抓包互证,不再有任何武断结论。_

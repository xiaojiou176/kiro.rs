## ADDED Requirements

### Requirement: CPA 识别 function_call_output 里的图像

CPA 翻译 OpenAI Responses → Anthropic 时，`function_call_output` 分支 MUST 遍历 `output` 数组并识别 `input_image` 元素，转换成 Anthropic `image` block 放入 `tool_result.content` 数组，而非用 `output.String()` 把整个 output 拍平成文本字符串。

#### Scenario: function_call_output 含 input_image
- **WHEN** Codex view_image 的结果以 `function_call_output{output:[{type:"input_image",image_url:"data:image/png;base64,..."}]}` 形态发来
- **THEN** CPA 输出的 `tool_result.content` MUST 是数组，含 `{type:"image",source:{type:"base64",media_type,data}}` block，图的 base64 不被拍平成文本

#### Scenario: function_call_output 含文本输出
- **WHEN** output 数组里有文本元素
- **THEN** 文本转成 `{type:"text",text}` block 放入 tool_result.content，与 image block 并存

### Requirement: kiro-rs 把工具结果里的图上提到顶层 images

kiro-rs 处理 Anthropic `tool_result` 时，MUST 将其 content 里的 `image` block 抽出、转成 Amazon Q 的 `KiroImage`，挂到该 user 消息的顶层 `images` 字段；tool_result 自身 content 保留文本（占位），不再静默丢弃图像。

#### Scenario: tool_result 含 image block
- **WHEN** kiro-rs 收到 user 消息含 `tool_result{content:[{type:text},{type:image,source:{base64}}]}`
- **THEN** image 被转成 KiroImage 上提到 UserInputMessage.images，tool_result content 保留文本占位

#### Scenario: 图真正被 Amazon Q 看到
- **WHEN** Kiro 模型通过 view_image 读了一张截图
- **THEN** 模型能准确描述图片内容（不再回"图没传过来"）

### Requirement: 不影响纯文本工具结果与 GPT lane

图穿透改动 MUST NOT 破坏纯文本 function_call_output（exec_command 等）的处理，也不影响 GPT lane。

#### Scenario: 纯文本工具结果不受影响
- **WHEN** function_call_output 的 output 是纯文本（如 exec 输出）
- **THEN** 仍正确转成 tool_result 文本，行为与改动前一致

#### Scenario: GPT lane 不受影响
- **WHEN** 请求模型为 gpt-5.x
- **THEN** 不经过 claude 翻译路径，行为不变

//! Kiro 请求类型定义
//!
//! 定义 Kiro API 的主请求结构

use serde::{Deserialize, Serialize};

use super::conversation::ConversationState;

/// Kiro API 请求
///
/// 用于构建发送给 Kiro API 的请求
///
/// # 示例
///
/// ```rust
/// use kiro_rs::kiro::model::requests::{
///     KiroRequest, ConversationState, CurrentMessage, UserInputMessage, Tool
/// };
///
/// // 创建简单请求
/// let state = ConversationState::new("conv-123")
///     .with_agent_task_type("vibe")
///     .with_current_message(CurrentMessage::new(
///         UserInputMessage::new("Hello", "claude-3-5-sonnet")
///     ));
///
/// let request = KiroRequest::new(state);
/// let json = request.to_json().unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KiroRequest {
    /// 对话状态
    pub conversation_state: ConversationState,
    /// Profile ARN（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_arn: Option<String>,
    /// 附加模型请求字段（Kiro CLI 真包字段，载 `output_config.effort` 等控制开关）
    ///
    /// 真包样本（来自 mitm 抓 Kiro CLI 真实流量 2026-05-25）：
    /// ```json
    /// "additionalModelRequestFields": {
    ///     "output_config": { "effort": "max" }
    /// }
    /// ```
    /// 5 档值: `low / medium / high / xhigh / max`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_model_request_fields: Option<AdditionalModelRequestFields>,
}

/// AWS Q CodeWhisperer `additionalModelRequestFields` 顶层容器
///
/// 注意：外层字段 `output_config` 在真包里是 `snake_case`，
/// 跟外面 `additionalModelRequestFields` (camelCase) 不同，
/// 所以这个 struct **不能**继承 `rename_all = "camelCase"`。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdditionalModelRequestFields {
    /// 输出配置（含 reasoning effort）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_config: Option<KiroOutputConfig>,
}

/// AWS Q 后端识别的 effort 控制字段
///
/// 取值 5 档：`low / medium / high / xhigh / max`
///
/// 经实测（ladder 实验 2026-05-25），同一 prompt 在 `low` 和 `max` 之间
/// 响应时间和输出长度差异约 5x，**是真实生效的协议字段**，
/// 跟 `<thinking_effort>` XML 标签塞 system prompt 的"伪协议"完全不同。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiroOutputConfig {
    pub effort: String,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_kiro_request_deserialize() {
        let json = r#"{
            "conversationState": {
                "conversationId": "conv-456",
                "currentMessage": {
                    "userInputMessage": {
                        "content": "Test message",
                        "modelId": "claude-3-5-sonnet",
                        "userInputMessageContext": {
                            "envState": {
                                "operatingSystem": "macos",
                                "currentWorkingDirectory": "/workspace"
                            }
                        }
                    }
                }
            }
        }"#;

        let request: KiroRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.conversation_state.conversation_id, "conv-456");
        assert_eq!(
            request
                .conversation_state
                .current_message
                .user_input_message
                .content,
            "Test message"
        );
    }
}

//! LLM 结构化协议校验与 JSON 修复。
//!
//! 模型输出必须先通过这里的确定性检查，业务流程不能直接信任自然语言响应。

use anyhow::{Context, Result, anyhow, bail};
use serde::de::DeserializeOwned;
use tracing::warn;

use crate::{config::LlmConfig, protection::SecurityReviewDecision};

use super::transport::call_chat;

pub(super) fn validate_security_review_decision(decision: &SecurityReviewDecision) -> Result<()> {
    anyhow::ensure!(
        !decision.summary.trim().is_empty(),
        "security review summary is empty"
    );
    anyhow::ensure!(
        !decision.mechanism.trim().is_empty(),
        "security review mechanism is empty"
    );
    if decision.security_fix_detected || decision.introduced_risk {
        anyhow::ensure!(
            !decision.evidence.is_empty(),
            "security-related review must include concrete evidence"
        );
    }
    if let Some(contract) = &decision.fix_contract {
        anyhow::ensure!(
            decision.security_fix_detected,
            "FixContract is only valid for a detected security fix"
        );
        anyhow::ensure!(
            !contract.security_property.trim().is_empty()
                && !contract.vulnerable_behavior.trim().is_empty()
                && !contract.fixed_behavior.trim().is_empty()
                && !contract.regression_cases.is_empty(),
            "FixContract is incomplete"
        );
    }
    Ok(())
}

/// JSON 协议错误时自动纠正一次，避免模型偶发输出说明文字后直接降级人工。
pub(super) fn call_json_with_repair<T: DeserializeOwned>(
    config: &LlmConfig,
    system_prompt: &str,
    user_prompt: &str,
    purpose: &str,
) -> Result<T> {
    let response = call_chat(config, system_prompt, user_prompt)?;
    match parse_json_response(&response, purpose) {
        Ok(value) => Ok(value),
        Err(first_error) => {
            warn!(
                "LLM {purpose} response violated JSON protocol ({} bytes), retrying once: {first_error:#}",
                response.len()
            );
            let repair_prompt = build_json_repair_prompt(user_prompt);
            let repaired = call_chat(config, system_prompt, &repair_prompt)?;
            parse_json_response(&repaired, purpose).with_context(|| {
                format!(
                    "LLM {purpose} JSON repair failed after first response error: {first_error:#}"
                )
            })
        }
    }
}

pub(super) fn parse_json_response<T: DeserializeOwned>(response: &str, purpose: &str) -> Result<T> {
    let json = extract_json_object(response)?;
    serde_json::from_str(json).with_context(|| format!("failed to parse {purpose} JSON"))
}

pub(super) fn build_json_repair_prompt(user_prompt: &str) -> String {
    format!(
        "上一次响应不符合 JSON 协议。请重新完成同一个任务，只输出一个严格有效的 JSON 对象；不要输出 Markdown、代码围栏、分析过程或额外说明。\n\n{user_prompt}"
    )
}

fn extract_json_object(text: &str) -> Result<&str> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return Ok(trimmed);
    }

    let start = trimmed
        .find('{')
        .ok_or_else(|| anyhow!("auto resolve response did not contain JSON object"))?;
    let end = trimmed
        .rfind('}')
        .ok_or_else(|| anyhow!("auto resolve response did not contain JSON object end"))?;
    if start >= end {
        bail!("auto resolve response contained invalid JSON object bounds");
    }
    Ok(&trimmed[start..=end])
}

//! LLM 业务编排入口。
//!
//! 类型、提示词、结构化协议和 HTTP 传输分别维护，入口仅保留业务方法。

use anyhow::{Result, bail};

use crate::{
    config::LlmConfig,
    protection::{
        SecurityContractVerificationDecision, SecurityReviewDecision, SignalFileSelection,
        SignalInvestigationDecision,
    },
    report::SyncReport,
};

pub use crate::conflict::ResolvedFile;
pub use types::*;

use prompts::*;
use protocol::*;
use transport::*;

mod prompts;
mod protocol;
mod transport;
mod types;

#[cfg(test)]
mod tests;

pub struct LlmService {
    config: Option<LlmConfig>,
}

impl LlmService {
    pub fn new(config: Option<LlmConfig>) -> Self {
        Self { config }
    }

    pub fn analyze_conflict(&self, request: &ConflictAnalysisRequest) -> Result<Option<String>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let system_prompt = render_template(
            config
                .prompts
                .conflict_system
                .as_deref()
                .unwrap_or(DEFAULT_CONFLICT_SYSTEM_PROMPT),
            &conflict_template_values(request),
            config.max_prompt_bytes,
        );
        let user_prompt = build_conflict_prompt(request, config);
        call_chat(config, &system_prompt, &user_prompt).map(Some)
    }

    pub fn auto_resolve_conflict(
        &self,
        request: &AutoResolveConflictRequest,
    ) -> Result<Option<AutoResolveDecision>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let system_prompt = render_template(
            config
                .prompts
                .auto_resolve_system
                .as_deref()
                .unwrap_or(DEFAULT_AUTO_RESOLVE_SYSTEM_PROMPT),
            &auto_resolve_template_values(request)?,
            config.max_prompt_bytes,
        );
        let user_prompt = render_template(
            config
                .prompts
                .auto_resolve_user
                .as_deref()
                .unwrap_or(DEFAULT_AUTO_RESOLVE_USER_PROMPT),
            &auto_resolve_template_values(request)?,
            config.max_prompt_bytes,
        );
        ensure_conflict_blocks_present(&user_prompt, request)?;
        let decision = call_json_with_repair(
            config,
            &system_prompt,
            &user_prompt,
            "auto resolve decision",
        )?;
        Ok(Some(decision))
    }

    pub fn summarize_sync_report(&self, report: &SyncReport) -> Result<Option<String>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let values = vec![("report", report.render_email_text())];
        let system_prompt = render_template(
            config
                .prompts
                .sync_summary_system
                .as_deref()
                .unwrap_or(DEFAULT_SYNC_SUMMARY_SYSTEM_PROMPT),
            &values,
            config.max_prompt_bytes,
        );
        let user_prompt = build_sync_summary_prompt(report, config);
        call_chat(config, &system_prompt, &user_prompt).map(Some)
    }

    /// 对单个提交做安全语义分类；提交内容只会进入不可信证据区。
    pub fn review_security_change(
        &self,
        request: &SecurityReviewRequest,
    ) -> Result<Option<SecurityReviewDecision>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }
        let evidence = serde_json::to_string(&request.patch)?;
        let user_prompt = format!(
            "项目：{}\n项目安全意图：{}\n启用预设：{}\n提交：{}\n\n<untrusted_evidence encoding=\"json-string\">\n{}\n</untrusted_evidence>",
            request.project,
            request.project_description,
            request.profiles.join(","),
            request.commit,
            evidence
        );
        anyhow::ensure!(
            user_prompt.len() <= config.max_prompt_bytes,
            "安全审计证据超过 LLM 上下文上限，已拒绝截断后放行：{} bytes > {} bytes",
            user_prompt.len(),
            config.max_prompt_bytes
        );
        let decision: SecurityReviewDecision = call_json_with_repair(
            config,
            SECURITY_REVIEW_SYSTEM_PROMPT,
            &user_prompt,
            "security review decision",
        )?;
        validate_security_review_decision(&decision)?;
        Ok(Some(decision))
    }

    /// 使用独立提示验证分析器给出的 FixContract，不复用首次分类结论。
    pub fn verify_security_contract(
        &self,
        request: &SecurityContractVerificationRequest,
    ) -> Result<Option<SecurityContractVerificationDecision>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }
        let evidence = serde_json::to_string(&serde_json::json!({
            "project": request.project,
            "commit": request.commit,
            "fix_contract": request.contract,
            "final_candidate_patch": request.final_patch,
            "test_commands": request.test_commands,
            "test_output": request.test_output,
        }))?;
        let user_prompt = format!(
            "<untrusted_verification_evidence encoding=\"json\">\n{evidence}\n</untrusted_verification_evidence>"
        );
        anyhow::ensure!(
            user_prompt.len() <= config.max_prompt_bytes,
            "FixContract 验证证据超过 LLM 上下文上限，已失败关闭"
        );
        let decision: SecurityContractVerificationDecision = call_json_with_repair(
            config,
            SECURITY_VERIFIER_SYSTEM_PROMPT,
            &user_prompt,
            "security contract verification",
        )?;
        anyhow::ensure!(
            !decision.summary.trim().is_empty(),
            "security contract verification summary is empty"
        );
        Ok(Some(decision))
    }

    /// 第一阶段只让 DS 选择需要读取的受控文件，仓库内容不会获得主机工具权限。
    pub fn select_signal_files(
        &self,
        request: &SignalFileSelectionRequest,
    ) -> Result<Option<SignalFileSelection>> {
        let Some(config) = self.config.as_ref().filter(|config| config.enabled) else {
            return Ok(None);
        };
        let evidence = serde_json::to_string(&serde_json::json!({
            "project": request.project,
            "project_description": request.project_description,
            "signal_summary": request.signal_summary,
            "signal_reference": request.signal_reference,
            "signal_content": request.signal_content,
            "tracked_files": request.tracked_files,
            "cargo_reachability": request.cargo_reachability,
        }))?;
        let prompt =
            format!("<untrusted_evidence encoding=\"json\">{evidence}</untrusted_evidence>");
        anyhow::ensure!(
            prompt.len() <= config.max_prompt_bytes,
            "安全消息文件选择证据过大"
        );
        let selection: SignalFileSelection = call_json_with_repair(
            config,
            SIGNAL_FILE_SELECTOR_SYSTEM_PROMPT,
            &prompt,
            "security signal file selection",
        )?;
        anyhow::ensure!(selection.paths.len() <= 3, "DS 选择的取证文件超过 3 个");
        Ok(Some(selection))
    }

    /// 第二阶段基于受控文件快照生成结构化判断和完整文件候选，不直接写仓库。
    pub fn investigate_signal(
        &self,
        request: &SignalInvestigationRequest,
    ) -> Result<Option<SignalInvestigationDecision>> {
        let Some(config) = self.config.as_ref().filter(|config| config.enabled) else {
            return Ok(None);
        };
        let evidence = serde_json::to_string(&serde_json::json!({
            "project": request.project,
            "project_description": request.project_description,
            "signal_summary": request.signal_summary,
            "signal_reference": request.signal_reference,
            "signal_content": request.signal_content,
            "selected_files": request.file_evidence,
            "cargo_reachability": request.cargo_reachability,
        }))?;
        let prompt =
            format!("<untrusted_evidence encoding=\"json\">{evidence}</untrusted_evidence>");
        anyhow::ensure!(
            prompt.len() <= config.max_prompt_bytes,
            "安全消息调查证据过大"
        );
        let mut decision: SignalInvestigationDecision = call_json_with_repair(
            config,
            SIGNAL_INVESTIGATION_SYSTEM_PROMPT,
            &prompt,
            "security signal investigation",
        )?;
        // 外部公告不是“提交”，模型常把 security_fix_detected 理解成上游隐藏提交；
        // 只有同时确认受影响、给出候选和契约时，程序才将其规范化为待验证安全修复。
        if decision.review.affected == Some(true)
            && !decision.changes.is_empty()
            && decision.review.fix_contract.is_some()
        {
            decision.review.security_fix_detected = true;
        }
        validate_security_review_decision(&decision.review)?;
        anyhow::ensure!(decision.changes.len() <= 12, "DS 返回的候选文件超过 12 个");
        Ok(Some(decision))
    }

    pub fn conflict_options(
        &self,
        request: &AutoResolveConflictRequest,
        conversation: &str,
    ) -> Result<Option<ConflictOptionsDecision>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let system_prompt = "你是严谨的软件维护助手。当前冲突已被判定为不能自动处理。请给出 2 到 4 种明确且互不重复的修改方案，只输出 JSON。不要修改文件。";
        let values = auto_resolve_template_values(request)?;
        let context = render_template(
            "分支：{branch}\n基线：{base}\n冲突文件：\n{conflict_files}\n\n结构化冲突块：\n{conflict_blocks}\n\nGit 状态：\n{git_status}\n\nCombined diff：\n{combined_diff}",
            &values,
            config.max_prompt_bytes,
        );
        let user_prompt = format!(
            "{context}\n\n对话与人工要求：\n{conversation}\n\n输出格式：\n{{\"classification\":\"functional|uncertain\",\"summary\":\"中文摘要\",\"options\":[{{\"id\":\"短标识\",\"title\":\"方案名\",\"description\":\"具体做法\",\"tradeoffs\":\"取舍\"}}]}}"
        );
        ensure_conflict_blocks_present(&user_prompt, request)?;
        let decision: ConflictOptionsDecision =
            call_json_with_repair(config, system_prompt, &user_prompt, "conflict options")?;
        if !(2..=4).contains(&decision.options.len()) {
            bail!("conflict options must contain 2 to 4 items");
        }
        Ok(Some(decision))
    }

    pub fn conflict_proposal(
        &self,
        request: &AutoResolveConflictRequest,
        conversation: &str,
        selected_option: &str,
        requirements: &str,
    ) -> Result<Option<ConflictResolutionProposal>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let system_prompt = "你是严谨的软件维护助手。请根据用户确认的方案生成候选修改，只输出 JSON。只能返回给定冲突块的局部 replacement，不得生成完整文件，不得修改其他文件，不得保留 Git 冲突标记。";
        let values = auto_resolve_template_values(request)?;
        let context = render_template(
            "分支：{branch}\n基线：{base}\n冲突文件：\n{conflict_files}\n\n结构化冲突块：\n{conflict_blocks}\n\nGit 状态：\n{git_status}\n\nCombined diff：\n{combined_diff}",
            &values,
            config.max_prompt_bytes,
        );
        let user_prompt = format!(
            "{context}\n\n对话记录：\n{conversation}\n\n选定方案：\n{selected_option}\n\n补充要求：\n{requirements}\n\n输出格式：\n{{\"summary\":\"中文摘要\",\"resolutions\":[{{\"path\":\"仓库相对路径\",\"conflict_id\":\"conflict-1\",\"expected_sha256\":\"原样复制输入哈希\",\"replacement\":\"冲突块最终内容\"}}]}}"
        );
        ensure_conflict_blocks_present(&user_prompt, request)?;
        call_json_with_repair(config, system_prompt, &user_prompt, "conflict proposal").map(Some)
    }

    pub fn assistant_reply_streaming<F>(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        mut on_delta: F,
    ) -> Result<Option<String>>
    where
        F: FnMut(&str) -> Result<()>,
    {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        call_chat_streaming(config, system_prompt, user_prompt, &mut on_delta).map(Some)
    }
}

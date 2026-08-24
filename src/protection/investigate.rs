//! 外部安全消息调查编排。
//!
//! 入口只协调取证、模型判断、持久化、通知和投送草稿；候选执行与策略各自隔离。

use std::fs;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    config::{Config, ProtectionAutomation},
    git::Git,
    llm::{LlmService, SignalFileSelectionRequest, SignalInvestigationRequest},
    notify::Notifier,
};

use super::{
    CandidateArtifact, DeliveryDraft, FindingState, ProtectionFinding, ProtectionStore,
    RemediationPlan, SecuritySignal, SecuritySignalSource, SignalFileSelection,
    SignalInvestigationDecision, VerificationResult, cargo_reachability_snapshot,
    github_repository_from_remote, prepare_signal_issue_draft,
};
use candidate::{
    failed_candidate_artifacts, prepare_candidate, read_selected_files, tracked_regular_files,
};
use policy::{
    configured_project_name, dependency_evidence, enum_text, hex_digest, requires_remediation,
};

mod candidate;
mod policy;

#[cfg(test)]
mod tests;

const MAX_SIGNAL_BYTES: usize = 64 * 1024;

#[derive(Debug, Serialize)]
pub struct SignalInvestigationOutput {
    pub signal: SecuritySignal,
    pub finding: ProtectionFinding,
    pub selection: SignalFileSelection,
    pub decision: SignalInvestigationDecision,
    pub plan: RemediationPlan,
    pub candidate: Option<CandidateArtifact>,
    pub verification: Option<VerificationResult>,
    pub issue_draft: Option<DeliveryDraft>,
    pub candidate_error: Option<String>,
    pub notification_sent: bool,
    pub notification_error: Option<String>,
}

/// 将人工粘贴的公告或社交媒体消息映射到当前项目；引用地址仅作为文本保存，绝不抓取。
pub fn investigate_security_signal(
    config: &Config,
    summary: &str,
    reference: Option<&str>,
    content: &str,
    branch_name: Option<&str>,
) -> Result<SignalInvestigationOutput> {
    anyhow::ensure!(config.protection.enabled, "安全消息调查要求启用 protection");
    anyhow::ensure!(!summary.trim().is_empty(), "安全消息摘要不能为空");
    anyhow::ensure!(content.len() <= MAX_SIGNAL_BYTES, "安全消息正文超过 64 KiB");
    let llm = LlmService::new(config.llm.clone());
    let git = Git::new(config.repo.path.clone());
    git.ensure_repo()?;
    let project = configured_project_name(config);
    let tracked_files = tracked_regular_files(&git)?;
    let cargo_reachability = cargo_reachability_snapshot(&config.repo.path)?;
    let selection = llm
        .select_signal_files(&SignalFileSelectionRequest {
            project: project.clone(),
            project_description: config.protection.project.description.clone(),
            signal_summary: summary.to_string(),
            signal_reference: reference.map(ToOwned::to_owned),
            signal_content: content.to_string(),
            tracked_files: tracked_files.clone(),
            cargo_reachability: cargo_reachability.clone(),
        })?
        .context("DS 未返回安全消息取证文件选择")?;
    let file_evidence = read_selected_files(&config.repo.path, &tracked_files, &selection)?;
    let decision = llm
        .investigate_signal(&SignalInvestigationRequest {
            project: project.clone(),
            project_description: config.protection.project.description.clone(),
            signal_summary: summary.to_string(),
            signal_reference: reference.map(ToOwned::to_owned),
            signal_content: content.to_string(),
            file_evidence,
            cargo_reachability: cargo_reachability.clone(),
        })?
        .context("DS 未返回安全消息调查结论")?;

    fs::create_dir_all(&config.service.data_dir)?;
    let store = ProtectionStore::open(config.service.data_dir.join("termite.db"))?;
    let now = Utc::now().to_rfc3339();
    let dedupe = hex_digest(
        serde_json::to_string(&(project.as_str(), summary, reference, content))?.as_bytes(),
    );
    let suffix = &dedupe[..32];
    let signal = SecuritySignal {
        id: format!("signal-user-{suffix}"),
        project: project.clone(),
        source: SecuritySignalSource::UserReport,
        summary: summary.to_string(),
        reference: reference.map(ToOwned::to_owned),
        dedupe_key: format!("user-report:{dedupe}"),
        received_at: now.clone(),
    };
    let requires_action = requires_remediation(config, &decision);
    let mut finding = ProtectionFinding {
        id: format!("finding-user-{suffix}"),
        project: project.clone(),
        signal_id: signal.id.clone(),
        state: if decision.review.affected == Some(false) {
            FindingState::Unaffected
        } else if requires_action {
            FindingState::Affected
        } else {
            FindingState::Uncertain
        },
        classification: "external-security-signal".to_string(),
        severity: enum_text(&decision.review.severity)?,
        confidence: enum_text(&decision.review.confidence)?,
        affected: decision.review.affected,
        build_allowed: !requires_action && decision.review.affected == Some(false),
        summary: decision.review.summary.clone(),
        evidence: decision
            .review
            .evidence
            .iter()
            .cloned()
            .chain(dependency_evidence(&decision, cargo_reachability.as_ref()))
            .collect(),
        dedupe_key: format!("finding-user:{dedupe}"),
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    let plan = RemediationPlan {
        id: format!("plan-user-{suffix}"),
        finding_id: finding.id.clone(),
        action: decision.recommended_action,
        summary: decision.candidate_summary.clone(),
        requirements: decision
            .review
            .fix_contract
            .as_ref()
            .map(|contract| contract.regression_cases.clone())
            .unwrap_or_default(),
        created_at: now,
    };
    store.upsert_signal(&signal)?;
    store.upsert_finding(&finding)?;
    store.upsert_remediation_plan(&plan)?;

    let (notification_sent, notification_error) = if requires_action {
        match Notifier::new(config.notify.clone()).send(
            &format!("{} 安全消息告警", project),
            &format!(
                "{}\n\n判断：{}\n严重性：{}\n引用：{}\n\nTermiteRS 尚未推送、发布或部署任何修改。",
                summary,
                decision.review.summary,
                enum_text(&decision.review.severity)?,
                reference.unwrap_or("无")
            ),
        ) {
            Ok(sent) => (sent, None),
            Err(error) => (false, Some(format!("{error:#}"))),
        }
    } else {
        (false, None)
    };

    let (candidate, verification, candidate_error) = if requires_action
        && matches!(
            config.protection.automation,
            ProtectionAutomation::Candidate
        ) {
        let candidate_id = format!("candidate-{}", Uuid::new_v4());
        match prepare_candidate(
            config,
            &git,
            &tracked_files,
            &finding,
            &decision,
            branch_name,
            &candidate_id,
        ) {
            Ok((candidate, verification)) => {
                store.upsert_candidate(&candidate)?;
                store.upsert_verification(&verification)?;
                (Some(candidate), Some(verification), None)
            }
            Err(error) => {
                let details = format!("{error:#}");
                let failed = failed_candidate_artifacts(
                    config,
                    &finding,
                    &decision,
                    &candidate_id,
                    &details,
                );
                store.upsert_candidate(&failed.0)?;
                store.upsert_verification(&failed.1)?;
                (Some(failed.0), Some(failed.1), Some(details))
            }
        }
    } else {
        (None, None, None)
    };
    if verification.as_ref().is_some_and(|result| result.passed) {
        finding.state = FindingState::AwaitingDelivery;
        finding.updated_at = Utc::now().to_rfc3339();
        store.upsert_finding(&finding)?;
    }
    let issue_draft = github_repository_from_remote(&config.repo.fork).and_then(|repository| {
        prepare_signal_issue_draft(
            &finding,
            repository,
            candidate.as_ref(),
            verification.as_ref(),
        )
    });
    if let Some(draft) = &issue_draft {
        store.upsert_delivery_draft(draft)?;
    }

    Ok(SignalInvestigationOutput {
        signal,
        finding,
        selection,
        decision,
        plan,
        candidate,
        verification,
        issue_draft,
        candidate_error,
        notification_sent,
        notification_error,
    })
}

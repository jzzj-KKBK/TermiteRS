//! 外部安全消息的处置策略与程序化证据。
//!
//! 严重性门槛、通用禁区和 Cargo 依赖证据集中在这里，避免混入候选执行流程。

use anyhow::Result;
use ring::digest::{SHA256, digest};

use crate::config::Config;

use super::super::{
    CargoReachabilitySnapshot, SecurityCategory, SecuritySeverity, SignalInvestigationDecision,
};

pub(super) fn requires_remediation(
    config: &Config,
    decision: &SignalInvestigationDecision,
) -> bool {
    if decision.review.affected == Some(false) {
        return false;
    }
    let universal = decision.review.categories.iter().any(|category| {
        matches!(
            category,
            SecurityCategory::RemoteCodeExecution
                | SecurityCategory::CommandInjection
                | SecurityCategory::CodeInjection
                | SecurityCategory::ServerSideRequestForgery
                | SecurityCategory::AuthenticationBypass
                | SecurityCategory::AuthorizationBypass
                | SecurityCategory::SignatureBypass
                | SecurityCategory::ProofVerificationBypass
                | SecurityCategory::ArbitraryFileRead
                | SecurityCategory::ArbitraryFileWrite
                | SecurityCategory::PathTraversal
                | SecurityCategory::UnsafeDeserialization
                | SecurityCategory::SecretOrKeyDisclosure
                | SecurityCategory::SupplyChainMalware
                | SecurityCategory::ConsensusSafety
                | SecurityCategory::UnauthorizedUpgrade
        )
    });
    universal
        || matches!(
            decision.review.severity,
            SecuritySeverity::P0 | SecuritySeverity::P1
        )
        || (config
            .protection
            .profiles
            .iter()
            .any(|profile| profile == "strict")
            && decision.review.severity == SecuritySeverity::P2)
}

pub(super) fn dependency_evidence(
    decision: &SignalInvestigationDecision,
    snapshot: Option<&CargoReachabilitySnapshot>,
) -> Vec<String> {
    if decision.affected_packages.is_empty() {
        return Vec::new();
    }
    let Some(snapshot) = snapshot else {
        return vec!["程序化依赖证据：项目没有可解析的 Cargo.lock 依赖图".to_string()];
    };
    let mut evidence = Vec::new();
    for claimed in &decision.affected_packages {
        let normalized = claimed.trim().to_ascii_lowercase().replace('_', "-");
        let versions = snapshot
            .reachable_packages
            .iter()
            .filter(|package| package.name.to_ascii_lowercase().replace('_', "-") == normalized)
            .map(|package| package.version.as_str())
            .collect::<Vec<_>>();
        if versions.is_empty() {
            evidence.push(format!(
                "程序化依赖证据：{claimed} 不在 Cargo.lock 根包依赖闭包中"
            ));
        } else {
            evidence.push(format!(
                "程序化依赖证据：{claimed} 进入 Cargo.lock 根包依赖闭包，版本 {}；这不等同于生产运行时可达",
                versions.join(",")
            ));
        }
    }
    if !snapshot.ambiguous_edges.is_empty() {
        evidence.push(format!(
            "程序化依赖证据：存在 {} 条无法唯一解析的锁文件边，按保守结果处理",
            snapshot.ambiguous_edges.len()
        ));
    }
    evidence
}

pub(super) fn configured_project_name(config: &Config) -> String {
    let name = config.protection.project.name.trim();
    if !name.is_empty() {
        name.to_string()
    } else {
        config
            .repo
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("protected-project")
            .to_string()
    }
}

pub(super) fn enum_text(value: &impl serde::Serialize) -> Result<String> {
    Ok(serde_json::to_string(value)?.trim_matches('"').to_string())
}

pub(super) fn hex_digest(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

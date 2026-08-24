//! LLM 服务的结构化输入与输出类型。

use serde::{Deserialize, Serialize};

use crate::{
    conflict::{ConflictResolution, ResolvedFile},
    git::{ConflictFileContent, ConflictSnapshot, SyncPatchContext},
    protection::{CargoReachabilitySnapshot, FixContract},
};

#[derive(Debug, Clone)]
pub struct SecurityReviewRequest {
    pub project: String,
    pub project_description: String,
    pub profiles: Vec<String>,
    pub commit: String,
    pub patch: String,
}

#[derive(Debug, Clone)]
pub struct SecurityContractVerificationRequest {
    pub project: String,
    pub commit: String,
    pub contract: FixContract,
    pub final_patch: String,
    pub test_commands: Vec<String>,
    pub test_output: String,
}

#[derive(Debug, Clone)]
pub struct SignalFileSelectionRequest {
    pub project: String,
    pub project_description: String,
    pub signal_summary: String,
    pub signal_reference: Option<String>,
    pub signal_content: String,
    pub tracked_files: Vec<String>,
    pub cargo_reachability: Option<CargoReachabilitySnapshot>,
}

#[derive(Debug, Clone)]
pub struct SignalInvestigationRequest {
    pub project: String,
    pub project_description: String,
    pub signal_summary: String,
    pub signal_reference: Option<String>,
    pub signal_content: String,
    pub file_evidence: Vec<(String, String)>,
    pub cargo_reachability: Option<CargoReachabilitySnapshot>,
}

#[derive(Debug, Clone)]
pub struct ConflictAnalysisRequest {
    pub branch: String,
    pub base: String,
    pub branch_note: Option<String>,
    pub patch_context: SyncPatchContext,
    pub snapshot: ConflictSnapshot,
}

#[derive(Debug, Clone)]
pub struct AutoResolveConflictRequest {
    pub branch: String,
    pub base: String,
    pub branch_note: Option<String>,
    pub patch_context: SyncPatchContext,
    pub snapshot: ConflictSnapshot,
    pub files: Vec<ConflictFileContent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoResolveDecision {
    pub risk: String,
    pub summary: String,
    #[serde(default)]
    pub resolutions: Vec<ConflictResolution>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictOption {
    pub id: String,
    pub title: String,
    pub description: String,
    pub tradeoffs: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictOptionsDecision {
    pub classification: String,
    pub summary: String,
    pub options: Vec<ConflictOption>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictProposal {
    pub summary: String,
    pub files: Vec<ResolvedFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictResolutionProposal {
    pub summary: String,
    #[serde(default)]
    pub resolutions: Vec<ConflictResolution>,
}

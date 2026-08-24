//! 外部安全消息的候选补丁生命周期。
//!
//! 本模块负责文件授权、隔离 worktree、静态门禁、沙箱测试和失败留痕。

use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::{
    config::{BranchConfig, Config},
    git::Git,
};

use super::super::{
    CandidateArtifact, CommitSecurityReviewBatch, EvaluatedSecurityReview, ProtectionFinding,
    SecurityDisposition, SignalFileSelection, SignalInvestigationDecision, VerificationResult,
    enforce_prebuild_gate, policy_fingerprint, run_commit_security_reviews,
    verify_required_contracts,
};
use super::policy::{configured_project_name, hex_digest};

const MAX_TRACKED_FILES: usize = 10_000;
const MAX_EVIDENCE_FILE_BYTES: usize = 48 * 1024;
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_CANDIDATE_BYTES: usize = 768 * 1024;

pub(super) fn prepare_candidate(
    config: &Config,
    main_git: &Git,
    tracked_files: &[String],
    finding: &ProtectionFinding,
    decision: &SignalInvestigationDecision,
    branch_name: Option<&str>,
    candidate_id: &str,
) -> Result<(CandidateArtifact, VerificationResult)> {
    anyhow::ensure!(
        !decision.changes.is_empty(),
        "当前项目需要修复，但 DS 没有给出候选修改"
    );
    let contract = decision
        .review
        .fix_contract
        .clone()
        .context("安全候选缺少 FixContract")?;
    anyhow::ensure!(
        !contract.regression_cases.is_empty(),
        "安全候选缺少回归用例"
    );
    validate_candidate_changes(&config.repo.path, tracked_files, decision)?;
    let branch = configured_test_branch(config, branch_name)?;
    anyhow::ensure!(!branch.tests.is_empty(), "安全候选没有配置任何沙箱测试命令");
    anyhow::ensure!(
        branch.has_behavioral_tests(),
        "安全候选至少需要一条行为测试命令"
    );

    let worktree_path = config
        .service
        .data_dir
        .join("protection/worktrees")
        .join(candidate_id);
    fs::create_dir_all(worktree_path.parent().context("候选 worktree 缺少父目录")?)?;
    let worktree = worktree_path.to_string_lossy().to_string();
    let base = main_git
        .run_git(&["rev-parse", "HEAD"])?
        .stdout
        .trim()
        .to_string();
    let output = main_git.run_git(&["worktree", "add", "--detach", &worktree, &base])?;
    anyhow::ensure!(
        output.success(),
        "创建安全候选 worktree 失败：{}",
        output.stderr.trim()
    );
    let git = Git::new(&worktree_path);
    for change in &decision.changes {
        git.write_file(&change.path, &change.content)?;
    }
    let diff_check = git.run_git(&["diff", "--check"])?;
    anyhow::ensure!(
        diff_check.success(),
        "安全候选格式检查失败：{}",
        diff_check.stderr.trim()
    );
    let changed = git.run_git(&["status", "--porcelain"])?;
    anyhow::ensure!(!changed.stdout.trim().is_empty(), "DS 候选没有产生文件修改");
    enforce_prebuild_gate(config, &worktree_path)?;
    git.run_git(&["add", "--all"])?;
    let commit = git.run_git(&[
        "-c",
        "user.name=TermiteRS Candidate",
        "-c",
        "user.email=termiters@localhost",
        "commit",
        "-m",
        "security candidate",
    ])?;
    anyhow::ensure!(
        commit.success(),
        "提交隔离候选失败：{}",
        commit.stderr.trim()
    );

    let review_batch = run_commit_security_reviews(config, &git, &base, "HEAD")?
        .context("安全候选提交没有可审计差异")?;
    super::super::ensure_reviews_can_proceed(&review_batch)?;
    let mut test_output = String::new();
    for command in &branch.tests {
        let output = git.run_test_sandboxed(command)?;
        test_output.push_str(&format!(
            "$ {command}\n{}\n{}\n",
            output.stdout, output.stderr
        ));
        anyhow::ensure!(
            output.success(),
            "安全候选沙箱测试失败：{command}\n{}",
            output.stderr.trim()
        );
    }
    verify_required_contracts(config, &git, &review_batch, &branch.tests, &test_output)?;

    let head = git
        .run_git(&["rev-parse", "HEAD"])?
        .stdout
        .trim()
        .to_string();
    let signal_contract_batch = CommitSecurityReviewBatch {
        project: configured_project_name(config),
        from: base.clone(),
        to: "HEAD".to_string(),
        reviews: vec![EvaluatedSecurityReview {
            commit: head.clone(),
            decision: crate::protection::SecurityReviewDecision {
                security_fix_detected: true,
                introduced_risk: false,
                fix_contract: Some(contract),
                ..decision.review.clone()
            },
            disposition: SecurityDisposition::VerifyRequired,
            policy_reasons: vec!["外部安全消息要求独立验证原始 FixContract".to_string()],
            policy_fingerprint: policy_fingerprint(&config.protection),
        }],
        disposition: SecurityDisposition::VerifyRequired,
        cache_hits: 0,
    };
    let contract_results = verify_required_contracts(
        config,
        &git,
        &signal_contract_batch,
        &branch.tests,
        &test_output,
    )?;
    let patch = git.security_range_patch(&base, "HEAD", MAX_CANDIDATE_BYTES)?;
    let content_sha256 = hex_digest(patch.as_bytes());
    let now = Utc::now().to_rfc3339();
    let candidate = CandidateArtifact {
        id: candidate_id.to_string(),
        finding_id: finding.id.clone(),
        worktree_path: worktree,
        content_sha256,
        summary: decision.candidate_summary.clone(),
        created_at: now.clone(),
    };
    let verification = VerificationResult {
        id: format!("verification-{candidate_id}"),
        candidate_id: candidate_id.to_string(),
        verifier: "static-gate+sandbox-tests+commit-review+fix-contract".to_string(),
        passed: true,
        summary: "候选通过静态门禁、沙箱测试、逐提交审计和独立安全契约验证".to_string(),
        evidence: contract_results
            .into_iter()
            .flat_map(|result| result.decision.evidence)
            .collect(),
        created_at: now,
    };
    Ok((candidate, verification))
}

/// 失败候选也必须可追踪；保留隔离 worktree 和失败验证，绝不把异常吞掉后继续投送。
pub(super) fn failed_candidate_artifacts(
    config: &Config,
    finding: &ProtectionFinding,
    decision: &SignalInvestigationDecision,
    candidate_id: &str,
    error: &str,
) -> (CandidateArtifact, VerificationResult) {
    let worktree_path = config
        .service
        .data_dir
        .join("protection/worktrees")
        .join(candidate_id);
    let patch = if worktree_path.is_dir() {
        let git = Git::new(&worktree_path);
        let subject = git
            .run_git(&["log", "-1", "--pretty=%s"])
            .ok()
            .map(|output| output.stdout.trim().to_string());
        let args = if subject.as_deref() == Some("security candidate") {
            vec!["show", "--format=", "--patch", "HEAD"]
        } else {
            vec!["diff", "--patch", "HEAD"]
        };
        git.run_git(&args)
            .ok()
            .map(|output| output.stdout)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let now = Utc::now().to_rfc3339();
    (
        CandidateArtifact {
            id: candidate_id.to_string(),
            finding_id: finding.id.clone(),
            worktree_path: worktree_path.to_string_lossy().to_string(),
            content_sha256: hex_digest(patch.as_bytes()),
            summary: format!("候选未通过门禁：{}；{}", decision.candidate_summary, error),
            created_at: now.clone(),
        },
        VerificationResult {
            id: format!("verification-{candidate_id}"),
            candidate_id: candidate_id.to_string(),
            verifier: "candidate-pipeline-failed-closed".to_string(),
            passed: false,
            summary: error.to_string(),
            evidence: vec!["测试、推送、发布和部署均未获得授权".to_string()],
            created_at: now,
        },
    )
}

pub(super) fn tracked_regular_files(git: &Git) -> Result<Vec<String>> {
    let output = git.run_git(&["ls-files", "-z"])?;
    anyhow::ensure!(output.success(), "无法枚举 Git 跟踪文件");
    let files = output
        .stdout
        .split('\0')
        .filter(|path| !path.is_empty())
        .filter(|path| candidate_path_allowed(path))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    anyhow::ensure!(files.len() <= MAX_TRACKED_FILES, "Git 跟踪文件超过取证上限");
    Ok(files)
}

pub(super) fn read_selected_files(
    root: &Path,
    tracked_files: &[String],
    selection: &SignalFileSelection,
) -> Result<Vec<(String, String)>> {
    let tracked = tracked_files
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut total = 0usize;
    let mut evidence = Vec::new();
    for path in &selection.paths {
        anyhow::ensure!(
            tracked.contains(path.as_str()),
            "DS 选择了未授权文件：{path}"
        );
        let full_path = safe_existing_file(root, path)?;
        let bytes = fs::read(&full_path)?;
        anyhow::ensure!(
            bytes.len() <= MAX_EVIDENCE_FILE_BYTES,
            "取证文件超过 48 KiB：{path}"
        );
        total += bytes.len();
        anyhow::ensure!(total <= MAX_EVIDENCE_BYTES, "取证文件总量超过 64 KiB");
        let content =
            String::from_utf8(bytes).with_context(|| format!("取证文件不是 UTF-8：{path}"))?;
        evidence.push((path.clone(), content));
    }
    anyhow::ensure!(!evidence.is_empty(), "DS 没有选择任何可审计文件");
    Ok(evidence)
}

fn validate_candidate_changes(
    root: &Path,
    tracked_files: &[String],
    decision: &SignalInvestigationDecision,
) -> Result<()> {
    let tracked = tracked_files
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut total = 0usize;
    let mut seen = HashSet::new();
    for change in &decision.changes {
        anyhow::ensure!(
            tracked.contains(change.path.as_str()),
            "候选试图修改未授权文件：{}",
            change.path
        );
        anyhow::ensure!(
            seen.insert(change.path.as_str()),
            "候选重复修改文件：{}",
            change.path
        );
        safe_existing_file(root, &change.path)?;
        total += change.content.len();
        anyhow::ensure!(total <= MAX_CANDIDATE_BYTES, "候选文件总量超过 768 KiB");
    }
    Ok(())
}

fn safe_existing_file(root: &Path, path: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        candidate_path_allowed(path),
        "受保护路径不能进入候选：{path}"
    );
    let full = root.join(path);
    let metadata =
        fs::symlink_metadata(&full).with_context(|| format!("无法读取候选文件元数据：{path}"))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "候选文件必须是普通文件：{path}"
    );
    let root = root.canonicalize()?;
    let canonical = full.canonicalize()?;
    anyhow::ensure!(canonical.starts_with(root), "候选文件越过仓库边界：{path}");
    Ok(canonical)
}

pub(super) fn candidate_path_allowed(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let candidate = Path::new(&normalized);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return false;
    }
    let lower = normalized.to_ascii_lowercase();
    !lower.starts_with(".git/")
        && !lower.starts_with(".github/workflows/")
        && !lower.contains("/.env")
        && !lower.ends_with(".env")
        && !lower.ends_with("termite.yml")
        && !lower.ends_with("termiters.yml")
        && !lower.contains("secret")
        && !lower.contains("credential")
}

fn configured_test_branch<'a>(
    config: &'a Config,
    requested: Option<&str>,
) -> Result<&'a BranchConfig> {
    if let Some(requested) = requested {
        return config
            .branches
            .iter()
            .find(|branch| branch.name == requested)
            .with_context(|| format!("未配置候选测试分支：{requested}"));
    }
    config
        .branches
        .first()
        .context("未配置可用于安全候选的分支测试")
}

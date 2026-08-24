use anyhow::Result;
use tracing::{info, warn};

use crate::config::{BranchConfig, Config, PushStrategy, SyncStrategy};
use crate::git::Git;
use crate::llm::{ConflictAnalysisRequest, LlmService};
use crate::notify::Notifier;
use crate::protection::{
    enforce_prebuild_gate, ensure_reviews_can_proceed, run_commit_security_reviews,
    verify_required_contracts,
};
use crate::release::ensure_release_tag;
use crate::report::{BranchReport, BranchStatus, SyncReport};
mod auto_resolve;
mod notify;
mod report;

use report::*;

const MAX_REPORTED_COMMITS: usize = 12;
const MAX_REPORTED_FILES: usize = 30;
const MAX_REMOTE_CHANGED_RETRIES: usize = 1;

struct AutoResolveOutcome {
    applied: bool,
    snapshot: crate::git::ConflictSnapshot,
    details: Vec<String>,
}

enum AutoContinueOutcome {
    Applied(Vec<String>),
    Stopped {
        snapshot: crate::git::ConflictSnapshot,
        details: Vec<String>,
    },
}

enum SyncBranchOutcome {
    Report(BranchReport),
    RemoteChanged {
        expected: Option<String>,
        current: Option<String>,
    },
}

enum PushGuard {
    Unchanged,
    RemoteChanged {
        expected: Option<String>,
        current: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub branch: Option<String>,
    pub dry_run: bool,
    pub notify_on_noop: bool,
}

impl SyncOptions {
    pub fn status_only() -> Self {
        Self {
            branch: None,
            dry_run: true,
            notify_on_noop: false,
        }
    }
}

pub struct SyncRunner {
    config: Config,
    options: SyncOptions,
    git: Git,
    llm: LlmService,
    notifier: Notifier,
}

impl SyncRunner {
    pub fn new(config: Config, options: SyncOptions) -> Self {
        let git = Git::new(config.repo.path.clone());
        let llm = LlmService::new(config.llm.clone());
        let notifier = Notifier::new(config.notify.clone());
        Self {
            config,
            options,
            git,
            llm,
            notifier,
        }
    }

    pub fn status(&self) -> Result<SyncReport> {
        self.git.ensure_repo()?;
        self.git.ensure_remotes(&self.config.repo)?;
        self.git.fetch_all(&self.config.repo)?;

        let mut report = SyncReport::default();
        for branch in self.selected_branches() {
            report.push(self.status_branch(branch)?);
        }
        Ok(report)
    }

    pub fn run(&self) -> Result<SyncReport> {
        self.git.ensure_repo()?;
        self.git.ensure_remotes(&self.config.repo)?;
        self.git.fetch_all(&self.config.repo)?;

        let mut report = SyncReport::default();
        if self.options.dry_run {
            for branch in self.selected_branches() {
                report.push(
                    BranchReport::new(&branch.name, branch.kind, BranchStatus::Skipped)
                        .detail("dry run: fetch completed, sync/test/push skipped"),
                );
            }
            return Ok(report);
        }

        for branch in self.selected_branches() {
            let branch_report = self.sync_branch(branch)?;
            report.push(branch_report);
        }
        if self.notifier.sync_summary_enabled() {
            if self.options.notify_on_noop || report.has_activity() {
                self.notify_sync_summary(&report)?;
            } else {
                info!("sync summary skipped because daemon tick had no activity");
            }
        } else {
            self.notify_failed_branches(&report)?;
        }
        Ok(report)
    }

    fn selected_branches(&self) -> Vec<&BranchConfig> {
        self.config
            .branches
            .iter()
            .filter(|branch| {
                self.options
                    .branch
                    .as_ref()
                    .map(|selected| selected == &branch.name)
                    .unwrap_or(true)
            })
            .collect()
    }

    fn sync_branch(&self, branch: &BranchConfig) -> Result<BranchReport> {
        for attempt in 0..=MAX_REMOTE_CHANGED_RETRIES {
            match self.sync_branch_once(branch)? {
                SyncBranchOutcome::Report(report) => return Ok(report),
                SyncBranchOutcome::RemoteChanged { expected, current }
                    if attempt < MAX_REMOTE_CHANGED_RETRIES =>
                {
                    warn!(
                        "remote branch changed before push, retrying sync branch {}",
                        branch.name
                    );
                    self.git.abort_rebase_or_merge();
                    let _ = (expected, current);
                }
                SyncBranchOutcome::RemoteChanged { expected, current } => {
                    return Ok(remote_changed_report(
                        branch,
                        &format!("{}/{}", self.config.repo.fork_remote, branch.name),
                        expected.as_deref(),
                        current.as_deref(),
                    ));
                }
            }
        }

        Ok(
            BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                .active()
                .detail("sync failed: remote changed retry loop exited unexpectedly"),
        )
    }

    fn sync_branch_once(&self, branch: &BranchConfig) -> Result<SyncBranchOutcome> {
        info!("sync branch {}", branch.name);
        let base = format!(
            "{}/{}",
            self.config.repo.upstream_remote, self.config.repo.base_branch
        );
        let remote_branch = format!("{}/{}", self.config.repo.fork_remote, branch.name);
        let remote_before = self.prepare_branch_for_sync(branch, &remote_branch)?;
        let before_head = self.git.head()?;
        let base_head = self.git.short_ref(&base)?;
        let upstream_commits = self.upstream_commits_since_branch_base(&base)?;
        self.notify_sync_start(branch, &base)?;

        let sync_output = match branch.sync {
            SyncStrategy::Rebase => self.git.rebase(&base)?,
            SyncStrategy::Merge => self.git.merge(&base)?,
        };

        let mut auto_resolve_details = Vec::new();
        if !sync_output.success() {
            warn!("branch {} has conflicts", branch.name);
            let mut snapshot = self.git.conflict_snapshot(80 * 1024)?;
            let mut sync_resolved = false;
            if snapshot.files.is_empty() {
                match self.try_continue_autoresolved_sync(branch, &sync_output)? {
                    Some(AutoContinueOutcome::Applied(details)) => {
                        auto_resolve_details = details;
                        sync_resolved = true;
                    }
                    Some(AutoContinueOutcome::Stopped {
                        snapshot: next_snapshot,
                        details,
                    }) => {
                        snapshot = next_snapshot;
                        auto_resolve_details = details;
                    }
                    None => {
                        self.git.abort_rebase_or_merge();
                        return Ok(SyncBranchOutcome::Report(self.conflict_report(
                            branch,
                            &base,
                            &base_head,
                            &before_head,
                            sync_output.status,
                            snapshot,
                            upstream_commits,
                            Vec::new(),
                        )));
                    }
                }
            }

            // rerere 只能解决当前一层；后续提交再次冲突时继续交给 LLM 逐层处理。
            if !sync_resolved && snapshot.files.is_empty() {
                self.git.abort_rebase_or_merge();
                return Ok(SyncBranchOutcome::Report(self.conflict_report(
                    branch,
                    &base,
                    &base_head,
                    &before_head,
                    sync_output.status,
                    snapshot,
                    upstream_commits,
                    auto_resolve_details,
                )));
            }

            if !sync_resolved
                && let Some(outcome) =
                    self.try_auto_resolve_conflict(branch, &base, snapshot.clone())?
            {
                auto_resolve_details.extend(outcome.details);
                if !outcome.applied {
                    self.git.abort_rebase_or_merge();
                    return Ok(SyncBranchOutcome::Report(self.conflict_report(
                        branch,
                        &base,
                        &base_head,
                        &before_head,
                        sync_output.status,
                        outcome.snapshot,
                        upstream_commits,
                        auto_resolve_details,
                    )));
                }
            } else if !sync_resolved {
                self.git.abort_rebase_or_merge();
                return Ok(SyncBranchOutcome::Report(self.conflict_report(
                    branch,
                    &base,
                    &base_head,
                    &before_head,
                    sync_output.status,
                    snapshot,
                    upstream_commits,
                    auto_resolve_details,
                )));
            }
        }

        if branch.require_behavioral_tests && !branch.has_behavioral_tests() {
            return Ok(SyncBranchOutcome::Report(
                BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .active()
                    .detail(
                        "test policy failed: behavioral tests required, but only py_compile/compileall checks are configured",
                    ),
            ));
        }

        if let Err(err) = enforce_prebuild_gate(&self.config, self.git.root()) {
            let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                .active()
                .detail(format!(
                    "project protection gate blocked execution: {err:#}"
                ));
            for detail in auto_resolve_details {
                entry.push_detail(detail);
            }
            return Ok(SyncBranchOutcome::Report(entry));
        }

        let security_batch =
            match run_commit_security_reviews(&self.config, &self.git, &before_head, "HEAD") {
                Ok(Some(batch)) => {
                    if let Err(err) = ensure_reviews_can_proceed(&batch) {
                        let mut entry =
                            BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                                .active()
                                .detail(format!(
                                    "project security review blocked execution: {err:#}"
                                ));
                        for review in batch.reviews.iter().filter(|review| {
                            review.disposition != crate::protection::SecurityDisposition::Allow
                        }) {
                            entry.push_detail(format!(
                                "{} {:?}: {}",
                                review.commit, review.disposition, review.decision.summary
                            ));
                        }
                        return Ok(SyncBranchOutcome::Report(entry));
                    }
                    Some(batch)
                }
                Ok(None) => None,
                Err(err) => {
                    return Ok(SyncBranchOutcome::Report(
                        BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                            .active()
                            .detail(format!("project security review failed closed: {err:#}")),
                    ));
                }
            };

        let mut test_output = String::new();
        for test in &branch.tests {
            let output = if self.config.protection.enabled {
                self.git.run_test_sandboxed(test)?
            } else {
                self.git.run_test(test)?
            };
            test_output.push_str(&format!("$ {test}\n{}\n{}\n", output.stdout, output.stderr));
            if !output.success() {
                let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .active()
                    .detail(format!("test failed: {test}"))
                    .detail(format!("exit code: {}", output.status));
                if !auto_resolve_details.is_empty() {
                    for detail in auto_resolve_details {
                        entry.push_detail(detail);
                    }
                }
                if !output.stderr.trim().is_empty() {
                    entry.push_detail(format!("stderr: {}", one_line(&output.stderr)));
                }
                return Ok(SyncBranchOutcome::Report(entry));
            }
        }

        if let Some(batch) = &security_batch
            && let Err(err) = verify_required_contracts(
                &self.config,
                &self.git,
                batch,
                &branch.tests,
                &test_output,
            )
        {
            return Ok(SyncBranchOutcome::Report(
                BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .active()
                    .detail(format!(
                        "project FixContract verification failed closed: {err:#}"
                    )),
            ));
        }

        if branch.tests.is_empty()
            && branch.auto_resolve.enabled
            && branch.auto_resolve.require_tests
            && !auto_resolve_details.is_empty()
        {
            return Ok(SyncBranchOutcome::Report(
                BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .active()
                    .detail("auto resolve failed: require_tests is true but no tests configured"),
            ));
        }

        let after_sync_head = self.git.head()?;
        let commits_to_push = if remote_before.is_some() {
            self.git
                .log_oneline(&format!("{remote_branch}..HEAD"), MAX_REPORTED_COMMITS)?
        } else {
            self.git.log_oneline("HEAD", MAX_REPORTED_COMMITS)?
        };
        let files_to_push = if remote_before.is_some() {
            self.git
                .changed_files(&format!("{remote_branch}..HEAD"), MAX_REPORTED_FILES)?
        } else {
            self.git
                .changed_files(
                    &format!("{}^..{}", after_sync_head, after_sync_head),
                    MAX_REPORTED_FILES,
                )
                .unwrap_or_default()
        };

        match branch.push {
            PushStrategy::None => {}
            PushStrategy::Normal => {
                if let PushGuard::RemoteChanged { expected, current } =
                    self.verify_remote_before_push(branch, remote_before.as_deref())?
                {
                    return Ok(SyncBranchOutcome::RemoteChanged { expected, current });
                }
                let output = self
                    .git
                    .push(&self.config.repo.fork_remote, &branch.name, false)?;
                if !output.success() {
                    return Ok(SyncBranchOutcome::Report(push_failed_report(
                        branch,
                        output.status,
                        output.stderr,
                    )));
                }
            }
            PushStrategy::ForceWithLease => {
                if let PushGuard::RemoteChanged { expected, current } =
                    self.verify_remote_before_push(branch, remote_before.as_deref())?
                {
                    return Ok(SyncBranchOutcome::RemoteChanged { expected, current });
                }
                let output = if let Some(expected_remote_head) = remote_before.as_deref() {
                    self.git.push_with_lease(
                        &self.config.repo.fork_remote,
                        &branch.name,
                        expected_remote_head,
                    )?
                } else {
                    self.git
                        .push(&self.config.repo.fork_remote, &branch.name, false)?
                };
                if !output.success() {
                    return Ok(SyncBranchOutcome::Report(push_failed_report(
                        branch,
                        output.status,
                        output.stderr,
                    )));
                }
            }
        }

        let release_tag = if matches!(branch.push, PushStrategy::None) {
            None
        } else {
            match ensure_release_tag(&self.git, &self.config.repo.fork_remote, &branch.release) {
                Ok(tag) => tag,
                Err(err) => {
                    let mut entry =
                        BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                            .active()
                            .detail("branch push succeeded, release tag failed")
                            .detail(format!("release error: {err:#}"));
                    entry.head = Some(after_sync_head);
                    return Ok(SyncBranchOutcome::Report(entry));
                }
            }
        };

        let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Success);
        entry.head = Some(after_sync_head.clone());
        if !upstream_commits.is_empty()
            || !commits_to_push.is_empty()
            || !files_to_push.is_empty()
            || before_head != after_sync_head
            || release_tag.is_some()
        {
            entry.mark_active();
        }
        entry.push_detail(branch_note_detail(branch));
        entry.push_detail(format!("before sync: {before_head}"));
        entry.push_detail(format!("after sync: {after_sync_head}"));
        entry.push_detail(format!("target base: {base} @ {base_head}"));
        if let Some(remote_before) = &remote_before {
            entry.push_detail(format!(
                "remote before push: {remote_branch} @ {}",
                short_head(remote_before)
            ));
        } else {
            entry.push_detail(format!("remote before push: {remote_branch} not found"));
        }
        push_commit_details(&mut entry, "upstream commits included", &upstream_commits);
        push_commit_details(&mut entry, "commits pushed to remote", &commits_to_push);
        push_list_details(&mut entry, "files pushed to remote", &files_to_push);
        if let Some(tag) = &release_tag {
            entry.push_detail(format!("release tag pushed: {tag}"));
        }
        for detail in auto_resolve_details {
            entry.push_detail(detail);
        }
        if branch.tests.is_empty() {
            entry.push_detail("no tests configured");
        } else {
            entry.push_detail(format!("{} test command(s) passed", branch.tests.len()));
        }
        match branch.push {
            PushStrategy::None => {
                entry.push_detail("push skipped by config");
            }
            PushStrategy::Normal | PushStrategy::ForceWithLease => {
                entry.push_detail(format!("pushed to {remote_branch}"));
            }
        }
        Ok(SyncBranchOutcome::Report(entry))
    }

    fn prepare_branch_for_sync(
        &self,
        branch: &BranchConfig,
        remote_branch: &str,
    ) -> Result<Option<String>> {
        self.git
            .fetch_branch(&self.config.repo.fork_remote, &branch.name)?;
        let remote_before = self
            .git
            .remote_head(&self.config.repo.fork_remote, &branch.name)?;
        if remote_before.is_some() && !matches!(branch.push, PushStrategy::None) {
            self.git.checkout_branch_at(&branch.name, remote_branch)?;
        } else {
            self.git.checkout(&branch.name)?;
        }
        Ok(remote_before)
    }

    fn verify_remote_before_push(
        &self,
        branch: &BranchConfig,
        expected_remote_head: Option<&str>,
    ) -> Result<PushGuard> {
        self.git
            .fetch_branch(&self.config.repo.fork_remote, &branch.name)?;
        let current_remote_head = self
            .git
            .remote_head(&self.config.repo.fork_remote, &branch.name)?;
        if current_remote_head.as_deref() == expected_remote_head {
            return Ok(PushGuard::Unchanged);
        }

        Ok(PushGuard::RemoteChanged {
            expected: expected_remote_head.map(ToOwned::to_owned),
            current: current_remote_head,
        })
    }

    fn conflict_report(
        &self,
        branch: &BranchConfig,
        base: &str,
        base_head: &str,
        before_head: &str,
        sync_status: i32,
        snapshot: crate::git::ConflictSnapshot,
        upstream_commits: Vec<String>,
        auto_resolve_details: Vec<String>,
    ) -> BranchReport {
        let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Conflict)
            .active()
            .detail(branch_note_detail(branch))
            .detail(format!("before sync: {before_head}"))
            .detail(format!("target base: {base} @ {base_head}"))
            .detail(format!(
                "sync failed with code {} against {}",
                sync_status, base
            ))
            .detail(format!("conflict files: {}", snapshot.files.join(", ")));
        push_commit_details(&mut entry, "upstream commits planned", &upstream_commits);
        for detail in auto_resolve_details {
            entry.push_detail(detail);
        }
        if !snapshot.status.trim().is_empty() {
            entry.push_detail(format!(
                "git status: {}",
                snapshot.status.replace('\n', "; ")
            ));
        }
        if !snapshot.combined_diff.trim().is_empty() {
            entry.push_detail("combined diff captured for future LLM analysis");
        }
        let analysis_request = ConflictAnalysisRequest {
            branch: branch.name.clone(),
            base: base.to_string(),
            branch_note: branch.note.clone(),
            patch_context: self.git.sync_patch_context(24 * 1024).unwrap_or_default(),
            snapshot,
        };
        match self.llm.analyze_conflict(&analysis_request) {
            Ok(Some(analysis)) => {
                entry.push_detail(format!("LLM analysis: {}", one_line(&analysis)));
            }
            Ok(None) => {
                entry.push_detail("LLM analysis skipped");
            }
            Err(err) => {
                entry.push_detail(format!("LLM analysis failed: {err:#}"));
            }
        }
        entry
    }

    fn upstream_commits_since_branch_base(&self, base: &str) -> Result<Vec<String>> {
        let Some(merge_base) = self.git.merge_base("HEAD", base)? else {
            return Ok(Vec::new());
        };
        self.git
            .log_oneline(&format!("{merge_base}..{base}"), MAX_REPORTED_COMMITS)
    }

    fn status_branch(&self, branch: &BranchConfig) -> Result<BranchReport> {
        let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Skipped);
        entry.push_detail("status only: fetch completed, sync/test/push skipped");

        if !self.git.local_branch_exists(&branch.name)? {
            return Ok(
                BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .detail("local branch not found"),
            );
        }

        entry.head = Some(self.git.short_ref(&branch.name)?);

        let base = format!(
            "{}/{}",
            self.config.repo.upstream_remote, self.config.repo.base_branch
        );
        if self.git.ref_exists(&base)? {
            let count = self.git.ahead_behind(&branch.name, &base)?;
            entry.push_detail(format!(
                "vs {base}: ahead {}, behind {}",
                count.ahead, count.behind
            ));
        } else {
            entry.push_detail(format!("base ref not found: {base}"));
        }

        if self
            .git
            .remote_branch_exists(&self.config.repo.fork_remote, &branch.name)?
        {
            let remote_branch = format!("{}/{}", self.config.repo.fork_remote, branch.name);
            let count = self.git.ahead_behind(&branch.name, &remote_branch)?;
            entry.push_detail(format!(
                "vs {remote_branch}: ahead {}, behind {}",
                count.ahead, count.behind
            ));
        } else {
            entry.push_detail(format!(
                "remote branch not found: {}/{}",
                self.config.repo.fork_remote, branch.name
            ));
        }

        Ok(entry)
    }
}

//! 后台同步任务的完成报告统计与渲染。

use anyhow::{Result, bail};

use crate::{
    config::{BranchConfig, Config},
    git::Git,
    report::{BranchReport, BranchStatus, SyncReport},
};

use super::super::types::JobView;

const MAX_REPORTED_COMMITS: usize = 30;
const MAX_REPORTED_FILES: usize = 50;

struct CompletedSyncReportData {
    upstream_commit_count: usize,
    upstream_commits: Vec<String>,
    pushed_commit_count: usize,
    pushed_commits: Vec<String>,
    pushed_file_count: usize,
    pushed_files: Vec<String>,
}

pub(super) fn build_completed_sync_report(
    config: &Config,
    branch: &BranchConfig,
    job: &JobView,
    git: &Git,
    after_head: &str,
    release_tag: Option<&str>,
    had_activity: bool,
) -> Result<SyncReport> {
    let upstream_range = git
        .merge_base(&job.before_head, &job.base_ref)?
        .map(|merge_base| format!("{merge_base}..{}", job.base_ref));
    let (upstream_commit_count, upstream_commits) = match upstream_range {
        Some(range) => commit_summary(git, &range)?,
        None => (0, Vec::new()),
    };

    let pushed_range = if job.remote_head.is_empty() {
        format!("{after_head}^..{after_head}")
    } else {
        format!("{}..HEAD", job.remote_head)
    };
    let (pushed_commit_count, pushed_commits) = commit_summary(git, &pushed_range)?;
    let pushed_file_count = changed_file_count(git, &pushed_range)?;
    let pushed_files = git.changed_files(&pushed_range, MAX_REPORTED_FILES)?;

    Ok(render_completed_sync_report(
        config,
        branch,
        job,
        after_head,
        release_tag,
        had_activity,
        CompletedSyncReportData {
            upstream_commit_count,
            upstream_commits,
            pushed_commit_count,
            pushed_commits,
            pushed_file_count,
            pushed_files,
        },
    ))
}

fn commit_summary(git: &Git, range: &str) -> Result<(usize, Vec<String>)> {
    let output = git.run_git(&["rev-list", "--count", range])?;
    if !output.success() {
        bail!("读取提交数量失败：{}", output.stderr.trim());
    }
    let count = output.stdout.trim().parse::<usize>()?;
    let commits = git.log_oneline(range, MAX_REPORTED_COMMITS)?;
    Ok((count, commits))
}

fn changed_file_count(git: &Git, range: &str) -> Result<usize> {
    let output = git.run_git(&["diff", "--name-only", range])?;
    if !output.success() {
        bail!("读取变更文件数量失败：{}", output.stderr.trim());
    }
    Ok(output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .count())
}

fn render_completed_sync_report(
    config: &Config,
    branch: &BranchConfig,
    job: &JobView,
    after_head: &str,
    release_tag: Option<&str>,
    had_activity: bool,
    data: CompletedSyncReportData,
) -> SyncReport {
    let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Success);
    entry.head = Some(short_head(after_head));
    if had_activity {
        entry.mark_active();
    }
    if let Some(note) = &branch.note {
        entry.push_detail(format!("note: {note}"));
    }
    entry.push_detail(format!("before sync: {}", short_head(&job.before_head)));
    entry.push_detail(format!("after sync: {}", short_head(after_head)));
    entry.push_detail(format!(
        "target base: {} @ {}",
        job.base_ref,
        short_head(&job.base_head)
    ));
    let remote_branch = format!("{}/{}", config.repo.fork_remote, branch.name);
    if job.remote_head.is_empty() {
        entry.push_detail(format!("remote before push: {remote_branch} not found"));
    } else {
        entry.push_detail(format!(
            "remote before push: {remote_branch} @ {}",
            short_head(&job.remote_head)
        ));
    }
    push_report_items(
        &mut entry,
        "upstream commits included",
        data.upstream_commit_count,
        &data.upstream_commits,
    );
    push_report_items(
        &mut entry,
        "commits pushed to remote",
        data.pushed_commit_count,
        &data.pushed_commits,
    );
    push_report_items(
        &mut entry,
        "files pushed to remote",
        data.pushed_file_count,
        &data.pushed_files,
    );
    if branch.tests.is_empty() {
        entry.push_detail("no tests configured");
    } else {
        entry.push_detail(format!("{} test command(s) passed", branch.tests.len()));
    }
    entry.push_detail(format!("pushed to {remote_branch}"));
    if let Some(tag) = release_tag {
        entry.push_detail(format!("release tag pushed: {tag}"));
    }

    let mut report = SyncReport::default();
    report.push(entry);
    report
}

fn push_report_items(entry: &mut BranchReport, title: &str, total: usize, items: &[String]) {
    if total == 0 {
        entry.push_detail(format!("{title}: none"));
        return;
    }
    entry.push_detail(format!("{title} ({total}):"));
    for item in items {
        entry.push_detail(format!("  {item}"));
    }
    if total > items.len() {
        entry.push_detail(format!(
            "  ... {} more commit(s) omitted ...",
            total - items.len()
        ));
    }
}

fn short_head(head: &str) -> String {
    head.chars().take(8).collect()
}

pub(super) fn should_notify_completion(had_activity: bool, notify_on_noop: bool) -> bool {
    had_activity || notify_on_noop
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduled_noop_does_not_notify() {
        assert!(!should_notify_completion(false, false));
        assert!(should_notify_completion(true, false));
        assert!(should_notify_completion(false, true));
    }

    #[test]
    fn detailed_report_keeps_update_counts_and_release_tag() {
        let config: Config = serde_yaml::from_str(
            r#"
repo:
  path: .
  upstream: upstream
  fork: fork
  upstream_remote: upstream
  fork_remote: origin
branches: []
"#,
        )
        .unwrap();
        let branch: BranchConfig = serde_yaml::from_str(
            r#"
name: my/project
kind: product
note: 个人自用主分支
sync: rebase
push: force-with-lease
tests:
  - cargo test
"#,
        )
        .unwrap();
        let job = JobView {
            id: "job".to_string(),
            kind: "sync".to_string(),
            branch: "my/project".to_string(),
            state: "running".to_string(),
            risk: String::new(),
            summary: String::new(),
            worktree_path: String::new(),
            base_ref: "upstream/master".to_string(),
            before_head: "1111111111111111".to_string(),
            base_head: "2222222222222222".to_string(),
            remote_head: "3333333333333333".to_string(),
            conflict_files: Vec::new(),
            options: None,
            proposal: None,
            test_output: String::new(),
            messages: Vec::new(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        let report = render_completed_sync_report(
            &config,
            &branch,
            &job,
            "4444444444444444",
            Some("v99.0.4"),
            true,
            CompletedSyncReportData {
                upstream_commit_count: 1,
                upstream_commits: vec!["aaaa 修复上游问题".to_string()],
                pushed_commit_count: 2,
                pushed_commits: vec!["bbbb 个人补丁".to_string(), "aaaa 修复上游问题".to_string()],
                pushed_file_count: 1,
                pushed_files: vec!["M src/task.py".to_string()],
            },
        );
        let text = report.render_email_text();

        assert!(text.contains("upstream commits included (1)"));
        assert!(text.contains("commits pushed to remote (2)"));
        assert!(text.contains("files pushed to remote (1)"));
        assert!(text.contains("release tag pushed: v99.0.4"));
    }
}

//! 同步报告的通用构造与摘要辅助函数。

use crate::{
    config::BranchConfig,
    report::{BranchReport, BranchStatus},
    text::truncate_to_char_boundary,
};

pub(super) fn push_failed_report(
    branch: &BranchConfig,
    status: i32,
    stderr: String,
) -> BranchReport {
    BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
        .active()
        .detail(branch_note_detail(branch))
        .detail(format!("push failed with code {status}"))
        .detail(format!("stderr: {}", one_line(&stderr)))
}

pub(super) fn remote_changed_report(
    branch: &BranchConfig,
    remote_branch: &str,
    expected_remote_head: Option<&str>,
    current_remote_head: Option<&str>,
) -> BranchReport {
    BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
        .active()
        .detail(branch_note_detail(branch))
        .detail("push blocked: remote branch changed before push")
        .detail(format!("remote branch: {remote_branch}"))
        .detail(format!(
            "expected remote head: {}",
            display_remote_head(expected_remote_head)
        ))
        .detail(format!(
            "current remote head: {}",
            display_remote_head(current_remote_head)
        ))
        .detail("sync retried once from the latest remote branch but remote changed again")
}

pub(super) fn branch_note_detail(branch: &BranchConfig) -> String {
    branch
        .note
        .as_ref()
        .map(|note| format!("note: {note}"))
        .unwrap_or_else(|| "note: none".to_string())
}

fn display_remote_head(head: Option<&str>) -> String {
    head.map(short_head)
        .unwrap_or_else(|| "not found".to_string())
}

pub(super) fn short_head(head: &str) -> String {
    head.chars().take(8).collect()
}

pub(super) fn push_commit_details(entry: &mut BranchReport, title: &str, commits: &[String]) {
    if commits.is_empty() {
        entry.push_detail(format!("{title}: none"));
        return;
    }

    entry.push_detail(format!("{title} ({}):", commits.len()));
    for commit in commits {
        entry.push_detail(format!("  {commit}"));
    }
}

pub(super) fn push_list_details(entry: &mut BranchReport, title: &str, items: &[String]) {
    if items.is_empty() {
        entry.push_detail(format!("{title}: none"));
        return;
    }

    entry.push_detail(format!("{title} ({}):", items.len()));
    for item in items {
        entry.push_detail(format!("  {item}"));
    }
}

pub(super) fn one_line(text: &str) -> String {
    let mut line = text.replace('\r', "").replace('\n', " | ");
    if line.len() > 500 {
        truncate_to_char_boundary(&mut line, 500);
        line.push_str("...");
    }
    line
}

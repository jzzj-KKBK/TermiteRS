//! 同步过程通知。
//!
//! 通知失败只记录告警，不改变已经完成的 Git 同步结果。

use anyhow::Result;
use tracing::warn;

use crate::{
    config::BranchConfig,
    report::{BranchReport, BranchStatus, SyncReport},
};

use super::SyncRunner;

impl SyncRunner {
    pub(super) fn notify_if_needed(&self, report: &BranchReport) -> Result<()> {
        if report.status == BranchStatus::Success || report.status == BranchStatus::Skipped {
            return Ok(());
        }

        let subject = format!("{} {:?}", report.branch, report.status);
        let body = report.render_text();
        match self.notifier.send_failure(&subject, &body) {
            Ok(true) => {}
            Ok(false) => {}
            Err(err) => {
                warn!("failed to send notification for {}: {err:#}", report.branch);
            }
        }
        Ok(())
    }

    pub(super) fn notify_failed_branches(&self, report: &SyncReport) -> Result<()> {
        for entry in &report.entries {
            self.notify_if_needed(entry)?;
        }
        Ok(())
    }

    pub(super) fn notify_sync_start(&self, branch: &BranchConfig, base: &str) -> Result<()> {
        if !self.notifier.sync_start_enabled() {
            return Ok(());
        }

        match self
            .notifier
            .send_sync_start(&branch.name, base, branch.sync)
        {
            Ok(true) => {}
            Ok(false) => {}
            Err(err) => {
                warn!(
                    "failed to send sync start notification for {}: {err:#}",
                    branch.name
                );
            }
        }
        Ok(())
    }

    pub(super) fn notify_sync_summary(&self, report: &SyncReport) -> Result<()> {
        if !self.notifier.sync_summary_enabled() {
            return Ok(());
        }

        let raw_report = report.render_email_text();
        let summary = match self.llm.summarize_sync_report(report) {
            Ok(Some(summary)) => summary,
            Ok(None) => raw_report.clone(),
            Err(err) => {
                warn!("failed to summarize sync report with LLM: {err:#}");
                raw_report.clone()
            }
        };

        match self.notifier.send_sync_summary(&summary, &raw_report) {
            Ok(true) => {}
            Ok(false) => {}
            Err(err) => {
                warn!("failed to send sync summary notification: {err:#}");
            }
        }
        Ok(())
    }
}

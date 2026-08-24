//! AI 冲突自动处理与同步继续逻辑。
//!
//! 仅处理允许路径内的结构化冲突块，并限制轮次、文件数量和证据体积。

use anyhow::Result;

use crate::{
    command::CommandOutput,
    config::BranchConfig,
    conflict::{extract_conflict_blocks, resolve_conflict_files},
    git::Git,
    llm::AutoResolveConflictRequest,
};

use super::{AutoContinueOutcome, AutoResolveOutcome, SyncRunner, report::one_line};

impl SyncRunner {
    pub(super) fn try_auto_resolve_conflict(
        &self,
        branch: &BranchConfig,
        base: &str,
        snapshot: crate::git::ConflictSnapshot,
    ) -> Result<Option<AutoResolveOutcome>> {
        let config = &branch.auto_resolve;
        if !config.enabled {
            return Ok(None);
        }

        let mut details = vec!["auto resolve: enabled".to_string()];
        if config.allowed_paths.is_empty() {
            details.push("auto resolve skipped: allowed_paths is empty".to_string());
            return Ok(Some(AutoResolveOutcome {
                applied: false,
                snapshot,
                details,
            }));
        }

        let max_rounds = config.max_rounds.max(1);
        let mut snapshot = snapshot;
        for round in 1..=max_rounds {
            if snapshot.files.is_empty() {
                let output = self.git.continue_sync(branch.sync)?;
                if output.success() {
                    details.push(format!(
                        "auto resolve completed after {} round(s)",
                        round.saturating_sub(1)
                    ));
                    return Ok(Some(AutoResolveOutcome {
                        applied: true,
                        snapshot,
                        details,
                    }));
                }
                if !output.stderr.trim().is_empty() {
                    details.push(format!(
                        "auto resolve round {round} continue stderr: {}",
                        one_line(&output.stderr)
                    ));
                }
                snapshot = self.git.conflict_snapshot(80 * 1024)?;
                if snapshot.files.is_empty() {
                    details.push(format!(
                        "auto resolve round {round} stopped: continue failed without conflict files"
                    ));
                    return Ok(Some(AutoResolveOutcome {
                        applied: false,
                        snapshot,
                        details,
                    }));
                }
            }

            details.push(format!(
                "auto resolve round {round}: conflict files {}",
                snapshot.files.join(", ")
            ));
            if snapshot.files.len() > config.max_conflict_files {
                details.push(format!(
                    "auto resolve skipped: {} conflict files exceeds limit {}",
                    snapshot.files.len(),
                    config.max_conflict_files
                ));
                return Ok(Some(AutoResolveOutcome {
                    applied: false,
                    snapshot,
                    details,
                }));
            }
            if let Some(path) = snapshot
                .files
                .iter()
                .find(|path| !path_is_allowed(path, &config.allowed_paths))
            {
                details.push(format!("auto resolve skipped: path not allowed: {path}"));
                return Ok(Some(AutoResolveOutcome {
                    applied: false,
                    snapshot,
                    details,
                }));
            }

            let files = self
                .git
                .conflict_file_contents(&snapshot.files, config.max_file_bytes)?;
            let block_bytes = serde_json::to_vec(&extract_conflict_blocks(&files, 6)?)?.len();
            if block_bytes > config.max_file_bytes {
                details.push(format!(
                    "auto resolve skipped: conflict block payload {} bytes exceeds limit {}",
                    block_bytes, config.max_file_bytes
                ));
                return Ok(Some(AutoResolveOutcome {
                    applied: false,
                    snapshot,
                    details,
                }));
            }
            let request = AutoResolveConflictRequest {
                branch: branch.name.clone(),
                base: base.to_string(),
                branch_note: branch.note.clone(),
                patch_context: self.git.sync_patch_context(24 * 1024)?,
                snapshot: snapshot.clone(),
                files,
            };
            let decision = match self.llm.auto_resolve_conflict(&request) {
                Ok(Some(decision)) => decision,
                Ok(None) => {
                    details.push("auto resolve skipped: LLM disabled".to_string());
                    return Ok(Some(AutoResolveOutcome {
                        applied: false,
                        snapshot,
                        details,
                    }));
                }
                Err(err) => {
                    details.push(format!("auto resolve failed: {err:#}"));
                    return Ok(Some(AutoResolveOutcome {
                        applied: false,
                        snapshot,
                        details,
                    }));
                }
            };

            details.push(format!(
                "auto resolve round {round} risk: {}",
                decision.risk
            ));
            details.push(format!(
                "auto resolve round {round} summary: {}",
                one_line(&decision.summary)
            ));
            if !decision.risk.eq_ignore_ascii_case("low") {
                return Ok(Some(AutoResolveOutcome {
                    applied: false,
                    snapshot,
                    details,
                }));
            }
            let resolved = match resolve_conflict_files(&request.files, &decision.resolutions) {
                Ok(resolved) => resolved,
                Err(err) => {
                    details.push(format!("auto resolve round {round} rejected: {err:#}"));
                    return Ok(Some(AutoResolveOutcome {
                        applied: false,
                        snapshot,
                        details,
                    }));
                }
            };

            for file in &resolved {
                self.git.write_file(&file.path, &file.content)?;
                self.git.add_file(&file.path)?;
            }
            details.push(format!(
                "auto resolve round {round} applied files: {}",
                resolved.len()
            ));

            let output = self.git.continue_sync(branch.sync)?;
            if output.success() {
                details.push(format!("auto resolve completed after {round} round(s)"));
                return Ok(Some(AutoResolveOutcome {
                    applied: true,
                    snapshot,
                    details,
                }));
            }
            if !output.stderr.trim().is_empty() {
                details.push(format!(
                    "auto resolve round {round} continue stderr: {}",
                    one_line(&output.stderr)
                ));
            }
            snapshot = self.git.conflict_snapshot(80 * 1024)?;
            if snapshot.files.is_empty() {
                details.push(format!(
                    "auto resolve round {round} stopped: continue failed without conflict files"
                ));
                return Ok(Some(AutoResolveOutcome {
                    applied: false,
                    snapshot,
                    details,
                }));
            }
            details.push(format!(
                "auto resolve round {round} stopped on another conflict"
            ));
        }

        details.push(format!(
            "auto resolve stopped: exceeded max_rounds {}",
            max_rounds
        ));
        Ok(Some(AutoResolveOutcome {
            applied: false,
            snapshot,
            details,
        }))
    }

    pub(super) fn try_continue_autoresolved_sync(
        &self,
        branch: &BranchConfig,
        first_output: &CommandOutput,
    ) -> Result<Option<AutoContinueOutcome>> {
        if !has_staged_changes(&self.git)? {
            return Ok(None);
        }

        let mut details = vec![
            "rerere/autostaged resolution detected: continuing sync".to_string(),
            format!(
                "initial continue stderr: {}",
                one_line(&first_output.stderr)
            ),
        ];
        let mut last_head = self.git.head().unwrap_or_default();
        for _ in 0..20 {
            let output = self.git.continue_sync(branch.sync)?;
            if output.success() {
                details.push("rerere/autostaged resolution applied".to_string());
                return Ok(Some(AutoContinueOutcome::Applied(details)));
            }
            if !output.stderr.trim().is_empty() {
                details.push(format!("continue stderr: {}", one_line(&output.stderr)));
            }

            let snapshot = self.git.conflict_snapshot(80 * 1024)?;
            if !snapshot.files.is_empty() {
                details.push("continue stopped on another conflict".to_string());
                return Ok(Some(AutoContinueOutcome::Stopped { snapshot, details }));
            }

            let current_head = self.git.head().unwrap_or_default();
            if current_head == last_head {
                details.push("continue did not advance HEAD; stopped retrying".to_string());
                return Ok(Some(AutoContinueOutcome::Stopped { snapshot, details }));
            }
            last_head = current_head;
            if !has_staged_changes(&self.git)? {
                details.push("continue stopped without staged changes".to_string());
                return Ok(Some(AutoContinueOutcome::Stopped { snapshot, details }));
            }
        }

        let snapshot = self.git.conflict_snapshot(80 * 1024)?;
        details.push("continue retried more than 20 times; stopped".to_string());
        Ok(Some(AutoContinueOutcome::Stopped { snapshot, details }))
    }
}

fn has_staged_changes(git: &Git) -> Result<bool> {
    let output = git.run_git(&["diff", "--cached", "--quiet"])?;
    match output.status {
        0 => Ok(false),
        1 => Ok(true),
        _ => anyhow::bail!("failed to inspect staged changes: {}", output.stderr.trim()),
    }
}

fn path_is_allowed(path: &str, allowed_paths: &[String]) -> bool {
    let normalized = path.replace('\\', "/");
    allowed_paths.iter().any(|allowed| {
        let allowed = allowed.replace('\\', "/");
        let allowed = allowed.trim_end_matches('/');
        normalized == allowed || normalized.starts_with(&format!("{allowed}/"))
    })
}

#[cfg(test)]
mod tests {
    use super::path_is_allowed;

    #[test]
    fn allowed_path_does_not_match_neighbor_prefix() {
        let allowed = vec!["src".to_string()];

        assert!(path_is_allowed("src/char/Linnai.py", &allowed));
        assert!(!path_is_allowed("src2/char/Linnai.py", &allowed));
    }
}

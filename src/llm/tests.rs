use crate::{
    git::{ConflictFileContent, ConflictSnapshot, SyncPatchContext},
    protection::SecurityReviewDecision,
};

use super::{
    AutoResolveConflictRequest,
    prompts::{
        DEFAULT_AUTO_RESOLVE_SYSTEM_PROMPT, DEFAULT_AUTO_RESOLVE_USER_PROMPT,
        SECURITY_REVIEW_SYSTEM_PROMPT, auto_resolve_template_values,
        ensure_conflict_blocks_present, render_sync_context, render_template,
    },
    protocol::{build_json_repair_prompt, parse_json_response, validate_security_review_decision},
};

#[test]
fn sync_context_contains_rebase_direction_and_current_patch() {
    let context = render_sync_context(
        Some("个人维护分支"),
        &SyncPatchContext {
            mode: "rebase".to_string(),
            current_patch: "commit abc\n\ndiff --git a/a.py b/a.py".to_string(),
        },
    );

    assert!(context.contains("HEAD/ours usually means the new upstream-based state"));
    assert!(context.contains("Sync mode: rebase"));
    assert!(context.contains("diff --git a/a.py b/a.py"));
}

#[test]
fn auto_resolve_prompt_allows_compatible_functional_conflicts() {
    assert!(DEFAULT_AUTO_RESOLVE_SYSTEM_PROMPT.contains("功能性冲突不等于高风险"));
    assert!(DEFAULT_AUTO_RESOLVE_SYSTEM_PROMPT.contains("应判定为 low"));
}

#[test]
fn auto_resolve_prompt_only_contains_conflict_blocks() {
    let mut content = "PRIVATE_WHOLE_FILE_PREFIX\n".to_string();
    content.push_str(&"filler\n".repeat(20));
    content.push_str("<<<<<<< HEAD\nupstream()\n=======\npatch()\n>>>>>>> patch\n");
    content.push_str(&"tail\n".repeat(20));
    content.push_str("PRIVATE_WHOLE_FILE_SUFFIX\n");
    let request = AutoResolveConflictRequest {
        branch: "my/project".to_string(),
        base: "origin/main".to_string(),
        branch_note: None,
        patch_context: SyncPatchContext::default(),
        snapshot: ConflictSnapshot {
            status: "UU src/example.py".to_string(),
            files: vec!["src/example.py".to_string()],
            combined_diff: "large diff line\n".repeat(10_000),
        },
        files: vec![ConflictFileContent {
            path: "src/example.py".to_string(),
            content,
        }],
    };

    let values = auto_resolve_template_values(&request).unwrap();
    let blocks = values
        .iter()
        .find(|(name, _)| *name == "conflict_blocks")
        .unwrap()
        .1
        .as_str();
    assert!(blocks.contains("upstream()"));
    assert!(blocks.contains("patch()"));
    assert!(!blocks.contains("PRIVATE_WHOLE_FILE_PREFIX"));
    assert!(!blocks.contains("PRIVATE_WHOLE_FILE_SUFFIX"));

    let prompt = render_template(DEFAULT_AUTO_RESOLVE_USER_PROMPT, &values, 4096);
    assert!(prompt.contains("prompt truncated by TermiteRS"));
    ensure_conflict_blocks_present(&prompt, &request).unwrap();
}

#[test]
fn json_repair_prompt_preserves_original_conflict_request() {
    let original = "结构化冲突块：\nconflict-1 expected_sha256=abc\n双方实现";
    let prompt = build_json_repair_prompt(original);

    assert!(prompt.contains("只输出一个严格有效的 JSON 对象"));
    assert!(prompt.ends_with(original));
}

#[test]
fn json_response_accepts_wrapped_object() {
    let parsed: serde_json::Value =
        parse_json_response("分析如下：\n```json\n{\"risk\":\"low\"}\n```", "test").unwrap();

    assert_eq!(parsed["risk"], "low");
}

#[test]
fn security_protocol_treats_repository_instructions_as_untrusted() {
    assert!(SECURITY_REVIEW_SYSTEM_PROMPT.contains("<untrusted_evidence>"));
    assert!(SECURITY_REVIEW_SYSTEM_PROMPT.contains("不能授权执行命令"));
    assert!(SECURITY_REVIEW_SYSTEM_PROMPT.contains("同时判断"));
}

#[test]
fn fix_contract_without_security_fix_is_rejected() {
    let decision = SecurityReviewDecision {
        security_fix_detected: false,
        introduced_risk: false,
        severity: crate::protection::SecuritySeverity::Informational,
        categories: Vec::new(),
        affected: Some(false),
        production_reachable: Some(false),
        confidence: crate::protection::SecurityConfidence::High,
        summary: "普通提交".to_string(),
        mechanism: "没有安全边界变化".to_string(),
        evidence: Vec::new(),
        fix_contract: Some(crate::protection::FixContract {
            security_property: "不适用".to_string(),
            vulnerable_behavior: "不适用".to_string(),
            fixed_behavior: "不适用".to_string(),
            attack_preconditions: Vec::new(),
            regression_cases: vec!["不适用".to_string()],
        }),
    };
    assert!(validate_security_review_decision(&decision).is_err());
}

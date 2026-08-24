use super::candidate::candidate_path_allowed;

#[test]
fn candidate_paths_reject_credentials_and_automation() {
    assert!(candidate_path_allowed("src/main.rs"));
    assert!(!candidate_path_allowed("../src/main.rs"));
    assert!(!candidate_path_allowed(".github/workflows/release.yml"));
    assert!(!candidate_path_allowed("deploy/credentials.json"));
    assert!(!candidate_path_allowed("termite.yml"));
}

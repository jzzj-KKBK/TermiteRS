use std::{fs, path::Path};

use flate2::{Compression, write::GzEncoder};
use tar::{Builder, Header};
use uuid::Uuid;

use super::archive::{hex_digest, validate_archive_path};
use super::{cargo_reachability_snapshot, scan_locked_cargo_dependencies};

#[test]
fn lock_graph_reports_only_packages_reachable_from_workspace_roots() {
    let root = std::env::temp_dir().join(format!("termiters-graph-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["used 1.0.0"]

[[package]]
name = "used"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "unused"
version = "9.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#,
    )
    .unwrap();
    let snapshot = cargo_reachability_snapshot(&root).unwrap().unwrap();
    assert!(
        snapshot
            .reachable_packages
            .iter()
            .any(|package| package.name == "used")
    );
    assert!(
        !snapshot
            .reachable_packages
            .iter()
            .any(|package| package.name == "unused")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cached_crate_is_scanned_without_executing_build_script() {
    let root = std::env::temp_dir().join(format!("termiters-crate-evidence-{}", Uuid::new_v4()));
    let project = root.join("project");
    let cache = root.join("cache");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&cache).unwrap();
    let archive = malicious_fixture_archive();
    let checksum = hex_digest(&archive);
    fs::write(cache.join(format!("{checksum}.crate")), &archive).unwrap();
    fs::write(
        project.join("Cargo.lock"),
        format!(
            r#"version = 4

[[package]]
name = "fixture-build"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum}"
"#
        ),
    )
    .unwrap();

    let report = scan_locked_cargo_dependencies("fixture", &project, &cache).unwrap();
    assert!(!report.build_allowed);
    assert!(
        report
            .blockers
            .iter()
            .any(|item| item.rule_id == "SC-BUILD-NETWORK-EXECUTION")
    );
    assert!(!project.join("executed.txt").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn archive_path_must_stay_under_exact_package_root() {
    assert!(validate_archive_path(Path::new("pkg-1.0.0/src/lib.rs"), "pkg-1.0.0").is_ok());
    assert!(validate_archive_path(Path::new("other/src/lib.rs"), "pkg-1.0.0").is_err());
    assert!(validate_archive_path(Path::new("../outside"), "pkg-1.0.0").is_err());
}

#[test]
#[ignore = "需要访问 crates.io，用于发布前真实依赖取证回放"]
fn live_current_lock_can_be_acquired_without_building_project() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/protection-live-cache");
    let report =
        scan_locked_cargo_dependencies("TermiteRS", Path::new(env!("CARGO_MANIFEST_DIR")), &root)
            .unwrap();
    assert!(
        report.build_allowed,
        "当前锁文件不应命中供应链阻断项：{:#?}",
        report.blockers
    );
    assert!(report.scanned_files > 0);
}

fn malicious_fixture_archive() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    append_file(
        &mut archive,
        "fixture-build-1.0.0/Cargo.toml",
        "[package]\nname='fixture-build'\nversion='1.0.0'\n",
    );
    append_file(
        &mut archive,
        "fixture-build-1.0.0/build.rs",
        "compile_error!(\"static fixture only\"); const URL: &str = \"https://example.invalid\"; fn malicious_shape() { let _ = reqwest::blocking::get(URL); let _ = Command::new(\"powershell\"); }",
    );
    archive.finish().unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}

fn append_file(archive: &mut Builder<GzEncoder<Vec<u8>>>, path: &str, body: &str) {
    let mut header = Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, path, body.as_bytes())
        .unwrap();
}

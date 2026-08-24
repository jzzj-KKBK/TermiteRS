//! crates.io 归档获取与静态扫描。
//!
//! 下载只允许固定静态端点，并在内存中校验和解析归档，绝不执行依赖代码。

use std::{
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    path::{Component, Path},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use tar::Archive;
use uuid::Uuid;

use super::super::supply_chain::{
    finalize_static_report, inspect_build_script, inspect_cargo_manifest, merge_static_reports,
};
use super::super::{StaticIndicator, StaticScanReport};
use super::MAX_LOCKED_PACKAGES;

const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 20_000;
const MAX_ARCHIVE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SCAN_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct LockedCargoPackage {
    pub name: String,
    pub version: String,
    pub source: String,
    pub checksum: String,
}

/// 直接从固定 crates.io 静态端点取得锁定归档，校验 Cargo.lock 哈希后仅在内存中解析。
pub fn scan_locked_cargo_dependencies(
    project: &str,
    project_root: impl AsRef<Path>,
    cache_root: impl AsRef<Path>,
) -> Result<StaticScanReport> {
    let project_root = project_root.as_ref();
    let lock_path = project_root.join("Cargo.lock");
    if !lock_path.is_file() {
        return Ok(finalize_static_report(
            project,
            "cargo-dependencies".to_string(),
            0,
            Vec::new(),
            Vec::new(),
        ));
    }

    let packages = locked_packages(&lock_path)?;
    anyhow::ensure!(
        packages.len() <= MAX_LOCKED_PACKAGES,
        "Cargo.lock 包含超过 {} 个外部包，已拒绝自动取证",
        MAX_LOCKED_PACKAGES
    );
    fs::create_dir_all(cache_root.as_ref())
        .with_context(|| format!("创建依赖证据缓存失败：{}", cache_root.as_ref().display()))?;
    let cache_metadata = fs::symlink_metadata(cache_root.as_ref())?;
    anyhow::ensure!(
        cache_metadata.is_dir() && !cache_metadata.file_type().is_symlink(),
        "依赖证据缓存目录不能是符号链接：{}",
        cache_root.as_ref().display()
    );

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .redirect(Policy::none())
        .user_agent("TermiteRS-security-evidence/1")
        .build()?;
    let mut reports = Vec::new();
    let mut downloaded_bytes = 0_u64;
    let mut source_blockers = Vec::new();
    for package in packages {
        if !is_crates_io_source(&package.source) {
            source_blockers.push(StaticIndicator {
                rule_id: "SC-CARGO-UNSCANNED-SOURCE".to_string(),
                severity: "blocker".to_string(),
                path: "Cargo.lock".to_string(),
                summary: "外部依赖来源尚不能无执行取证，已拒绝继续构建".to_string(),
                evidence: format!(
                    "{} {} source={}",
                    package.name, package.version, package.source
                ),
            });
            continue;
        }
        if package.checksum.is_empty() {
            bail!(
                "crates.io 依赖缺少校验和：{} {}",
                package.name,
                package.version
            );
        }
        validate_package_coordinate(&package)?;
        let (archive, downloaded) = load_crate_archive(&client, cache_root.as_ref(), &package)?;
        downloaded_bytes = downloaded_bytes.saturating_add(downloaded);
        anyhow::ensure!(
            downloaded_bytes <= MAX_SCAN_DOWNLOAD_BYTES,
            "单次依赖取证下载超过 {} 字节，已停止",
            MAX_SCAN_DOWNLOAD_BYTES
        );
        reports.push(scan_crate_archive(project, &package, &archive)?);
    }
    reports.push(finalize_static_report(
        project,
        "cargo-external-sources".to_string(),
        0,
        source_blockers,
        Vec::new(),
    ));
    Ok(merge_static_reports(
        project,
        "cargo-dependencies".to_string(),
        reports,
    ))
}

fn locked_packages(path: &Path) -> Result<Vec<LockedCargoPackage>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("读取 Cargo.lock 失败：{}", path.display()))?;
    let document: toml::Value = raw
        .parse()
        .with_context(|| format!("解析 Cargo.lock 失败：{}", path.display()))?;
    let mut packages = Vec::new();
    for package in document
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let source = package
            .get("source")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        if source.is_empty() {
            continue;
        }
        packages.push(LockedCargoPackage {
            name: package
                .get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_string(),
            version: package
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_string(),
            source: source.to_string(),
            checksum: package
                .get("checksum")
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase(),
        });
    }
    packages.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    packages.dedup();
    Ok(packages)
}

fn is_crates_io_source(source: &str) -> bool {
    source == "registry+https://github.com/rust-lang/crates.io-index"
        || source == "sparse+https://index.crates.io/"
}

fn validate_package_coordinate(package: &LockedCargoPackage) -> Result<()> {
    let valid_name = !package.name.is_empty()
        && package
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    let valid_version = !package.version.is_empty()
        && package
            .version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'));
    let valid_checksum = package.checksum.len() == 64
        && package
            .checksum
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    anyhow::ensure!(valid_name, "非法 crate 名称：{}", package.name);
    anyhow::ensure!(valid_version, "非法 crate 版本：{}", package.version);
    anyhow::ensure!(valid_checksum, "非法 crate 校验和：{}", package.name);
    Ok(())
}

fn load_crate_archive(
    client: &Client,
    cache_root: &Path,
    package: &LockedCargoPackage,
) -> Result<(Vec<u8>, u64)> {
    let cache_path = cache_root.join(format!("{}.crate", package.checksum));
    if cache_path.exists() {
        let metadata = fs::symlink_metadata(&cache_path)?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "依赖证据缓存不是普通文件：{}",
            cache_path.display()
        );
        let bytes = fs::read(&cache_path)
            .with_context(|| format!("读取依赖证据缓存失败：{}", cache_path.display()))?;
        verify_archive_checksum(package, &bytes)?;
        return Ok((bytes, 0));
    }

    let url = format!(
        "https://static.crates.io/crates/{0}/{0}-{1}.crate",
        package.name, package.version
    );
    let mut response = client
        .get(&url)
        .send()
        .with_context(|| format!("下载 crate 证据失败：{} {}", package.name, package.version))?;
    if response.status() != StatusCode::OK {
        bail!(
            "下载 crate 证据返回 HTTP {}：{} {}",
            response.status(),
            package.name,
            package.version
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ARCHIVE_BYTES)
    {
        bail!(
            "crate 归档超过大小上限：{} {}",
            package.name,
            package.version
        );
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MAX_ARCHIVE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE_BYTES,
        "crate 归档超过大小上限：{} {}",
        package.name,
        package.version
    );
    verify_archive_checksum(package, &bytes)?;
    write_cache_atomically(&cache_path, &bytes)?;
    let downloaded = bytes.len() as u64;
    Ok((bytes, downloaded))
}

fn verify_archive_checksum(package: &LockedCargoPackage, bytes: &[u8]) -> Result<()> {
    let actual = hex_digest(bytes);
    anyhow::ensure!(
        actual == package.checksum,
        "crate 归档校验和不匹配：{} {}",
        package.name,
        package.version
    );
    Ok(())
}

fn write_cache_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("依赖证据缓存路径缺少父目录")?;
    let temporary = parent.join(format!(".download-{}.part", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::rename(&temporary, path) {
            Ok(()) => {}
            Err(error) if path.exists() => {
                let metadata = fs::symlink_metadata(path)?;
                anyhow::ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "并发写入的依赖证据缓存不是普通文件：{}",
                    path.display()
                );
                let existing = fs::read(path)?;
                anyhow::ensure!(
                    hex_digest(&existing) == hex_digest(bytes),
                    "并发写入的依赖证据缓存内容不一致：{}",
                    path.display()
                );
                fs::remove_file(&temporary)?;
                let _ = error;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn scan_crate_archive(
    project: &str,
    package: &LockedCargoPackage,
    archive_bytes: &[u8],
) -> Result<StaticScanReport> {
    let expected_root = format!("{}-{}", package.name, package.version);
    let decoder = GzDecoder::new(Cursor::new(archive_bytes));
    let mut archive = Archive::new(decoder);
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut scanned_files = 0_usize;
    let mut entry_count = 0_usize;
    let mut expanded_bytes = 0_u64;
    let mut saw_manifest = false;
    for entry in archive.entries().context("读取 crate 归档目录失败")? {
        let mut entry = entry.context("读取 crate 归档条目失败")?;
        entry_count += 1;
        anyhow::ensure!(
            entry_count <= MAX_ARCHIVE_ENTRIES,
            "crate 归档条目超过 {} 个：{} {}",
            MAX_ARCHIVE_ENTRIES,
            package.name,
            package.version
        );
        let path = entry
            .path()
            .context("解析 crate 归档路径失败")?
            .into_owned();
        validate_archive_path(&path, &expected_root)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            continue;
        }
        anyhow::ensure!(
            entry_type.is_file(),
            "crate 归档包含非普通文件条目：{}",
            path.display()
        );
        let size = entry.header().size()?;
        expanded_bytes = expanded_bytes.saturating_add(size);
        anyhow::ensure!(
            expanded_bytes <= MAX_ARCHIVE_EXPANDED_BYTES,
            "crate 归档展开大小超过上限：{} {}",
            package.name,
            package.version
        );
        let file_name = path.file_name().and_then(|name| name.to_str());
        if !matches!(file_name, Some("Cargo.toml") | Some("build.rs")) {
            continue;
        }
        anyhow::ensure!(
            size <= MAX_ARCHIVE_FILE_BYTES,
            "crate 静态审计文件超过大小上限：{}",
            path.display()
        );
        let mut bytes = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut bytes)?;
        let raw = std::str::from_utf8(&bytes)
            .with_context(|| format!("crate 静态审计文件不是 UTF-8：{}", path.display()))?;
        let display_path = format!(
            "crate:{}@{}/{}",
            package.name,
            package.version,
            path.display()
        );
        match file_name {
            Some("Cargo.toml") => {
                saw_manifest = true;
                inspect_cargo_manifest(&display_path, raw, &mut blockers)?;
            }
            Some("build.rs") => {
                inspect_build_script(&display_path, raw, &mut blockers, &mut warnings)
            }
            _ => {}
        }
        scanned_files += 1;
    }
    anyhow::ensure!(
        saw_manifest,
        "crate 归档缺少 Cargo.toml：{} {}",
        package.name,
        package.version
    );
    Ok(finalize_static_report(
        project,
        format!("crate:{}@{}", package.name, package.version),
        scanned_files,
        blockers,
        warnings,
    ))
}

pub(super) fn validate_archive_path(path: &Path, expected_root: &str) -> Result<()> {
    anyhow::ensure!(
        !path.is_absolute(),
        "crate 归档包含绝对路径：{}",
        path.display()
    );
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(root)) if root == expected_root => {}
        _ => bail!("crate 归档根目录异常：{}", path.display()),
    }
    anyhow::ensure!(
        components.all(|component| matches!(component, Component::Normal(_))),
        "crate 归档包含越界路径：{}",
        path.display()
    );
    Ok(())
}

pub(super) fn hex_digest(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

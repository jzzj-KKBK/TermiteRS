//! Cargo 锁文件依赖图解析。
//!
//! 本模块只读取 `Cargo.lock`，不会调用 Cargo、构建脚本或项目代码。

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::Path,
};

use anyhow::{Context, Result};

use super::super::{CargoPackageCoordinate, CargoReachabilitySnapshot};
use super::MAX_LOCKED_PACKAGES;

#[derive(Debug)]
struct LockGraphNode {
    name: String,
    version: String,
    source: String,
    dependencies: Vec<String>,
}

/// 从 Cargo.lock 直接计算工作区本地包到锁定包的保守依赖闭包，全程不调用 Cargo 或构建脚本。
pub fn cargo_reachability_snapshot(
    project_root: impl AsRef<Path>,
) -> Result<Option<CargoReachabilitySnapshot>> {
    let lock_path = project_root.as_ref().join("Cargo.lock");
    if !lock_path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&lock_path)
        .with_context(|| format!("读取 Cargo.lock 失败：{}", lock_path.display()))?;
    let document: toml::Value = raw
        .parse()
        .with_context(|| format!("解析 Cargo.lock 失败：{}", lock_path.display()))?;
    let mut nodes = Vec::new();
    for package in document
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        nodes.push(LockGraphNode {
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
            source: package
                .get("source")
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_string(),
            dependencies: package
                .get("dependencies")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
        });
    }
    anyhow::ensure!(
        nodes.len() <= MAX_LOCKED_PACKAGES,
        "Cargo.lock 包数量超过依赖图上限"
    );
    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, node) in nodes.iter().enumerate() {
        by_name.entry(&node.name).or_default().push(index);
    }
    let roots = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.source.is_empty())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    anyhow::ensure!(!roots.is_empty(), "Cargo.lock 中没有可识别的本地根包");
    let mut queue = VecDeque::from(roots.clone());
    let mut reachable = HashSet::new();
    let mut ambiguous_edges = Vec::new();
    while let Some(index) = queue.pop_front() {
        if !reachable.insert(index) {
            continue;
        }
        for dependency in &nodes[index].dependencies {
            let (name, version) = parse_lock_dependency(dependency);
            let Some(candidates) = by_name.get(name) else {
                ambiguous_edges.push(format!("{} -> {} (missing)", nodes[index].name, dependency));
                continue;
            };
            let matched = candidates
                .iter()
                .copied()
                .filter(|candidate| {
                    version.is_none_or(|version| nodes[*candidate].version == version)
                })
                .collect::<Vec<_>>();
            if matched.len() != 1 {
                ambiguous_edges.push(format!("{} -> {}", nodes[index].name, dependency));
            }
            for candidate in matched {
                queue.push_back(candidate);
            }
        }
    }
    let mut root_names = roots
        .iter()
        .map(|index| format!("{} {}", nodes[*index].name, nodes[*index].version))
        .collect::<Vec<_>>();
    root_names.sort();
    let mut reachable_packages = reachable
        .into_iter()
        .map(|index| CargoPackageCoordinate {
            name: nodes[index].name.clone(),
            version: nodes[index].version.clone(),
            source: if nodes[index].source.is_empty() {
                "workspace".to_string()
            } else {
                nodes[index].source.clone()
            },
        })
        .collect::<Vec<_>>();
    reachable_packages.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    ambiguous_edges.sort();
    ambiguous_edges.dedup();
    Ok(Some(CargoReachabilitySnapshot {
        roots: root_names,
        reachable_packages,
        ambiguous_edges,
    }))
}

fn parse_lock_dependency(dependency: &str) -> (&str, Option<&str>) {
    let coordinate = dependency.split(" (").next().unwrap_or(dependency);
    let mut parts = coordinate.split_whitespace();
    let name = parts.next().unwrap_or("");
    let version = parts
        .next()
        .filter(|value| value.as_bytes().first().is_some_and(u8::is_ascii_digit));
    (name, version)
}

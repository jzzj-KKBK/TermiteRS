//! Rust 依赖安全取证入口。
//!
//! 依赖图解析与归档扫描保持独立，便于分别审计“是否可达”和“代码是否危险”。

mod archive;
mod graph;

#[cfg(test)]
mod tests;

pub use archive::scan_locked_cargo_dependencies;
pub use graph::cargo_reachability_snapshot;

const MAX_LOCKED_PACKAGES: usize = 2_048;

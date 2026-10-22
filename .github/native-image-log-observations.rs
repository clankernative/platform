#![forbid(unsafe_code)]
use std::{collections::BTreeSet, fs, io::Read, path::Path};

const MARKERS: &[(&str, &str)] = &[
    ("Bazel build failed: primary=", "bazel_command_failed"),
    ("primary=exit, code=Some(1)", "reported_bazel_exit1"),
    ("native_link_failed", "reported_native_link_failure"),
    ("link_library_not_found", "reported_missing_link_library"),
    ("rust_missing_crate", "reported_missing_rust_crate"),
    ("rust_unresolved_import", "reported_unresolved_import"),
    (
        "offline_download_refused",
        "reported_offline_dependency_refusal",
    ),
    ("module_lock_changed", "reported_module_lock_change"),
    ("missing_path", "reported_missing_path"),
    ("os_access_refused", "reported_access_refusal"),
    ("read_only_output", "reported_readonly_output"),
    (
        "artifact admission worker start",
        "artifact_worker_start_failed",
    ),
    (
        "current worker supervisor executable is unavailable",
        "supervisor_path_unavailable",
    ),
    ("trusted worker launcher missing", "worker_launcher_missing"),
    ("spawn isolated Roc worker", "worker_spawn_failed"),
    (
        "No such file or directory (os error 2)",
        "reported_missing_filesystem_entry",
    ),
    (
        "Text file busy (os error 26)",
        "reported_executable_text_busy",
    ),
    (
        "failed to exchange app-contract",
        "app_contract_exchange_failed",
    ),
    ("command deadline exceeded", "reported_command_deadline"),
    ("source byte pin", "reported_source_pin_refusal"),
];

fn main() -> std::io::Result<()> {
    let root = Path::new("artifacts/bazel-native-images/artifacts/failed-operations");
    let mut markers = BTreeSet::new();
    let mut seen = 0usize;
    let mut complete = true;
    if root.try_exists()? {
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            complete = false;
        } else {
            for entry in fs::read_dir(root)?.take(33) {
                let entry = entry?;
                seen += 1;
                if seen > 32 {
                    complete = false;
                    break;
                }
                let metadata = entry.file_type()?;
                if !metadata.is_dir() || metadata.is_symlink() {
                    complete = false;
                    continue;
                }
                let log = entry.path().join("build.log");
                if !log.try_exists()? {
                    continue;
                }
                let metadata = fs::symlink_metadata(&log)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    complete = false;
                    continue;
                }
                let mut bytes = Vec::new();
                fs::File::open(&log)?
                    .take(8 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 8 * 1024 * 1024 {
                    complete = false;
                    bytes.truncate(8 * 1024 * 1024);
                }
                let text = String::from_utf8_lossy(&bytes);
                for (needle, label) in MARKERS {
                    if text.contains(needle) {
                        markers.insert(*label);
                    }
                }
            }
        }
    } else {
        complete = false;
    }
    // Only compile-time vocabulary and counts leave the protected log directory.
    // Markers are advisory observations, never original kill/causal attribution.
    let markers = markers.into_iter().collect::<Vec<_>>();
    println!(
        "{{\"entries_seen\":{seen},\"capture_complete\":{complete},\"fixed_observations\":{markers:?},\"cause_attribution\":false}}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_observations_exclude_raw_source_environment_and_path_values() {
        let private = "PRIVATE-SDK PRIVATE-PROVIDER PRIVATE-ENV /private/secret";
        let input =
            format!("{private} Bazel build failed: primary=exit, code=Some(1) native_link_failed");
        let result = MARKERS
            .iter()
            .filter_map(|(needle, label)| input.contains(needle).then_some(*label))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            result,
            BTreeSet::from([
                "bazel_command_failed",
                "reported_bazel_exit1",
                "reported_native_link_failure"
            ])
        );
        assert!(!format!("{result:?}").contains("PRIVATE"));
        assert!(!format!("{result:?}").contains("/private"));
        assert!(MARKERS.iter().all(|(needle, _)| !private.contains(needle)));
    }
}

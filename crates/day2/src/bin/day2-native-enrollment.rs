//! Fixed node provisioner / private child issuer. No caller paths, PIDs, keys,
//! runtime methods or callbacks are accepted at this executable boundary.
#![forbid(unsafe_code)]

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let issuer = match arguments.as_slice() {
        [] => false,
        [mode] if mode == "issuer" => true,
        _ => {
            eprintln!("day2-native-enrollment refused");
            std::process::exit(1);
        }
    };
    if let Err(error) = day2::deployment::run_native_enrollment(issuer) {
        eprintln!(
            "day2-native-enrollment refused or stopped [{}]",
            refusal_category(&error)
        );
        std::process::exit(1);
    }
}

/// Emit only literal categories, never error text or data from a provider,
/// policy, protocol message or credential projection.
fn refusal_category(error: &anyhow::Error) -> String {
    const CATEGORIES: &[(&str, &str)] = &[
        ("native_enrollment_runner", "runner"),
        ("Roc workflow sources changed", "workflow_sources"),
        ("Roc workflow compiler changed", "workflow_toolchain"),
        ("Roc workflow executable changed", "workflow_executable"),
        ("Roc workflow stalled", "workflow_stalled"),
        ("workflow process failed", "workflow_process"),
        ("native_enrollment_original_clock", "clock"),
        ("native_enrollment_policy", "policy"),
        ("native_enrollment_provisioner_self", "self"),
        ("native_enrollment_node_init", "node_init"),
        ("native_enrollment_root_client", "root_client"),
        ("native_enrollment_socket_directory", "directory"),
        ("native_enrollment_storage_directory", "storage_directory"),
        ("native_enrollment_listener", "listener"),
        ("native_enrollment_startup_channel", "startup_channel"),
        ("native_enrollment_child_spawn", "child_spawn"),
        ("native_enrollment_birth_grant", "birth_grant"),
        ("native_enrollment_issuer", "issuer"),
        ("native_enrollment_kms_version", "kms_version"),
        ("native_enrollment_kms_public", "kms_public"),
        ("native_enrollment_kms_sign", "kms_sign"),
        ("native_enrollment_kms_status", "kms_status"),
        ("native_enrollment_kms_transport", "kms_transport"),
        ("epoch_native_metadata", "metadata"),
        ("Permission denied", "permission_denied"),
        ("Operation not permitted", "operation_not_permitted"),
        ("No such file", "missing_file"),
        ("File exists", "already_exists"),
        ("Invalid argument", "invalid_argument"),
        ("native_acquisition_expired", "expired"),
        (
            "native_enrollment_socket_closed_or_timeout",
            "socket_closed_or_timeout",
        ),
    ];
    let mut labels = Vec::new();
    for cause in error.chain() {
        let message = cause.to_string();
        for &(needle, label) in CATEGORIES {
            if message.contains(needle) && !labels.contains(&label) && labels.len() < 8 {
                labels.push(label);
            }
        }
    }
    if labels.is_empty() {
        "unclassified".into()
    } else {
        labels.join(",")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn startup_categories_never_include_error_or_secret_contents() {
        let error =
            anyhow::anyhow!("Permission denied: bearer-secret native_enrollment_arbitrary_secret")
                .context("native_enrollment_policy");
        assert_eq!(super::refusal_category(&error), "policy,permission_denied");
        assert_eq!(
            super::refusal_category(&anyhow::anyhow!("bearer-secret")),
            "unclassified"
        );
    }
}

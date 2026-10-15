//! Host-owned Linux pure-worker confinement. No application-selectable policies.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerCache {
    General,
    SchemaGlue,
    RustGlue,
}

impl CompilerCache {
    pub fn name(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::SchemaGlue => "schema-glue",
            Self::RustGlue => "rust-glue",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "general" => Some(Self::General),
            "schema-glue" => Some(Self::SchemaGlue),
            "rust-glue" => Some(Self::RustGlue),
            _ => None,
        }
    }

    pub fn directory(self) -> &'static str {
        match self {
            Self::General => "cache",
            Self::SchemaGlue => "cache/schema-glue",
            Self::RustGlue => "cache/rust-glue",
        }
    }
}

pub const QUALIFIED: &[u8] = b"day2-linux-sandbox-v1:qualified";
pub const ADDRESS_SPACE_BYTES: u64 = 256 * 1024 * 1024;
pub const CPU_SECONDS: u64 = 5;
pub const QUALIFIED_ADDRESS_SPACE_BYTES: u64 = 512 * 1024 * 1024;
pub const QUALIFIED_CPU_SECONDS: u64 = 30;
pub const OPEN_FILES: u64 = 32;

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchProfile {
    Ordinary,
    QualifiedProperty,
}

#[cfg(any(target_os = "linux", test))]
impl LaunchProfile {
    pub(crate) const fn worker_argument(self) -> Option<&'static str> {
        match self {
            Self::Ordinary => None,
            Self::QualifiedProperty => Some("--day2-qualified-property-v1"),
        }
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn profile_for_limits(
    memory_bytes: u64,
    cpu_seconds: u64,
) -> anyhow::Result<LaunchProfile> {
    match (memory_bytes, cpu_seconds) {
        (ADDRESS_SPACE_BYTES, CPU_SECONDS) => Ok(LaunchProfile::Ordinary),
        (QUALIFIED_ADDRESS_SPACE_BYTES, QUALIFIED_CPU_SECONDS) => {
            Ok(LaunchProfile::QualifiedProperty)
        }
        _ => anyhow::bail!("unreviewed worker resource profile"),
    }
}

#[cfg(target_os = "linux")]
pub use linux::launch;

#[cfg(not(target_os = "linux"))]
pub fn launch(
    _worker: &std::path::Path,
    _parent: u32,
    _memory_bytes: u64,
    _cpu_seconds: u64,
) -> anyhow::Result<()> {
    anyhow::bail!("day2-sandbox requires Linux with enforced Landlock and seccomp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_scopes_are_closed_owned_paths() {
        for scope in [
            CompilerCache::General,
            CompilerCache::SchemaGlue,
            CompilerCache::RustGlue,
        ] {
            assert_eq!(CompilerCache::parse(scope.name()), Some(scope));
            assert!(scope.directory().starts_with("cache"));
        }
        assert_ne!(
            CompilerCache::SchemaGlue.directory(),
            CompilerCache::RustGlue.directory()
        );
        for invalid in ["", "../", "/tmp", "schema-glue/.."] {
            assert_eq!(CompilerCache::parse(invalid), None);
        }
    }

    #[test]
    fn permits_only_reviewed_resource_pairs_and_selects_native_argument() {
        assert_eq!(
            profile_for_limits(ADDRESS_SPACE_BYTES, CPU_SECONDS).unwrap(),
            LaunchProfile::Ordinary
        );
        assert_eq!(LaunchProfile::Ordinary.worker_argument(), None);
        assert_eq!(
            profile_for_limits(QUALIFIED_ADDRESS_SPACE_BYTES, QUALIFIED_CPU_SECONDS).unwrap(),
            LaunchProfile::QualifiedProperty
        );
        assert_eq!(
            LaunchProfile::QualifiedProperty.worker_argument(),
            Some("--day2-qualified-property-v1")
        );
        for pair in [
            (ADDRESS_SPACE_BYTES, QUALIFIED_CPU_SECONDS),
            (QUALIFIED_ADDRESS_SPACE_BYTES, CPU_SECONDS),
            (ADDRESS_SPACE_BYTES + 1, CPU_SECONDS),
            (0, 0),
        ] {
            assert!(profile_for_limits(pair.0, pair.1).is_err());
        }
    }
}

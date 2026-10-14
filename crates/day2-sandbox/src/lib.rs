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
pub const OPEN_FILES: u64 = 32;

#[cfg(target_os = "linux")]
pub use linux::launch;

#[cfg(not(target_os = "linux"))]
pub fn launch(_worker: &std::path::Path, _parent: u32) -> anyhow::Result<()> {
    anyhow::bail!("day2-sandbox requires Linux with enforced Landlock and seccomp")
}

#[cfg(test)]
mod compiler_cache_tests {
    use super::CompilerCache;

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
}

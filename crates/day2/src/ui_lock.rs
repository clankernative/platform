//! Pure authored UI lock contract shared by admission and the offline builder.
use anyhow::{Context, Result, ensure};
use ring::digest::{Context as DigestContext, SHA256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

const MAX_INPUTS: usize = 4096;
const MAX_FILE: usize = 1_048_576;
const MAX_TOTAL: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lock {
    pub schema_version: u32,
    pub provider: String,
    pub package: LockedPackage,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub digest: String,
    pub inputs: Vec<Input>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    pub path: String,
    pub digest: String,
    pub bytes: usize,
}

pub fn validate(lock: &Lock) -> Result<()> {
    ensure!(
        lock.schema_version == 2
            && !lock.provider.is_empty()
            && lock.provider.len() <= 128
            && lock
                .provider
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            && !lock.package.name.trim().is_empty()
            && !lock.package.version.trim().is_empty(),
        "unsupported UI lock"
    );
    ensure!(
        valid_digest(&lock.package.digest),
        "invalid package digest in lock"
    );
    ensure!(
        manifest_digest(&lock.package.inputs)? == lock.package.digest,
        "locked input manifest digest mismatch"
    );
    Ok(())
}

pub fn safe_rel(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
}

pub fn valid_digest(digest: &str) -> bool {
    digest.len() == 71
        && digest.starts_with("sha256:")
        && digest[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Identity of the complete, sorted, bounded input closure. Order is not authority.
pub fn manifest_digest(inputs: &[Input]) -> Result<String> {
    ensure!(
        !inputs.is_empty() && inputs.len() <= MAX_INPUTS,
        "locked input count budget"
    );
    let mut sorted = inputs.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    let mut digest = DigestContext::new(&SHA256);
    for input in sorted {
        ensure!(
            safe_rel(&input.path)
                && input.path.len() <= 512
                && input.path.split('/').count() <= 8
                && input.bytes <= MAX_FILE
                && valid_digest(&input.digest),
            "invalid locked input"
        );
        ensure!(
            names.insert(input.path.to_ascii_lowercase()),
            "duplicate/case-colliding locked input"
        );
        total = total
            .checked_add(input.bytes)
            .context("locked byte count overflow")?;
        ensure!(total <= MAX_TOTAL, "locked package byte budget");
        digest.update(input.path.as_bytes());
        digest.update(&[0]);
        digest.update(input.bytes.to_string().as_bytes());
        digest.update(&[0]);
        digest.update(input.digest.as_bytes());
        digest.update(b"\n");
    }
    Ok(format!("sha256:{}", crate::hex(digest.finish().as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn input(path: &str) -> Input {
        Input {
            path: path.into(),
            bytes: 4,
            digest: crate::digest(b"html"),
        }
    }

    #[test]
    fn manifest_digest_preserves_input_framing() {
        assert_eq!(
            manifest_digest(&[input("file")]).unwrap(),
            "sha256:48ac86795abf7f9d52a1a4e682c1db018da2249febc34a8617287a24b2d8c643"
        );
    }

    #[test]
    fn malformed_closures_are_rejected_before_effects() {
        for path in ["../escape", "assets/foo:bar", "a//b", "./file", "/absolute"] {
            assert!(manifest_digest(&[input(path)]).is_err());
        }
        assert!(manifest_digest(&[input("File"), input("file")]).is_err());
        let mut lock = Lock {
            schema_version: 2,
            provider: "clanker-ui.native".into(),
            package: LockedPackage {
                name: "@clanker/vanilla".into(),
                version: "0.7.0".into(),
                digest: manifest_digest(&[input("file")]).unwrap(),
                inputs: vec![input("file")],
            },
        };
        validate(&lock).unwrap();
        lock.package.inputs[0].bytes += 1;
        assert!(validate(&lock).is_err());
    }

    proptest! {
        #[test]
        fn closure_identity_is_order_independent_and_binds_every_input(bytes in 0usize..MAX_FILE) {
            let mut a = input("a");
            a.bytes = bytes;
            let b = input("b");
            let expected = manifest_digest(&[a.clone(), b.clone()]).unwrap();
            prop_assert_eq!(&expected, &manifest_digest(&[b.clone(), a.clone()]).unwrap());
            a.digest = crate::digest(b"changed");
            prop_assert_ne!(&expected, &manifest_digest(&[a, b]).unwrap());
        }
    }
}

//! Optional immutable release inputs. Every caller still verifies its source pin.
use anyhow::{Context, Result, ensure};
use std::{fs, io::Read, path::Path};

pub(crate) fn cached(root: &Path, digest: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "source-owned release digest required"
    );
    let path = root.join(".cache/day2-release").join(digest);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "regular bounded release archive required"
    );
    let mut bytes = Vec::new();
    let mut input = fs::File::open(&path)?
        .take(limit.checked_add(1).context("release byte limit overflow")?);
    input.read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "release archive byte limit");
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_inputs_are_misses_but_malformed_or_oversized_inputs_refuse() -> Result<()> {
        let root = tempfile::tempdir()?;
        let digest = "a".repeat(64);
        assert!(cached(root.path(), &digest, 3)?.is_none());
        assert!(cached(root.path(), "../other", 3).is_err());
        let directory = root.path().join(".cache/day2-release");
        fs::create_dir_all(&directory)?;
        let path = directory.join(&digest);
        fs::write(&path, b"abc")?;
        assert_eq!(cached(root.path(), &digest, 3)?, Some(b"abc".to_vec()));
        assert!(cached(root.path(), &digest, 2).is_err());
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        assert!(cached(root.path(), &digest, 3).is_err());
        #[cfg(unix)]
        {
            fs::remove_dir(&path)?;
            let other = root.path().join("other");
            fs::write(&other, b"abc")?;
            std::os::unix::fs::symlink(&other, &path)?;
            assert!(cached(root.path(), &digest, 3).is_err());
        }
        Ok(())
    }
}

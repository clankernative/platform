use anyhow::{Result, ensure};

pub fn identifier(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 48,
        "invalid identifier length"
    );
    ensure!(
        name.as_bytes()[0].is_ascii_lowercase(),
        "identifier must start with a-z: {name}"
    );
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "invalid identifier: {name}"
    );
    ensure!(
        !name.starts_with("day2_") && !name.starts_with("sqlite_"),
        "reserved identifier: {name}"
    );
    Ok(())
}

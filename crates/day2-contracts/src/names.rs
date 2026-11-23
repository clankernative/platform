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

/// An instance app ID, exactly as `cli/Names.roc` admits it: 2-20 lowercase letters or digits starting
/// with a letter, so one string is a repository, DNS label, namespace suffix and bucket component.
/// The platform's own names in those positions start with day2, and the shared state bucket is
/// `<project>-tofu-state`, so no app ID may start with day2 or be tofu.
pub fn app_id(name: &str) -> Result<()> {
    ensure!(
        (2..=20).contains(&name.len())
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "app id {name:?} must be 2-20 lowercase letters or digits starting with a letter"
    );
    ensure!(
        !name.starts_with("day2") && name != "tofu",
        "reserved app id: {name}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn app_ids_match_the_instance_spec() {
        for name in ["go", "home", "inyourface", "a1", "instance", "dayii"] {
            super::app_id(name).unwrap();
        }
        for name in [
            "",
            "g",
            "golinks-v2",
            "go_links",
            "Home",
            "1app",
            "day2",
            "day2ci",
            "tofu",
            "abcdefghijklmnopqrstu",
        ] {
            assert!(super::app_id(name).is_err(), "{name}");
        }
    }
}

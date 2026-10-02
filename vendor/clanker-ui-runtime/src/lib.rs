//! Canonical, pure runtime value guards shared by Native UI hosts.
use anyhow::{ensure, Result};
use minijinja::Value;
use std::cmp::Ordering;
use unicode_segmentation::UnicodeSegmentation;

/// A persistent record key, never an expression or an HTML fragment.
pub fn token(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "cui_token_requires_bounded_ascii_key"
    );
    Ok(value.to_owned())
}

/// Closed ordinal styles; never return caller-provided class or markup text.
pub fn button_variant(value: &Value) -> Result<&'static str> {
    ensure!(
        value.kind() == minijinja::value::ValueKind::Number
            && value.to_string().bytes().all(|byte| byte.is_ascii_digit()),
        "cui_button_variant_requires_integer"
    );
    match value.as_i64() {
        Some(0) => Ok("primary"),
        Some(1) => Ok("secondary"),
        Some(2) => Ok("quiet"),
        Some(3) => Ok("danger"),
        _ => anyhow::bail!("cui_button_variant_out_of_range"),
    }
}

pub fn button_size(value: &Value) -> Result<&'static str> {
    ensure!(
        value.kind() == minijinja::value::ValueKind::Number
            && value.to_string().bytes().all(|byte| byte.is_ascii_digit()),
        "cui_button_size_requires_integer"
    );
    match value.as_i64() {
        Some(0) => Ok("cui-button--compact"),
        Some(1) => Ok(""),
        _ => anyhow::bail!("cui_button_size_out_of_range"),
    }
}

#[derive(Debug)]
pub struct ImageSource(pub String);
impl minijinja::value::Object for ImageSource {}

pub fn text(value: &str) -> Result<String> {
    ensure!(!value.trim().is_empty(), "cui_text_requires_nonblank_text");
    ensure!(
        !value.chars().any(char::is_control),
        "cui_text_control_character"
    );
    Ok(value.to_owned())
}

pub fn plain(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "cui_plain_control_character"
    );
    Ok(value.to_owned())
}

pub fn field_text(value: &str) -> Result<String> {
    ensure!(
        !value.trim().is_empty(),
        "cui_field_text_requires_nonblank_text"
    );
    ensure!(
        !value
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t')),
        "cui_field_text_control_character"
    );
    Ok(value.to_owned())
}

pub fn initials(value: &str) -> Result<String> {
    text(value)?;
    let result = value.graphemes(true).take(4).collect::<Vec<_>>();
    ensure!(
        (1..=3).contains(&result.len()),
        "cui_initials_grapheme_count"
    );
    Ok(result.concat())
}

#[derive(Clone, Copy)]
enum Number {
    Integer(u128),
    Real(f64),
}

impl Number {
    fn parse(value: &str) -> Result<Self> {
        if let Ok(integer) = value.parse::<u128>() {
            return Ok(Self::Integer(integer));
        }
        let number: f64 = value.parse()?;
        ensure!(number.is_finite(), "cui_progress_finite_number_required");
        Ok(Self::Real(number))
    }

    fn from_value(value: &Value) -> Result<Self> {
        ensure!(
            matches!(
                value.kind(),
                minijinja::value::ValueKind::Number | minijinja::value::ValueKind::String
            ),
            "cui_progress_number_required"
        );
        Self::parse(value.as_str().unwrap_or(&value.to_string()))
    }

    fn compare(self, other: Self) -> Ordering {
        // Never round an integer field into f64: that could admit an over-limit
        // value or falsely report completion above 2^53.
        fn mixed(integer: u128, real: f64) -> Ordering {
            if real < 0.0 {
                return Ordering::Greater;
            }
            if real >= u128::MAX as f64 {
                return Ordering::Less;
            }
            let integral = real as u128;
            match integer.cmp(&integral) {
                Ordering::Equal if real.fract() > 0.0 => Ordering::Less,
                order => order,
            }
        }
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => a.cmp(&b),
            (Self::Integer(a), Self::Real(b)) => mixed(a, b),
            (Self::Real(a), Self::Integer(b)) => mixed(b, a).reverse(),
            (Self::Real(a), Self::Real(b)) => a.partial_cmp(&b).expect("validated finite numbers"),
        }
    }

    fn text(self) -> String {
        match self {
            Self::Integer(value) => value.to_string(),
            Self::Real(value) => value.to_string(),
        }
    }
}

pub fn numeric_literal(value: &str) -> bool {
    Number::parse(value).is_ok()
}

fn progress(value: &Value, maximum: &Value) -> Result<(Number, Number)> {
    let value = Number::from_value(value)?;
    let maximum = Number::from_value(maximum)?;
    ensure!(
        maximum.compare(Number::Integer(0)) == Ordering::Greater
            && value.compare(Number::Integer(0)) != Ordering::Less
            && value.compare(maximum) != Ordering::Greater,
        "cui_progress_out_of_range"
    );
    Ok((value, maximum))
}

pub fn progress_value(value: &Value, maximum: &Value) -> Result<String> {
    let (value, _) = progress(value, maximum)?;
    Ok(value.text())
}

pub fn progress_maximum(value: &Value, maximum: &Value) -> Result<String> {
    let (_, maximum) = progress(value, maximum)?;
    Ok(maximum.text())
}

pub fn progress_complete(value: &Value, maximum: &Value) -> Result<bool> {
    let (value, maximum) = progress(value, maximum)?;
    Ok(value.compare(maximum) == Ordering::Equal)
}

pub fn validate_remote_image_source(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 4096
            && value == value.trim()
            && !value.chars().any(|c| c.is_control() || c == '\\'),
        "cui_image_invalid_url"
    );
    let parsed = url::Url::parse(value)?;
    ensure!(
        parsed.scheme() == "https" && parsed.host_str().is_some_and(|host| !host.contains('*')),
        "cui_image_https_required"
    );
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "cui_image_credentials_forbidden"
    );
    Ok(())
}

pub fn image(value: &str) -> Result<ImageSource> {
    validate_remote_image_source(value)?;
    let parsed = url::Url::parse(value)?;
    Ok(ImageSource(parsed.to_string()))
}

fn template_error(error: impl std::fmt::Display) -> minijinja::Error {
    minijinja::Error::new(minijinja::ErrorKind::InvalidOperation, error.to_string())
}

/// Register only the canonical value helpers; hosts retain asset and rendering policy.
pub fn install(environment: &mut minijinja::Environment<'_>) {
    environment.add_function("cui_button_variant", |value: Value| {
        button_variant(&value).map_err(template_error)
    });
    environment.add_function("cui_button_size", |value: Value| {
        button_size(&value).map_err(template_error)
    });
    environment.add_function("cui_token", |value: Value| {
        token(&value.to_string()).map_err(template_error)
    });
    environment.add_function("cui_text", |value: Value| {
        text(&value.to_string()).map_err(template_error)
    });
    environment.add_function("cui_initials", |value: String| {
        initials(&value).map_err(template_error)
    });
    environment.add_function("cui_plain", |value: String| {
        plain(&value).map_err(template_error)
    });
    environment.add_function("cui_field_text", |value: String| {
        field_text(&value).map_err(template_error)
    });
    environment.add_function("cui_progress_value", |value: Value, maximum: Value| {
        progress_value(&value, &maximum).map_err(template_error)
    });
    environment.add_function("cui_progress_maximum", |value: Value, maximum: Value| {
        progress_maximum(&value, &maximum).map_err(template_error)
    });
    environment.add_function("cui_progress_complete", |value: Value, maximum: Value| {
        progress_complete(&value, &maximum).map_err(template_error)
    });
    environment.add_function("cui_image", |value: String| {
        image(&value)
            .map(minijinja::Value::from_object)
            .map_err(template_error)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_preserves_integers_above_f64_precision() {
        let value = Value::from("9007199254740993");
        let maximum = Value::from("9007199254740994");
        assert_eq!(
            progress_value(&value, &maximum).unwrap(),
            "9007199254740993"
        );
        assert_eq!(
            progress_maximum(&value, &maximum).unwrap(),
            "9007199254740994"
        );
        assert!(!progress_complete(&value, &maximum).unwrap());
        assert!(progress(&Value::from(2), &Value::from("1.5")).is_err());
        assert!(progress(&Value::from("NaN"), &Value::from(1)).is_err());
        assert!(progress(
            &Value::from("9007199254740993"),
            &Value::from("9007199254740992.0")
        )
        .is_err());
    }

    #[test]
    fn enum_text_and_image_guards_remain_closed() {
        assert_eq!(button_variant(&Value::from(0)).unwrap(), "primary");
        assert!(button_variant(&Value::from(u64::MAX)).is_err());
        assert!(button_variant(&Value::from(1.0)).is_err());
        assert_eq!(text("hello").unwrap(), "hello");
        assert!(text(" \n").is_err());
        assert_eq!(plain("").unwrap(), "");
        assert!(plain("x\n").is_err());
        assert_eq!(field_text("a\nb").unwrap(), "a\nb");
        assert!(field_text(" \n\t").is_err());
        assert_eq!(
            image("https://cdn.example.test/a.png").unwrap().0,
            "https://cdn.example.test/a.png"
        );
        for invalid in [
            "http://cdn.example.test/a",
            "https://u:p@cdn.example.test/a",
            " https://cdn.example.test/a",
            "https://x.test/a\\b",
        ] {
            assert!(image(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn install_registers_canonical_helpers() {
        let mut environment = minijinja::Environment::empty();
        install(&mut environment);
        assert_eq!(
            environment
                .render_str("{{ cui_progress_value(1, 2) }}", ())
                .unwrap(),
            "1"
        );
        assert!(environment
            .render_str("{{ cui_button_variant(4) }}", ())
            .is_err());
    }
}

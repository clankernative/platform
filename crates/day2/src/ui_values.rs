//! Generic, host-owned value and presentation checks for admitted templates.
use anyhow::{Context, Result, ensure};
use minijinja::Value;
use std::collections::BTreeSet;
use unicode_segmentation::UnicodeSegmentation;

#[derive(Debug)]
pub(crate) struct ImageSource(pub(crate) String);
impl minijinja::value::Object for ImageSource {}

fn rendered(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

pub(crate) fn ui_text(value: &Value, policy: &str, minimum: u64, maximum: u64) -> Result<String> {
    ensure!(
        matches!(policy, "nonblank" | "plain" | "multiline"),
        "ui_text_policy"
    );
    let text = rendered(value);
    ensure!(
        text.chars()
            .all(|c| !c.is_control() || (policy == "multiline" && matches!(c, '\t' | '\r' | '\n'))),
        "ui_text_control_character"
    );
    if policy != "plain" {
        ensure!(!text.trim().is_empty(), "ui_text_blank");
    }
    let count = text.graphemes(true).count() as u64;
    ensure!(count >= minimum, "ui_text_below_minimum_graphemes");
    ensure!(
        maximum == 0 || count <= maximum,
        "ui_text_above_maximum_graphemes"
    );
    Ok(text)
}

pub(crate) fn ui_key(value: &Value) -> Result<String> {
    let key = rendered(value);
    ensure!(
        !key.is_empty()
            && key.len() <= 128
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "ui_key_invalid"
    );
    Ok(key)
}

#[derive(Clone, Debug)]
struct Decimal {
    negative: bool,
    digits: String,
    scale: i32,
}

impl Decimal {
    fn parse(input: &str) -> Result<Self> {
        Self::parse_with_limit(input, 256)
    }
    fn parse_with_limit(input: &str, maximum_length: usize) -> Result<Self> {
        ensure!(
            !input.is_empty() && input.len() <= maximum_length,
            "ui_number_invalid"
        );
        let (mantissa, exponent) =
            if let Some((m, e)) = input.split_once('e').or_else(|| input.split_once('E')) {
                (m, e.parse::<i32>().context("ui_number_invalid")?)
            } else {
                (input, 0)
            };
        ensure!(exponent.unsigned_abs() <= 10_000, "ui_number_invalid");
        let (negative, body) = match input.as_bytes().first() {
            Some(b'-') => (true, &mantissa[1..]),
            Some(b'+') => (false, &mantissa[1..]),
            _ => (false, mantissa),
        };
        let mut split = body.split('.');
        let whole = split.next().unwrap_or_default();
        let fraction = split.next().unwrap_or_default();
        ensure!(
            split.next().is_none()
                && (!whole.is_empty() || !fraction.is_empty())
                && whole.bytes().all(|b| b.is_ascii_digit())
                && fraction.bytes().all(|b| b.is_ascii_digit()),
            "ui_number_invalid"
        );
        let mut digits = format!("{whole}{fraction}");
        let mut scale = i32::try_from(fraction.len())? - exponent;
        while digits.len() > 1 && digits.starts_with('0') {
            digits.remove(0);
        }
        while digits.len() > 1 && digits.ends_with('0') {
            digits.pop();
            scale -= 1;
        }
        if digits.bytes().all(|b| b == b'0') {
            return Ok(Self {
                negative: false,
                digits: "0".into(),
                scale: 0,
            });
        }
        Ok(Self {
            negative,
            digits,
            scale,
        })
    }
    fn canonical(&self) -> String {
        if self.digits == "0" {
            return "0".into();
        }
        let point = self.digits.len() as i64 - i64::from(self.scale);
        let value = if point <= 0 {
            format!("0.{}{}", "0".repeat((-point) as usize), self.digits)
        } else if point >= self.digits.len() as i64 {
            format!(
                "{}{}",
                self.digits,
                "0".repeat((point - self.digits.len() as i64) as usize)
            )
        } else {
            format!(
                "{}.{}",
                &self.digits[..point as usize],
                &self.digits[point as usize..]
            )
        };
        if self.negative {
            format!("-{value}")
        } else {
            value
        }
    }
    fn cmp_abs(&self, other: &Self) -> std::cmp::Ordering {
        if self.digits == "0" || other.digits == "0" {
            return match (self.digits == "0", other.digits == "0") {
                (true, true) => std::cmp::Ordering::Equal,
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                (false, false) => unreachable!(),
            };
        }
        let a = self.digits.len() as i64 - i64::from(self.scale);
        let b = other.digits.len() as i64 - i64::from(other.scale);
        a.cmp(&b).then_with(|| {
            (0..self.digits.len().max(other.digits.len()))
                .map(|i| self.digits.as_bytes().get(i).copied().unwrap_or(b'0'))
                .cmp(
                    (0..self.digits.len().max(other.digits.len()))
                        .map(|i| other.digits.as_bytes().get(i).copied().unwrap_or(b'0')),
                )
        })
    }
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.negative != other.negative {
            return if self.negative {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
        let cmp = self.cmp_abs(other);
        if self.negative { cmp.reverse() } else { cmp }
    }
}
pub(crate) fn valid_number_literal(value: &str) -> bool {
    Decimal::parse(value).is_ok()
}
pub(crate) fn compare_number_literals(left: &str, right: &str) -> Result<i8> {
    Ok(match Decimal::parse(left)?.cmp(&Decimal::parse(right)?) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}
fn decimal_times_small(digits: &str, factor: u8) -> String {
    let mut output = Vec::with_capacity(digits.len() + 4);
    let mut carry = 0u16;
    for digit in digits.bytes().rev() {
        let value = u16::from(digit - b'0') * u16::from(factor) + carry;
        output.push(b'0' + (value % 10) as u8);
        carry = value / 10;
    }
    while carry > 0 {
        output.push(b'0' + (carry % 10) as u8);
        carry /= 10;
    }
    output.reverse();
    String::from_utf8(output).expect("decimal digits are valid UTF-8")
}

// Exact finite decimal representation of the IEEE-754 value, used only for
// ordering. Unlike f64::to_string(), this retains the binary value exactly.
fn exact_float(value: f64) -> Result<Decimal> {
    ensure!(value.is_finite(), "ui_number_invalid");
    if value == 0.0 {
        return Decimal::parse("0");
    }
    let bits = value.abs().to_bits();
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mantissa, exponent) = if exponent_bits == 0 {
        (fraction, -1074)
    } else {
        ((1u64 << 52) | fraction, exponent_bits - 1023 - 52)
    };
    let (mut digits, mut scale) = if exponent >= 0 {
        let mut digits = mantissa.to_string();
        for _ in 0..exponent {
            digits = decimal_times_small(&digits, 2);
        }
        (digits, 0)
    } else {
        let mut digits = mantissa.to_string();
        for _ in 0..-exponent {
            digits = decimal_times_small(&digits, 5);
        }
        (digits, -exponent)
    };
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
        scale -= 1;
    }
    Ok(Decimal {
        negative: value.is_sign_negative(),
        digits,
        scale,
    })
}

#[derive(Clone, Debug)]
struct Number {
    order: Decimal,
    canonical: String,
}
fn number(value: &Value) -> Result<Number> {
    let (order, canonical) = if let Some(text) = value.as_str() {
        let decimal = Decimal::parse(text)?;
        (decimal.clone(), decimal.canonical())
    } else {
        ensure!(
            value.kind() == minijinja::value::ValueKind::Number,
            "ui_number_invalid"
        );
        if value.is_integer() {
            let decimal = Decimal::parse(&value.to_string())?;
            (decimal.clone(), decimal.canonical())
        } else {
            let real = f64::try_from(value.clone()).context("ui_number_invalid")?;
            let order = exact_float(real)?;
            let canonical = Decimal::parse_with_limit(&real.to_string(), 1200)?.canonical();
            (order, canonical)
        }
    };
    Ok(Number { order, canonical })
}
pub(crate) fn ui_compare(left: &Value, right: &Value) -> Result<i64> {
    ensure!(
        left.kind() == minijinja::value::ValueKind::Number
            && right.kind() == minijinja::value::ValueKind::Number,
        "ui_compare_number_required"
    );
    Ok(match number(left)?.order.cmp(&number(right)?.order) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}
pub(crate) fn ui_integer(value: &Value, minimum: &str, maximum: &str) -> Result<String> {
    let raw = value.to_string();
    ensure!(
        value.kind() == minijinja::value::ValueKind::Number && value.is_integer(),
        "ui_integer_number_required"
    );
    let integer = raw;
    let n = Decimal::parse(&integer)?;
    let min = Decimal::parse(minimum)?;
    let max = Decimal::parse(maximum)?;
    ensure!(
        n.scale <= 0 && min.scale <= 0 && max.scale <= 0,
        "ui_integer_integral_required"
    );
    ensure!(
        n.cmp(&min) != std::cmp::Ordering::Less && n.cmp(&max) != std::cmp::Ordering::Greater,
        "ui_integer_out_of_bounds"
    );
    Ok(n.canonical())
}
pub(crate) fn ui_number(
    value: &Value,
    minimum: Option<&str>,
    maximum: Option<&str>,
    exclusive_minimum: bool,
) -> Result<String> {
    let n = number(value)?;
    if let Some(min) = minimum {
        let cmp = n.order.cmp(&Decimal::parse(min)?);
        ensure!(
            if exclusive_minimum {
                cmp == std::cmp::Ordering::Greater
            } else {
                cmp != std::cmp::Ordering::Less
            },
            "ui_number_below_minimum"
        );
    }
    if let Some(max) = maximum {
        ensure!(
            n.order.cmp(&Decimal::parse(max)?) != std::cmp::Ordering::Greater,
            "ui_number_above_maximum"
        );
    }
    Ok(n.canonical)
}
pub(crate) fn ui_image(value: &Value) -> Result<ImageSource> {
    let source = rendered(value);
    validate_remote_image_source(&source)?;
    Ok(ImageSource(source))
}
pub(crate) fn validate_remote_image_source(value: &str) -> Result<()> {
    ensure!(value.len() <= 4096 && !value.is_empty(), "ui_image_length");
    ensure!(
        !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
            && !value.contains('\\'),
        "ui_image_invalid_url"
    );
    let url = url::Url::parse(value).context("ui_image_invalid_url")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "ui_image_https_required"
    );
    ensure!(
        url.host_str()
            .is_some_and(|host| !host.contains('*') && host.len() <= 253),
        "ui_image_host_invalid"
    );
    Ok(())
}
pub(crate) fn remote_image_origins(markup: &str) -> Result<Vec<String>> {
    let html = scraper::Html::parse_fragment(markup);
    let selector = scraper::Selector::parse("img[src]").expect("static selector");
    let mut origins = BTreeSet::new();
    for image in html.select(&selector) {
        let src = image.value().attr("src").expect("selector requires src");
        if src.starts_with("/assets/app/") || src.starts_with("/assets/instance/") {
            continue;
        }
        validate_remote_image_source(src)?;
        origins.insert(url::Url::parse(src)?.origin().ascii_serialization());
        ensure!(origins.len() <= 32, "ui_image_origin_budget");
    }
    Ok(origins.into_iter().collect())
}
pub(crate) fn validate_selects(markup: &str) -> Result<()> {
    if !markup.contains("data-ui-choice-set") {
        return Ok(());
    }
    use scraper::{Html, Selector};
    let html = Html::parse_fragment(markup);
    let roots = Selector::parse("[data-ui-choice-set]").expect("static selector");
    let options = Selector::parse("option").expect("static selector");
    for root in html.select(&roots) {
        ensure!(
            root.value().name() == "select"
                && root.value().attr("data-ui-choice-set") == Some("true"),
            "ui_choice_set_target"
        );
        let choices = root.select(&options).collect::<Vec<_>>();
        ensure!(
            !choices.is_empty() && choices.len() <= 101,
            "ui_choice_budget"
        );
        let mut values = BTreeSet::new();
        let mut selected = 0;
        let mut placeholders = 0;
        let mut enabled = BTreeSet::new();
        for choice in &choices {
            let value = choice
                .value()
                .attr("value")
                .context("ui_choice_value_required")?;
            let label = choice.text().collect::<String>();
            ui_text(&Value::from(label), "nonblank", 0, 0)?;
            ensure!(values.insert(value.to_owned()), "ui_choice_duplicate");
            let placeholder = choice.value().attr("data-ui-placeholder").is_some();
            if placeholder {
                placeholders += 1;
                ensure!(value.is_empty(), "ui_placeholder_value");
            } else {
                ensure!(!value.trim().is_empty(), "ui_choice_blank_value");
            }
            let disabled = choice.value().attr("disabled").is_some()
                || choice
                    .ancestors()
                    .filter_map(scraper::ElementRef::wrap)
                    .any(|node| {
                        node.value().name() == "optgroup" && node.value().attr("disabled").is_some()
                    });
            if !disabled && !placeholder {
                enabled.insert(value.to_owned());
            }
            if choice.value().attr("selected").is_some() {
                selected += 1;
                ensure!(!disabled || placeholder, "ui_choice_selected_disabled");
            }
        }
        ensure!(
            placeholders <= 1 && values.len() - placeholders <= 100,
            "ui_choice_budget"
        );
        ensure!(
            values.len() > placeholders && selected <= 1,
            "ui_choice_selection_invalid"
        );
        if let Some(wanted) = root.value().attr("data-ui-choice-value") {
            ensure!(
                enabled.contains(wanted) || (wanted.is_empty() && placeholders == 1),
                "ui_choice_unknown_or_disabled"
            );
        }
    }
    Ok(())
}
pub(crate) fn validate_navigation(markup: &str) -> Result<()> {
    if !markup.contains("data-ui-navigation") {
        return Ok(());
    }
    use scraper::{Html, Selector};
    let html = Html::parse_fragment(markup);
    let roots = Selector::parse("[data-ui-navigation]").expect("static selector");
    let current = Selector::parse("[aria-current=page]").expect("static selector");
    let items = Selector::parse("li").expect("static selector");
    for root in html.select(&roots) {
        ensure!(
            root.value().attr("data-ui-navigation") == Some("true"),
            "ui_navigation_literal_required"
        );
        let item_nodes = root.select(&items).collect::<Vec<_>>();
        let minimum = root
            .value()
            .attr("data-ui-navigation-minimum-items")
            .context("ui_navigation_minimum_required")?
            .parse::<usize>()?;
        ensure!(item_nodes.len() >= minimum, "ui_navigation_item_minimum");
        let currents = root.select(&current).collect::<Vec<_>>();
        if root.value().attr("data-ui-navigation-current-last") == Some("true") {
            ensure!(
                currents.len() == 1 && currents[0].value().name() != "a",
                "ui_navigation_current_invalid"
            );
            ensure!(
                item_nodes
                    .last()
                    .is_some_and(|last| last.id() == currents[0].id()
                        || last.select(&current).next().is_some()),
                "ui_navigation_current_not_last"
            );
        }
        if root.value().attr("data-ui-navigation-ancestor-links") == Some("true") {
            ensure!(currents.len() == 1, "ui_navigation_current_invalid");
            let links = Selector::parse("a[href]").expect("static selector");
            ensure!(
                item_nodes
                    .iter()
                    .take(item_nodes.len().saturating_sub(1))
                    .all(|item| item.select(&links).count() == 1
                        && item.select(&current).next().is_none()),
                "ui_navigation_ancestor_link_required"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(value: &str) -> Value {
        Value::from(value)
    }
    #[test]
    fn text_policy_counts_graphemes_and_rejects_controls() {
        assert_eq!(
            ui_text(&v("A👩‍🚀e\u{301}"), "nonblank", 3, 3).unwrap(),
            "A👩‍🚀e\u{301}"
        );
        assert!(ui_text(&v("x\n"), "plain", 0, 0).is_err());
        assert!(ui_text(&v(" \t"), "nonblank", 0, 0).is_err());
        assert!(ui_text(&v("\tline\n"), "multiline", 0, 0).is_ok());
    }
    #[test]
    fn generic_key_and_integer_bounds_are_closed() {
        assert_eq!(
            ui_key(&v("task_9007199254740993")).unwrap(),
            "task_9007199254740993"
        );
        assert!(ui_key(&v("a:b")).is_err());
        assert!(ui_key(&v(&"x".repeat(129))).is_err());
        assert_eq!(
            ui_integer(
                &Value::from(9_007_199_254_740_993u64),
                "0",
                "9007199254740994"
            )
            .unwrap(),
            "9007199254740993"
        );
        assert!(ui_integer(&Value::from(1.5), "0", "3").is_err());
        assert!(ui_integer(&Value::from(4), "0", "3").is_err());
    }
    #[test]
    fn decimal_zero_orders_below_positive_subunit_and_above_negative_subunit() {
        assert_eq!(compare_number_literals("0", "0.1").unwrap(), -1);
        assert_eq!(compare_number_literals("0", "-0.1").unwrap(), 1);
        assert_eq!(compare_number_literals("-0.1", "0").unwrap(), -1);
        assert_eq!(compare_number_literals("0", "0.0").unwrap(), 0);
        assert_eq!(
            ui_compare(&Value::from(0), &Value::from(-0.1f64)).unwrap(),
            1
        );
        assert_eq!(
            ui_compare(&Value::from(0), &Value::from(-0.0f64)).unwrap(),
            0
        );
        assert_eq!(
            ui_compare(&Value::from(0), &Value::from(f64::MIN_POSITIVE)).unwrap(),
            -1
        );
        assert_eq!(
            ui_compare(&Value::from(0), &Value::from(f64::from_bits(1))).unwrap(),
            -1
        );
    }

    #[test]
    fn mixed_integer_float_comparisons_use_exact_binary_value() {
        let integer = Value::from(9_223_372_036_854_775_808u64);
        let real = Value::from(9_223_372_036_854_775_808f64);
        assert_eq!(ui_compare(&integer, &real).unwrap(), 0);
        assert_eq!(
            ui_compare(&Value::from(9_223_372_036_854_775_807u64), &real).unwrap(),
            -1
        );
        assert_eq!(
            ui_compare(&Value::from(9_223_372_036_854_775_809u64), &real).unwrap(),
            1
        );
        assert_eq!(
            ui_compare(&Value::from(-1i64), &Value::from(-0.5f64)).unwrap(),
            -1
        );
        assert!(ui_number(&Value::from(f64::NAN), None, None, false).is_err());
        assert!(ui_number(&Value::from(f64::INFINITY), None, None, false).is_err());
        assert!(
            ui_number(
                &Value::from(9_223_372_036_854_775_808f64),
                Some("9223372036854775809"),
                None,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn float_normalization_preserves_decimal_scale() {
        for (real, decimal) in [
            (1.0, "1"),
            (10.0, "10"),
            (1e20, "100000000000000000000"),
            (0.125, "0.125"),
            (-0.5, "-0.5"),
        ] {
            assert!(
                ui_number(&Value::from(real), Some(decimal), Some(decimal), false).is_ok(),
                "{real}: {decimal}"
            );
        }
        assert_eq!(ui_compare(&Value::from(1), &Value::from(1.0)).unwrap(), 0);
        assert_eq!(
            ui_compare(
                &Value::from(f64::MIN_POSITIVE),
                &Value::from(f64::from_bits(1))
            )
            .unwrap(),
            1
        );
    }

    proptest::proptest! {
        #[test]
        fn exactly_representable_integers_compare_equal_to_real(value in -9_007_199_254_740_992i64..=9_007_199_254_740_992i64) {
            proptest::prop_assert_eq!(ui_compare(&Value::from(value), &Value::from(value as f64)).unwrap(), 0);
        }

        #[test]
        fn binary_fractions_match_independent_exact_decimal_bounds(numerator in -1_048_576i32..=1_048_576i32, exponent in 0u32..=20) {
            let real = f64::from(numerator) / f64::from(1u32 << exponent);
            let coefficient = i128::from(numerator) * 5i128.pow(exponent);
            let decimal = format!("{coefficient}e-{exponent}");
            proptest::prop_assert!(ui_number(&Value::from(real), Some(&decimal), Some(&decimal), false).is_ok());
        }
    }

    #[test]
    fn ui_integer_rejects_float_even_when_integral() {
        assert!(ui_integer(&Value::from(1.0), "0", "2").is_err());
        assert_eq!(ui_integer(&Value::from(1), "0", "2").unwrap(), "1");
    }

    #[test]
    fn finite_decimal_compare_and_number_bounds_preserve_large_integer_order() {
        assert_eq!(
            ui_compare(
                &Value::from(9_007_199_254_740_993u64),
                &Value::from(9_007_199_254_740_992.0),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            ui_number(&v("1.500"), Some("1.5"), Some("2"), false).unwrap(),
            "1.5"
        );
        assert!(ui_number(&v("1.5"), Some("1.5"), None, true).is_err());
        for bad in ["NaN", "inf", "1e99999", " "] {
            assert!(ui_number(&v(bad), None, None, false).is_err());
        }
    }
    #[test]
    fn image_provenance_requires_safe_https_and_origin_budget() {
        assert_eq!(
            ui_image(&v("https://cdn.example.test/a.png")).unwrap().0,
            "https://cdn.example.test/a.png"
        );
        for bad in [
            "http://cdn.example.test/a",
            " https://cdn.example.test/a",
            "https://*.example.test/a",
            "https://u:p@cdn.example.test/a",
            "https://x.test/a\\b",
        ] {
            assert!(ui_image(&v(bad)).is_err());
        }
        assert_eq!(
            remote_image_origins(
                "<img src='https://cdn.example.test/a'><img src='/assets/app/logo'>"
            )
            .unwrap(),
            vec!["https://cdn.example.test"]
        );
    }
    #[test]
    fn generic_choice_and_navigation_constraints_are_validated() {
        assert!(validate_selects("<select data-ui-choice-set=true data-ui-choice-value=2><option value=1>One</option><option value=2 selected>Two</option></select>").is_ok());
        assert!(validate_selects("<select data-ui-choice-set=true data-ui-choice-value=3><option value=1>One</option></select>").is_err());
        assert!(validate_navigation("<nav data-ui-navigation=true data-ui-navigation-minimum-items=2 data-ui-navigation-current-last=true data-ui-navigation-ancestor-links=true><ol><li><a href='/'>Home</a></li><li><span aria-current=page>Current</span></li></ol></nav>").is_ok());
        assert!(validate_navigation("<nav data-ui-navigation=true data-ui-navigation-minimum-items=2 data-ui-navigation-current-last=true><ol><li><span aria-current=page>Current</span></li><li><a href='/'>Home</a></li></ol></nav>").is_err());
    }
}

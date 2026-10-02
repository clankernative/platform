//! Narrow host checks for values emitted by build-expanded Native UI bindings.
use anyhow::{Context, Result, ensure};
#[allow(unused_imports)]
pub(crate) use clanker_ui_runtime::{
    ImageSource, button_size, button_variant, field_text, image, initials, numeric_literal, plain,
    progress_complete, progress_maximum, progress_value, text, token, validate_remote_image_source,
};
use std::collections::BTreeSet;

pub(crate) fn remote_image_origins(markup: &str) -> Result<Vec<String>> {
    let html = scraper::Html::parse_fragment(markup);
    let selector = scraper::Selector::parse("img[src]").expect("static selector");
    let mut origins = BTreeSet::new();
    for image in html.select(&selector) {
        let src = image.value().attr("src").expect("selector requires src");
        if let Ok(url) = url::Url::parse(src) {
            ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none(),
                "cui_image_invalid_rendered_url"
            );
            ensure!(
                url.host_str()
                    .is_some_and(|host| !host.contains('*') && host.len() <= 253),
                "cui_image_invalid_rendered_host"
            );
            origins.insert(url.origin().ascii_serialization());
            ensure!(origins.len() <= 32, "cui_image_origin_budget");
        }
    }
    Ok(origins.into_iter().collect())
}

/// Check collection-backed choices after ordinary template rendering. Build-time
/// composition checks the declaration shape; only here are app loop values known.
pub(crate) fn validate_selects(markup: &str) -> Result<()> {
    if !markup.contains("select-field") {
        return Ok(());
    }
    use scraper::{Html, Selector};
    let html = Html::parse_fragment(markup);
    let roots = Selector::parse("[data-cui-component=select-field]").expect("static selector");
    let selects = Selector::parse("select").expect("static selector");
    let options = Selector::parse("option").expect("static selector");
    for root in html.select(&roots) {
        let controls = if root.value().name() == "select" {
            vec![root]
        } else {
            root.select(&selects).collect::<Vec<_>>()
        };
        ensure!(controls.len() == 1, "cui_select_requires_one_control");
        let control = controls[0];
        let choices = control.select(&options).collect::<Vec<_>>();
        ensure!(
            !choices.is_empty() && choices.len() <= 101,
            "cui_select_choice_budget"
        );
        let mut values = BTreeSet::new();
        let mut enabled = BTreeSet::new();
        let mut selected = 0;
        let mut placeholders = 0;
        for choice in choices {
            let value = choice
                .value()
                .attr("value")
                .context("cui_select_choice_requires_value")?;
            let label = choice.text().collect::<String>();
            text(&label)?;
            plain(value)?;
            ensure!(
                values.insert(value.to_owned()),
                "cui_select_duplicate_choice"
            );
            let placeholder = choice.value().attr("data-cui-placeholder").is_some();
            if placeholder {
                placeholders += 1;
                ensure!(value.is_empty(), "cui_select_placeholder_value");
            } else {
                ensure!(!value.trim().is_empty(), "cui_select_blank_choice");
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
                ensure!(
                    !disabled || placeholder,
                    "cui_select_selected_disabled_choice"
                );
            }
        }
        ensure!(
            placeholders <= 1 && values.len() - placeholders <= 100,
            "cui_select_choice_budget"
        );
        ensure!(
            values.len() > placeholders && selected <= 1,
            "cui_select_invalid_selection"
        );
        if let Some(wanted) = control
            .value()
            .attr("data-cui-selected")
            .or_else(|| root.value().attr("data-cui-selected"))
        {
            ensure!(
                enabled.contains(wanted) || (wanted.is_empty() && placeholders == 1),
                "cui_select_unknown_or_disabled_selection"
            );
        }
    }
    Ok(())
}

/// Runtime cardinality checks matter when app-authored conditionals/loops choose
/// navigation items. They do not turn page data into markup or destinations.
pub(crate) fn validate_navigation(markup: &str) -> Result<()> {
    if !markup.contains("breadcrumbs") && !markup.contains("pagination") {
        return Ok(());
    }
    use scraper::{Html, Selector};
    let html = Html::parse_fragment(markup);
    let roots =
        Selector::parse("[data-cui-component=breadcrumbs], [data-cui-component=pagination]")
            .expect("static selector");
    let current = Selector::parse("[aria-current=page]").expect("static selector");
    let items = Selector::parse("li").expect("static selector");
    for root in html.select(&roots) {
        let selected = root.select(&current).collect::<Vec<_>>();
        ensure!(
            selected.len() == 1,
            "cui_navigation_requires_one_current_page"
        );
        ensure!(
            selected[0].value().name() != "a",
            "cui_navigation_current_must_not_link"
        );
        if root.value().attr("data-cui-component") == Some("breadcrumbs") {
            let items = root.select(&items).collect::<Vec<_>>();
            ensure!(items.len() >= 2, "cui_breadcrumbs_require_ancestor");
            let last = items.last().expect("checked nonempty");
            ensure!(
                last.id() == selected[0].id() || last.select(&current).next().is_some(),
                "cui_breadcrumbs_current_must_be_last"
            );
            let links = Selector::parse("a[href]").expect("static selector");
            ensure!(
                items[..items.len() - 1]
                    .iter()
                    .all(|item| item.select(&links).count() == 1
                        && item.select(&current).next().is_none()),
                "cui_breadcrumbs_ancestors_require_links"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minijinja::Value;

    #[test]
    fn record_keys_reject_markup_whitespace_and_unbounded_values() {
        assert_eq!(
            token("task_9007199254740993").unwrap(),
            "task_9007199254740993"
        );
        for value in ["", "task key", "x\n", "<x>", "é", "a:b"] {
            assert!(token(value).is_err(), "{value:?}");
        }
        assert!(token(&"x".repeat(129)).is_err());
    }

    #[test]
    fn rendered_choices_validate_real_loop_values_and_requested_selection() {
        let valid = "<div data-cui-component=select-field data-cui-selected=2><select><option value=1>A</option><option value=2 selected>B</option></select></div>";
        assert!(validate_selects(valid).is_ok());
        for bad in [
            valid.replace("value=1", "value=2"),
            valid.replace("data-cui-selected=2", "data-cui-selected=3"),
            valid.replace("value=2 selected", "value=2 selected disabled"),
            valid.replace(">A<", "> <"),
            valid.replace("value=1", "value=1 selected"),
        ] {
            assert!(validate_selects(&bad).is_err(), "{bad}");
        }
        assert!(validate_selects("<div data-cui-component=select-field><select><option value='' data-cui-placeholder disabled selected>Choose</option><option value=1>A</option></select></div>").is_ok());
    }

    #[test]
    fn button_style_ordinals_emit_only_closed_tokens() {
        for (index, token) in [
            (0, "primary"),
            (1, "secondary"),
            (2, "quiet"),
            (3, "danger"),
        ] {
            assert_eq!(button_variant(&Value::from(index)).unwrap(), token);
        }
        assert_eq!(button_size(&Value::from(0)).unwrap(), "cui-button--compact");
        assert_eq!(button_size(&Value::from(1)).unwrap(), "");
        for bad in [
            Value::from(-1),
            Value::from(4),
            Value::from("0"),
            Value::from(true),
            Value::from(1.0),
            Value::from(u64::MAX),
        ] {
            assert!(button_variant(&bad).is_err());
        }
        for bad in [
            Value::from(-1),
            Value::from(2),
            Value::from("1"),
            Value::from(false),
            Value::from(0.0),
        ] {
            assert!(button_size(&bad).is_err());
        }
    }

    #[test]
    fn rendered_navigation_rejects_missing_duplicate_or_misplaced_current_items() {
        let good = "<nav data-cui-component=breadcrumbs><ol><li><a href='/'>Home</a></li><li><span aria-current=page>Task</span></li></ol></nav>";
        assert!(validate_navigation(good).is_ok());
        assert!(validate_navigation(&good.replace("aria-current=page", "")).is_err());
        assert!(
            validate_navigation(&good.replace("<a href='/'", "<a aria-current=page href='/'"))
                .is_err()
        );
        assert!(validate_navigation("<nav data-cui-component=breadcrumbs><ol><li><span aria-current=page>Task</span></li><li><a href='/'>Home</a></li></ol></nav>").is_err());
        assert!(validate_navigation("<nav data-cui-component=pagination><span aria-current=page>1</span><a href='/?page=2'>2</a></nav>").is_ok());
    }

    #[test]
    fn plain_and_field_text_have_distinct_control_and_blank_policies() {
        assert_eq!(plain("").unwrap(), "");
        assert!(plain("x\n").is_err());
        assert_eq!(
            field_text("line one\r\nline two\ttab").unwrap(),
            "line one\r\nline two\ttab"
        );
        assert!(field_text("  \n\t").is_err());
        assert!(field_text("x\u{7f}").is_err());
    }

    #[test]
    fn text_helpers_reject_blank_and_control_text_and_count_graphemes() {
        assert_eq!(text(" hello ").unwrap(), " hello ");
        assert!(text(" \n").is_err());
        assert!(text("a\u{7f}b").is_err());
        assert_eq!(initials("A👩‍🚀e\u{301}").unwrap(), "A👩‍🚀e\u{301}");
        assert!(initials("A👩‍🚀e\u{301}Z").is_err());
    }

    #[test]
    fn progress_preserves_large_integer_precision_and_rejects_invalid_ranges() {
        let value = Value::from("9007199254740993");
        let max = Value::from("9007199254740994");
        assert_eq!(progress_value(&value, &max).unwrap(), "9007199254740993");
        assert_eq!(progress_maximum(&value, &max).unwrap(), "9007199254740994");
        assert!(!progress_complete(&value, &max).unwrap());
        assert!(progress_value(&Value::from(5), &Value::from(4)).is_err());
        assert!(progress_value(&Value::from(0), &Value::from(0)).is_err());
        assert_eq!(
            progress_value(&Value::from(1), &Value::from("1.5")).unwrap(),
            "1"
        );
        assert!(!progress_complete(&Value::from(1), &Value::from("1.5")).unwrap());
        assert!(progress_value(&Value::from(2), &Value::from("1.5")).is_err());
        assert!(progress_value(&Value::from("NaN"), &Value::from(1)).is_err());
        assert!(
            progress_value(
                &Value::from("9007199254740993"),
                &Value::from("9007199254740992.0")
            )
            .is_err()
        );
    }

    proptest::proptest! {
        #[test]
        fn style_ordinals_match_the_closed_integer_domains(value in proptest::prelude::any::<i64>()) {
            proptest::prop_assert_eq!(button_variant(&Value::from(value)).is_ok(), (0..=3).contains(&value));
            proptest::prop_assert_eq!(button_size(&Value::from(value)).is_ok(), (0..=1).contains(&value));
        }
        #[test]
        fn record_token_matches_an_independent_character_oracle(value in ".{0,160}") {
            let allowed = value.chars().all(|c| c.is_ascii() && (c.is_alphanumeric() || c == '_' || c == '-'));
            proptest::prop_assert_eq!(token(&value).is_ok(), !value.is_empty() && value.len() <= 128 && allowed);
            if let Ok(actual) = token(&value) {
                proptest::prop_assert_eq!(actual, value);
            }
        }
        #[test]
        fn integer_progress_matches_the_unsigned_range_oracle(value in proptest::prelude::any::<u64>(), maximum in proptest::prelude::any::<u64>()) {
            let result = progress_value(&Value::from(value), &Value::from(maximum));
            proptest::prop_assert_eq!(result.is_ok(), maximum > 0 && value <= maximum);
            if let Ok(text) = result {
                proptest::prop_assert_eq!(text.parse::<u64>().unwrap(), value);
                proptest::prop_assert_eq!(progress_complete(&Value::from(value), &Value::from(maximum)).unwrap(), value == maximum);
            }
        }
        #[test]
        fn fractional_maximum_does_not_round_integer_fields(value in 0u64..200_000, maximum in 1u64..100_000) {
            let upper = Value::from(format!("{maximum}.5"));
            proptest::prop_assert_eq!(progress_value(&Value::from(value), &upper).is_ok(), value <= maximum);
            if value <= maximum {
                proptest::prop_assert!(!progress_complete(&Value::from(value), &upper).unwrap());
            }
        }
    }

    #[test]
    fn image_sources_require_safe_https_and_origins_are_scoped() {
        assert_eq!(
            image("https://cdn.example.test/a.png").unwrap().0,
            "https://cdn.example.test/a.png"
        );
        for value in [
            "http://cdn.example.test/a.png",
            " https://cdn.example.test/a.png",
            "https://*.example.test/a.png",
            "https://u:p@cdn.example.test/a",
            "https://x.test/a\\b",
            "https://x.test/a\n",
        ] {
            assert!(image(value).is_err(), "{value:?}");
        }
        assert_eq!(
            remote_image_origins(
                "<img src=\"https://cdn.example.test/a\"><img src=\"/assets/app/logo\">"
            )
            .unwrap(),
            vec!["https://cdn.example.test"]
        );
        assert!(remote_image_origins("<p>No images</p>").unwrap().is_empty());
        let too_many = (0..33)
            .map(|index| format!("<img src=\"https://cdn{index}.example.test/a.png\">"))
            .collect::<String>();
        assert!(remote_image_origins(&too_many).is_err());
    }
}

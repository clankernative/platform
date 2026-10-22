use crate::{routing::Catalog, schema::Kind};
use anyhow::{Context, Result, ensure};
use scraper::{ElementRef, Html, Selector};
use std::collections::{BTreeMap, BTreeSet};

/// Native range steps and datalist labels per range. Equity's $500M-$60B slider
/// at a $50M step needs 1,191; rendered HTML remains under the template budget.
pub(crate) const MAX_RANGE_CHOICES: i64 = 2048;

const QUERY_ATTRIBUTES: &[&str] = &[
    "data-query-on",
    "data-query-results",
    "data-query-status",
    "data-query-debounce",
    "data-query-revision",
    "data-query-commit-field",
    "data-query-commit-input",
];

fn selector(value: &str) -> Selector {
    Selector::parse(value).expect("static selector")
}

fn scalar_text(kind: &Kind) -> bool {
    matches!(
        kind,
        Kind::Text | Kind::StandardText { .. } | Kind::TextDomain { .. }
    )
}

pub(crate) fn validate_page_appearance(live: bool, live_refresh_ms: u64) -> Result<()> {
    ensure!(
        !live && live_refresh_ms == 0,
        "reactive_query_live_page_unsupported"
    );
    Ok(())
}

fn static_id(id: &str) -> bool {
    !id.starts_with("day2templatevalue")
        && id.len() <= 128
        && id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn canonical_integer(raw: &str) -> Option<i64> {
    let value = raw.parse::<i64>().ok()?;
    (raw == value.to_string() && value.unsigned_abs() <= 9_007_199_254_740_991).then_some(value)
}

fn id_is_unique(document: &Html, id: &str) -> bool {
    document
        .select(&selector("[id]"))
        .filter(|element| element.value().attr("id") == Some(id))
        .count()
        == 1
}

/// Validate the closed reactive-query attribute/control contract on a registered
/// query form. This is used for both source templates and rendered HTML.
pub(crate) fn validate_form(
    form: ElementRef<'_>,
    routes: &Catalog,
    page: &str,
    source_projection: bool,
) -> Result<()> {
    let attrs = form.value().attrs().collect::<Vec<_>>();
    for (name, _) in &attrs {
        if name.starts_with("data-query-") {
            ensure!(
                QUERY_ATTRIBUTES.contains(name),
                "unknown_query_form_attribute"
            );
        }
    }
    if !attrs
        .iter()
        .any(|(name, _)| name.starts_with("data-query-"))
    {
        return Ok(());
    }
    let get = |name: &str| form.value().attr(name);
    let form_id = get("id").context("query_form_id_required")?;
    ensure!(static_id(form_id), "query_form_id_invalid");
    ensure!(
        get("data-query-on") == Some("input"),
        "query_form_trigger_invalid"
    );
    let results_value = get("data-query-results").context("query_results_required")?;
    let results_ids = results_value.split_ascii_whitespace().collect::<Vec<_>>();
    ensure!(
        !results_ids.is_empty() && results_ids.join(" ") == results_value,
        "query_reference_whitespace_invalid"
    );
    let status_id = get("data-query-status").context("query_status_required")?;
    ensure!(
        static_id(status_id) && results_ids.iter().all(|id| static_id(id)),
        "query_reference_invalid"
    );
    ensure!(
        (1..=8).contains(&results_ids.len())
            && results_ids.iter().collect::<BTreeSet<_>>().len() == results_ids.len()
            && results_ids
                .iter()
                .all(|id| *id != status_id && *id != form_id),
        "query_reference_invalid"
    );
    if let Some(debounce) = get("data-query-debounce") {
        let ms = debounce.parse::<u16>().context("query_debounce_invalid")?;
        ensure!(
            ms <= 1000 && debounce == ms.to_string(),
            "query_debounce_invalid"
        );
    }
    let route = routes.route(page)?;
    ensure!(route.path_fields.is_empty(), "query_form_route_invalid");
    let descendants = form
        .descendants()
        .filter_map(ElementRef::wrap)
        .collect::<Vec<_>>();
    let mut names = BTreeSet::new();
    for node in &descendants {
        let value = node.value();
        if matches!(value.name(), "input" | "button" | "select" | "textarea") {
            ensure!(
                [
                    "form",
                    "formaction",
                    "formmethod",
                    "formenctype",
                    "formtarget",
                    "formnovalidate"
                ]
                .iter()
                .all(|attribute| value.attr(attribute).is_none()),
                "query_control_transport_override"
            );
            ensure!(
                value.attr("type") != Some("reset"),
                "reactive_query_reset_unsupported"
            );
            if let Some(name) = value.attr("name") {
                // The initial reactive port preserves scalar .value state, not
                // checked/selected choice groups or changing option inventories.
                ensure!(
                    (value.name() == "textarea"
                        || (value.name() == "input"
                            && matches!(
                                value.attr("type").unwrap_or("text"),
                                "text" | "search" | "hidden"
                            )))
                        && names.insert(name),
                    "reactive_query_control_unsupported"
                );
            }
        }
    }
    let by_id = |id: &str| {
        descendants
            .iter()
            .copied()
            .filter(|node| node.value().attr("id") == Some(id))
            .collect::<Vec<_>>()
    };
    let mut result_regions = Vec::new();
    for result_id in &results_ids {
        let matches = by_id(result_id);
        ensure!(matches.len() == 1, "query_reference_must_be_owned_unique");
        let region = matches[0];
        ensure!(
            matches!(region.value().name(), "div" | "section")
                && !region
                    .select(&selector(
                        "input,select,textarea,form,[data-query-results],[contenteditable]"
                    ))
                    .next()
                    .is_some()
                && region.value().attr("id") != Some(status_id)
                && region.value().attr("data-cui-component").is_none()
                && region.value().attr("contenteditable").is_none()
                && !region.ancestors().any(|ancestor| {
                    ElementRef::wrap(ancestor)
                        .is_some_and(|element| element.value().attr("contenteditable").is_some())
                }),
            "query_results_region_unsafe"
        );
        result_regions.push(region);
    }
    for (index, region) in result_regions.iter().enumerate() {
        ensure!(
            !result_regions
                .iter()
                .enumerate()
                .any(|(other_index, other)| {
                    index != other_index
                        && other
                            .ancestors()
                            .any(|ancestor| ancestor.id() == region.id())
                }),
            "query_results_regions_overlap"
        );
    }
    let status = by_id(status_id);
    ensure!(status.len() == 1, "query_reference_must_be_owned_unique");
    let status_node = status[0];
    ensure!(
        matches!(status_node.value().name(), "p" | "div" | "span" | "output")
            && (status_node.value().attr("role") == Some("status")
                || matches!(
                    status_node.value().attr("aria-live"),
                    Some("polite" | "assertive")
                ))
            && status_node.value().attr("contenteditable").is_none()
            && !status_node.ancestors().any(|ancestor| {
                ElementRef::wrap(ancestor)
                    .is_some_and(|element| element.value().attr("contenteditable").is_some())
            })
            && !result_regions.iter().any(|region| {
                status_node
                    .ancestors()
                    .any(|ancestor| ancestor.id() == region.id())
            }),
        "query_status_not_accessible"
    );
    // The host replaces the status text on mount and on every state change, which
    // deletes all of its descendants. It therefore holds only text: never a result
    // region, a control, a range label list or any other markup.
    ensure!(
        status_node
            .children()
            .all(|child| !child.value().is_element()),
        "query_status_must_be_text_only"
    );
    let revision = get("data-query-revision");
    let commit_field = get("data-query-commit-field");
    let commit_input = get("data-query-commit-input");
    ensure!(
        commit_input.is_none() || commit_field.is_some(),
        "query_commit_input_requires_field"
    );
    if let Some(field) = commit_input {
        let matches = descendants
            .iter()
            .filter(|node| {
                node.value().name() == "input" && node.value().attr("name") == Some(field)
            })
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1
                && matches[0].value().attr("type").unwrap_or("text") == "text"
                && matches[0].value().attr("readonly").is_none()
                && matches[0].value().attr("disabled").is_none()
                && route.input.fields.get(field).is_some_and(scalar_text),
            "query_commit_input_invalid"
        );
    }
    for (name, expected) in [(revision, Some("hidden")), (commit_field, Some("hidden"))] {
        if let Some(name) = name {
            ensure!(
                route.input.fields.contains_key(name),
                "query_auxiliary_field_unknown"
            );
            let matches = descendants
                .iter()
                .filter(|node| {
                    node.value().name() == "input" && node.value().attr("name") == Some(name)
                })
                .collect::<Vec<_>>();
            ensure!(
                matches.len() == 1
                    && matches[0].value().attr("type").unwrap_or("text") == expected.unwrap(),
                "query_auxiliary_field_invalid"
            );
            ensure!(
                matches[0].value().attr("type") == Some("hidden"),
                "query_auxiliary_field_invalid"
            );
            if name == revision.unwrap_or("") {
                ensure!(
                    matches!(route.input.fields[name], Kind::Unsigned(_)),
                    "query_revision_field_type_invalid"
                );
            } else {
                ensure!(
                    route.input.fields[name] == Kind::Boolean,
                    "query_commit_field_type_invalid"
                );
            }
        }
    }
    let text_fields: BTreeSet<_> = route
        .input
        .fields
        .iter()
        .filter(|(_, kind)| scalar_text(kind))
        .map(|(name, _)| name.as_str())
        .collect();
    let mut labels_seen = BTreeSet::new();
    let mut range_values = BTreeMap::<String, BTreeSet<i64>>::new();
    for &node in &descendants {
        let value = node.value();
        for (attribute, _) in value.attrs() {
            if node.id() != form.id() && attribute.starts_with("data-query-") {
                ensure!(
                    [
                        "data-query-input",
                        "data-query-labels",
                        "data-query-value",
                        "data-query-label",
                        "data-query-commit"
                    ]
                    .contains(&attribute),
                    "unknown_query_control_attribute"
                );
            }
        }
        let name = value.name();
        if value.attr("data-query-commit").is_some() {
            ensure!(
                commit_input.is_none(),
                "query_commit_configuration_conflict"
            );
            let field = value
                .attr("name")
                .context("query_commit_field_name_required")?;
            ensure!(
                name == "input"
                    && value.attr("data-query-commit") == Some("blur")
                    && commit_field.is_some()
                    && route.input.fields.contains_key(field)
                    && !matches!(route.input.fields[field], Kind::InputShape { .. }),
                "query_commit_control_invalid"
            );
            ensure!(
                value.attr("data-query-input").is_none(),
                "query_commit_control_invalid"
            );
            continue;
        }
        if let Some(target) = value.attr("data-query-input") {
            ensure!(text_fields.contains(target), "query_input_target_invalid");
            ensure!(value.attr("form").is_none(), "query_control_external_form");
            let targets = descendants
                .iter()
                .filter(|node| {
                    node.value().name() == "input"
                        && node.value().attr("name") == Some(target)
                        && matches!(
                            node.value().attr("type").unwrap_or("text"),
                            "text" | "search"
                        )
                        && node.value().attr("readonly").is_none()
                        && node.value().attr("disabled").is_none()
                        && node.value().attr("hidden").is_none()
                })
                .count();
            ensure!(targets == 1, "query_input_target_invalid");
            if name == "input" && value.attr("type") == Some("range") {
                let labels = value
                    .attr("data-query-labels")
                    .context("query_range_labels_required")?;
                ensure!(
                    static_id(value.attr("id").unwrap_or(""))
                        && (!source_projection
                            || !value.attr("id").unwrap_or("").contains("day2templatevalue"))
                        && value.attr("name").is_none()
                        && value.attr("disabled").is_none()
                        && value.attr("hidden").is_none()
                        && labels_seen.insert(labels.to_owned()),
                    "query_range_invalid"
                );
                let list = by_id(labels);
                ensure!(
                    list.len() == 1
                        && list[0].value().name() == "datalist"
                        && list[0].value().attr("name").is_none()
                        && static_id(labels),
                    "query_labels_list_invalid"
                );
                let minimum = canonical_integer(value.attr("min").unwrap_or(""))
                    .context("query_range_min_invalid")?;
                let maximum = canonical_integer(value.attr("max").unwrap_or(""))
                    .context("query_range_max_invalid")?;
                let step = canonical_integer(value.attr("step").unwrap_or(""))
                    .context("query_range_step_invalid")?;
                ensure!(minimum < maximum && step > 0, "query_range_bounds_invalid");
                let reachable = (maximum - minimum) / step + 1;
                ensure!(reachable <= MAX_RANGE_CHOICES, "query_range_steps_invalid");
                let options = list[0].select(&selector("option")).collect::<Vec<_>>();
                ensure!(
                    !options.is_empty() && options.len() as i64 <= MAX_RANGE_CHOICES,
                    "query_labels_options_invalid"
                );
                let mut values = BTreeSet::new();
                for option in options {
                    let option_value = option
                        .value()
                        .attr("value")
                        .context("query_option_value_required")?;
                    let number =
                        canonical_integer(option_value).context("query_option_value_invalid")?;
                    let label = option
                        .value()
                        .attr("label")
                        .map(str::to_owned)
                        .unwrap_or_else(|| option.text().collect::<String>());
                    ensure!(
                        (minimum..=maximum).contains(&number)
                            && values.insert(number)
                            && !label.trim().is_empty()
                            && label.len() <= 160,
                        "query_option_invalid"
                    );
                    crate::web_security::field_value(&route.input.fields[target], option_value)
                        .context("query_option_value_invalid")?;
                }
                ensure!(
                    (0..reachable).all(|index| values.contains(&(minimum + index * step))),
                    "query_range_labels_incomplete"
                );
                range_values.insert(target.to_owned(), values);
            } else if name == "button" && value.attr("type") == Some("button") {
                ensure!(
                    value.attr("data-query-value").is_some()
                        && value.attr("data-query-label").is_some()
                        && value.attr("name").is_none()
                        && static_id(value.attr("id").unwrap_or("")),
                    "query_preset_invalid"
                );
                let label = value.attr("data-query-label").unwrap();
                ensure!(
                    !label.trim().is_empty() && label.len() <= 160,
                    "query_preset_label_invalid"
                );
                let literal = value.attr("data-query-value").unwrap();
                if !source_projection || !literal.contains("day2templatevalue") {
                    crate::web_security::field_value(&route.input.fields[target], literal)
                        .context("query_preset_value_invalid")?;
                }
            } else {
                ensure!(
                    name == "input" && value.attr("data-query-commit") == Some("blur"),
                    "query_control_unsupported"
                );
            }
        } else {
            ensure!(
                value.attr("data-query-labels").is_none()
                    && value.attr("data-query-value").is_none()
                    && value.attr("data-query-label").is_none()
                    && value.attr("data-query-commit").is_none(),
                "query_control_attribute_orphaned"
            );
        }
    }
    for node in descendants.iter().filter(|node| {
        node.value().name() == "button" && node.value().attr("type") == Some("button")
    }) {
        if let (Some(target), Some(literal)) = (
            node.value().attr("data-query-input"),
            node.value().attr("data-query-value"),
        ) && (!source_projection || !literal.contains("day2templatevalue"))
            && let Some(values) = range_values.get(target)
        {
            let number = canonical_integer(literal).context("query_preset_value_invalid")?;
            ensure!(values.contains(&number), "query_preset_value_invalid");
        }
    }
    Ok(())
}

/// Product content changes inside result-region boundaries; runtime preserves host-owned root attributes.
///
/// Add the document-wide ID check at concrete rendering, after source fragments
/// have been assembled and before transport is bound.
pub(crate) fn validate_document(document: &Html, form: ElementRef<'_>) -> Result<()> {
    if form.value().attr("data-query-on").is_none() {
        return Ok(());
    }
    let form_id = form.value().attr("id").context("query_form_id_required")?;
    ensure!(
        document
            .select(&selector(
                "input[form],button[form],select[form],textarea[form]"
            ))
            .all(|node| node.value().attr("form") != Some(form_id)),
        "query_control_external_form"
    );
    for name in ["id", "data-query-status"] {
        if let Some(id) = form.value().attr(name) {
            ensure!(id_is_unique(document, id), "query_id_must_be_unique");
        }
    }
    if let Some(ids) = form.value().attr("data-query-results") {
        for id in ids.split_ascii_whitespace() {
            ensure!(id_is_unique(document, id), "query_id_must_be_unique");
        }
    }
    for node in form.select(&selector(
        "input[type=range][data-query-input],button[type=button][data-query-input]",
    )) {
        let id = node
            .value()
            .attr("id")
            .context("query_control_id_required")?;
        ensure!(
            static_id(id) && id_is_unique(document, id),
            "query_id_must_be_unique"
        );
        if let Some(labels) = node.value().attr("data-query-labels") {
            ensure!(id_is_unique(document, labels), "query_id_must_be_unique");
        }
    }
    Ok(())
}

use crate::{
    schema::{Kind, Record},
    web_html::View,
    web_security::{self as security, Ticket},
};
use anyhow::{Context, Result, ensure};
use ego_tree::NodeId;
use html5ever::QualName;
use maud::{Markup, PreEscaped};
use scraper::{ElementRef, Html, Node, Selector, node::Element};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_FORM_FIELDS: usize = crate::input_shape::MAX_FIELDS;
const MAX_FORM_CONTROLS: usize = 128;

fn selector(value: &str) -> Selector {
    Selector::parse(value).expect("static selector")
}

fn set_attr(document: &mut Html, id: NodeId, name: &str, value: &str) -> Result<()> {
    let mut node = document.tree.get_mut(id).context("form node missing")?;
    let Node::Element(element) = node.value() else {
        anyhow::bail!("expected form element");
    };
    element.attrs.retain(|(key, _)| key.local.as_ref() != name);
    element
        .attrs
        .push((QualName::new(None, "".into(), name.into()), value.into()));
    element
        .attrs
        .sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(())
}

fn remove_attr(document: &mut Html, id: NodeId, name: &str) -> Result<()> {
    let mut node = document.tree.get_mut(id).context("form node missing")?;
    let Node::Element(element) = node.value() else {
        anyhow::bail!("expected form element");
    };
    element.attrs.retain(|(key, _)| key.local.as_ref() != name);
    Ok(())
}

/// Materialize only closed boolean presentation attributes after checked rendering.
/// This preserves every select choice and avoids branching entire HTML documents
/// merely to add an option's `selected` or a checkbox's `checked` attribute.
/// It never creates destinations, form transport, commands, or arbitrary markup.
pub(crate) fn materialize_control_flags(document: &mut Html) -> Result<bool> {
    let mut changed = false;
    for (marker, attribute) in [
        ("data-ui-selected-flag", "selected"),
        ("data-ui-checked-flag", "checked"),
        ("data-ui-hidden-flag", "hidden"),
    ] {
        let nodes: Vec<_> = document
            .tree
            .nodes()
            .filter_map(ElementRef::wrap)
            .filter_map(|element| {
                element.value().attr(marker).map(|value| {
                    (
                        element.id(),
                        element.value().name().to_owned(),
                        element.value().attr("type").unwrap_or("").to_owned(),
                        value.to_owned(),
                    )
                })
            })
            .collect();
        changed |= !nodes.is_empty();
        for (id, tag, kind, value) in nodes {
            ensure!(
                match attribute {
                    "selected" => tag == "option",
                    "checked" => tag == "input" && matches!(kind.as_str(), "checkbox" | "radio"),
                    "hidden" => matches!(tag.as_str(), "fieldset" | "div"),
                    _ => false,
                },
                "ui_boolean_attribute_target"
            );
            ensure!(
                matches!(value.as_str(), "true" | "false"),
                "ui_boolean_attribute_value"
            );
            remove_attr(document, id, attribute)?;
            if value == "true" {
                set_attr(document, id, attribute, "")?;
            }
            remove_attr(document, id, marker)?;
        }
    }
    Ok(changed)
}

fn hidden(document: &mut Html, form: NodeId, name: &str, value: &str) -> Result<()> {
    let node = Node::Element(Element::new(
        QualName::new(None, "http://www.w3.org/1999/xhtml".into(), "input".into()),
        vec![],
    ));
    let id = document
        .tree
        .get_mut(form)
        .context("form missing")?
        .prepend(node)
        .id();
    for (key, content) in [("type", "hidden"), ("name", name), ("value", value)] {
        set_attr(document, id, key, content)?;
    }
    Ok(())
}

pub(crate) struct Control {
    pub(crate) id: NodeId,
    pub(crate) name: String,
    pub(crate) tag: String,
    pub(crate) hidden: bool,
    pub(crate) value: String,
    pub(crate) input_type: String,
    pub(crate) checked: bool,
    pub(crate) disabled: bool,
    pub(crate) multiple: bool,
    pub(crate) choices: Vec<String>,
}

/// A field may repeat only when the operation declares it a list of text. A list
/// of records needs indexed naming, which this protocol does not define, so it
/// stays unsupported rather than being approximated.
pub(crate) fn scalar_list(kind: &crate::schema::Kind) -> bool {
    use crate::output_schema::Type;
    matches!(
        kind,
        crate::schema::Kind::InputShape { shape: Type::List(inner), .. }
            if matches!(**inner, Type::String | Type::StandardText { .. })
    )
}

/// One control carrying an empty value represents the empty collection. A blank
/// item is never a legitimate member, so this cannot collide with a real value and
/// absence never has to mean anything.
pub(crate) fn empty_list(values: &[&str]) -> bool {
    values.len() == 1 && values[0].is_empty()
}

/// How a declared field is carried by form controls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Carrier {
    /// One control, one value.
    Scalar,
    /// Repeated controls sharing the field name; document order is list order.
    List,
    /// Controls named `field.key`; the key lives in the control name, so no index
    /// grammar is needed and a missing pair cannot be represented.
    Map,
    /// Repeated controls sharing the field name, decoded to a canonical set.
    Set,
}

pub(crate) fn carrier(kind: &crate::schema::Kind) -> Carrier {
    use crate::output_schema::Type;
    match kind {
        crate::schema::Kind::InputShape { shape, .. } => match shape {
            Type::List(inner) if matches!(**inner, Type::String | Type::StandardText { .. }) => {
                Carrier::List
            }
            Type::Map(_) => Carrier::Map,
            Type::Set => Carrier::Set,
            _ => Carrier::Scalar,
        },
        _ => Carrier::Scalar,
    }
}

/// Validate a closed native input group against its declared schema kind. The
/// returned metadata is signed into the command ticket and is the sole authority
/// for interpreting omitted successful controls at POST time.
pub(crate) fn native_field(
    controls: &[&Control],
    kind: &crate::schema::Kind,
) -> Result<Option<(security::NativeField, bool)>> {
    if controls.len() == 1 && controls[0].tag == "select" && controls[0].multiple {
        let control = &controls[0];
        ensure!(
            !control.disabled && scalar_list(kind),
            "native_form_schema_mismatch"
        );
        ensure!(
            control.choices.iter().all(|choice| !choice.is_empty())
                && control.choices.iter().collect::<BTreeSet<_>>().len() == control.choices.len(),
            "invalid_or_duplicate_native_choice"
        );
        return Ok(Some((
            security::NativeField {
                mode: security::NativeMode::MultipleSelect,
                omitted: Value::Array(Vec::new()),
                choices: control.choices.clone(),
            },
            false,
        )));
    }
    let native_count = controls
        .iter()
        .filter(|control| matches!(control.input_type.as_str(), "checkbox" | "radio"))
        .count();
    if native_count == 0 {
        ensure!(
            controls.iter().all(|control| !control.disabled),
            "disabled_form_fields_unsupported"
        );
        return Ok(None);
    }
    ensure!(native_count == controls.len(), "mixed_native_form_controls");
    let mode = controls[0].input_type.as_str();
    ensure!(
        controls.iter().all(|control| control.input_type == mode),
        "mixed_native_form_controls"
    );
    let disabled = controls.iter().all(|control| control.disabled);
    let values: Vec<_> = controls
        .iter()
        .map(|control| control.value.clone())
        .collect();
    ensure!(
        values.iter().all(|value| !value.is_empty())
            && values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "invalid_or_duplicate_native_choice"
    );
    let (native_mode, omitted) = match mode {
        "checkbox" if *kind == crate::schema::Kind::Boolean => {
            ensure!(
                controls.len() == 1 && values[0] == "true",
                "invalid_boolean_checkbox"
            );
            (security::NativeMode::BooleanCheckbox, Value::Bool(false))
        }
        "checkbox" if scalar_list(kind) => {
            (security::NativeMode::ListCheckbox, Value::Array(Vec::new()))
        }
        "checkbox" if carrier(kind) == Carrier::Set => (
            security::NativeMode::SetCheckbox,
            serde_json::json!({"members": []}),
        ),
        "radio"
            if matches!(
                kind,
                crate::schema::Kind::Text | crate::schema::Kind::StandardText { .. }
            ) =>
        {
            (security::NativeMode::Radio, Value::String(String::new()))
        }
        _ => anyhow::bail!("native_form_schema_mismatch"),
    };
    ensure!(
        controls
            .iter()
            .filter(|control| control.checked && (disabled || !control.disabled))
            .count()
            <= 1
            || mode == "checkbox",
        "multiple_checked_radios"
    );
    Ok(Some((
        security::NativeField {
            mode: native_mode,
            omitted,
            choices: if disabled {
                values
            } else {
                controls
                    .iter()
                    .filter(|control| !control.disabled)
                    .map(|control| control.value.clone())
                    .collect()
            },
        },
        disabled,
    )))
}

/// Split a control name into the declared field and, for a map, its key. The key
/// is part of the name so that one control always carries one complete entry.
pub(crate) fn split_control(name: &str) -> (&str, Option<&str>) {
    match name.split_once('.') {
        Some((field, key)) => (field, Some(key)),
        None => (name, None),
    }
}

fn bind_query_transport(
    document: &mut Html,
    form_id: NodeId,
    routes: &crate::routing::Catalog,
    page: &str,
) -> Result<()> {
    {
        let form = ElementRef::wrap(document.tree.get(form_id).context("form missing")?)
            .context("form element")?;
        validate_query_form(form, routes, page)?;
    }
    let route = routes.route(page)?;
    ensure!(route.path_fields.is_empty(), "path_page_form_unsupported");
    // Required query fields are supplied by the controls, not by defaults.
    // The route compiler has already admitted this fixed, canonical path.
    let destination = route.path.clone();
    set_attr(document, form_id, "method", "get")?;
    set_attr(document, form_id, "action", &destination)?;
    Ok(())
}

pub(crate) fn validate_query_form(
    form: ElementRef<'_>,
    routes: &crate::routing::Catalog,
    page: &str,
) -> Result<()> {
    validate_query_form_impl(form, routes, page, false)
}

pub(crate) fn validate_query_form_source(
    form: ElementRef<'_>,
    routes: &crate::routing::Catalog,
    page: &str,
) -> Result<()> {
    validate_query_form_impl(form, routes, page, true)
}

fn validate_query_form_impl(
    form: ElementRef<'_>,
    routes: &crate::routing::Catalog,
    page: &str,
    source_projection: bool,
) -> Result<()> {
    let route = routes
        .route(page)
        .with_context(|| format!("template_unknown_page: {page}"))?;
    ensure!(
        route.path_fields.is_empty(),
        "template_path_page_form_unsupported: {page}"
    );
    ensure!(
        form.value().attr("data-command").is_none() && form.value().attr("data-platform").is_none(),
        "template_page_form_mixed_binding"
    );
    for (name, _) in form.value().attrs() {
        ensure!(
            !["action", "method", "enctype", "target"].contains(&name),
            "reserved_form_transport_attribute"
        );
    }
    let mut fields = BTreeMap::<String, usize>::new();
    let mut count = 0;
    for element in form.descendants().filter_map(ElementRef::wrap) {
        let value = element.value();
        ensure!(
            value.attr("form").is_none(),
            "external_form_association_forbidden"
        );
        ensure!(
            ["formaction", "formmethod", "formenctype", "formtarget"]
                .iter()
                .all(|name| value.attr(name).is_none()),
            "submitter_transport_override_forbidden"
        );
        let Some(name) = value.attr("name") else {
            continue;
        };
        ensure!(
            ["input", "textarea", "select"].contains(&value.name())
                && !name.starts_with('_')
                && count < 32,
            "template_query_form_control_unsupported"
        );
        count += 1;
        let kind = route
            .input
            .fields
            .get(name)
            .with_context(|| format!("template_unknown_query_field: {page}.{name}"))?;
        let input_type = value.attr("type").unwrap_or("text").to_ascii_lowercase();
        let compatible = match kind {
            Kind::Boolean => input_type == "checkbox" || input_type == "hidden",
            Kind::Integer | Kind::Unsigned(_) | Kind::PageSize => {
                input_type == "number" || input_type == "hidden" || value.name() == "select"
            }
            Kind::WebUrl => input_type == "url" || value.name() == "select",
            Kind::Text
            | Kind::TextDomain { .. }
            | Kind::StandardText { .. }
            | Kind::Reference { .. }
            | Kind::ModelReference { .. }
            | Kind::RowVersion
            | Kind::Cursor
            | Kind::IdCursor => {
                ["text", "search", "email", "tel", "password", "hidden"]
                    .contains(&input_type.as_str())
                    || value.name() == "textarea"
                    || value.name() == "select"
            }
            Kind::OptionalText
            | Kind::OptionalInteger
            | Kind::OptionalUnsigned(_)
            | Kind::InputShape { .. } => false,
        };
        ensure!(
            compatible,
            "template_query_control_type_mismatch: {page}.{name}"
        );
        ensure!(
            !effectively_disabled(element) && value.attr("multiple").is_none(),
            "template_query_omitted_or_multiple_field"
        );
        if kind == &Kind::Boolean && input_type == "checkbox" {
            ensure!(
                route.defaults.get(name) == Some(&Value::Bool(false))
                    && value.attr("value") == Some("true"),
                "template_query_boolean_requires_false_default_and_true_value: {name}"
            );
        }
        if input_type == "hidden" {
            let carried = value
                .attr("value")
                .context("template_query_hidden_value_required")?;
            if !source_projection || !carried.contains("day2templatevalue") {
                crate::web_security::field_value(kind, carried)
                    .with_context(|| format!("template_query_hidden_value_invalid: {name}"))?;
            }
        }
        if value.name() == "select" {
            let mut options = BTreeSet::new();
            let mut selected = 0;
            for option in element
                .descendants()
                .filter_map(ElementRef::wrap)
                .filter(|option| option.value().name() == "option")
            {
                let label = option.text().collect::<String>();
                let text = option
                    .value()
                    .attr("value")
                    .map(str::to_owned)
                    .unwrap_or_else(|| label.clone());
                ensure!(
                    !text.is_empty()
                        && (source_projection || !text.contains("day2templatevalue"))
                        && !label.trim().is_empty()
                        && options.insert(text.clone())
                        && options.len() <= 100,
                    "template_query_select_options_invalid: {name}"
                );
                selected += usize::from(option.value().attr("selected").is_some());
                if !source_projection || !text.contains("day2templatevalue") {
                    crate::web_security::field_value(kind, &text)
                        .with_context(|| format!("template_query_select_option_invalid: {name}"))?;
                }
            }
            ensure!(
                !options.is_empty() && selected <= 1,
                "template_query_select_options_required: {name}"
            );
        }
        *fields.entry(name.to_owned()).or_default() += 1;
    }
    for (name, occurrences) in &fields {
        ensure!(
            *occurrences == 1,
            "template_duplicate_query_field: {page}.{name}"
        );
    }
    let required: BTreeSet<_> = route
        .input
        .fields
        .keys()
        .filter(|name| !route.defaults.contains_key(*name))
        .map(String::as_str)
        .collect();
    ensure!(
        required.is_subset(&fields.keys().map(String::as_str).collect()),
        "template_incomplete_query_form: {page}"
    );
    crate::web_query_bindings::validate_form(form, routes, page, source_projection)?;
    Ok(())
}

fn effectively_disabled(element: ElementRef<'_>) -> bool {
    if element.value().attr("disabled").is_some() {
        return true;
    }
    element
        .ancestors()
        .filter_map(ElementRef::wrap)
        .any(|ancestor| {
            if ancestor.value().name() != "fieldset" || ancestor.value().attr("disabled").is_none()
            {
                return false;
            }
            // HTML exempts controls inside a disabled fieldset's first direct legend.
            let first_legend = ancestor
                .children()
                .filter_map(ElementRef::wrap)
                .find(|child| child.value().name() == "legend")
                .map(|legend| legend.id());
            !element
                .ancestors()
                .any(|parent| Some(parent.id()) == first_legend)
        })
}

pub(crate) fn controls(form: ElementRef<'_>) -> Result<Vec<Control>> {
    let mut controls = Vec::new();
    let mut names = BTreeSet::new();
    for element in form.descendants().filter_map(ElementRef::wrap) {
        let value = element.value();
        ensure!(
            value.attr("form").is_none(),
            "external_form_association_forbidden"
        );
        ensure!(
            ["formaction", "formmethod", "formenctype", "formtarget"]
                .iter()
                .all(|name| value.attr(name).is_none()),
            "submitter_transport_override_forbidden"
        );
        let Some(name) = value.attr("name") else {
            continue;
        };
        // Repetition is a property of the declared field kind, not of the parser:
        // only a field the operation declares as a scalar list may appear twice.
        // Schema-aware callers enforce that; bound field names and repeated
        // controls independently so a bounded list can expose all its choices.
        names.insert(name.to_string());
        ensure!(
            ["input", "textarea", "select"].contains(&value.name())
                && !name.starts_with('_')
                && names.len() <= MAX_FORM_FIELDS
                && controls.len() < MAX_FORM_CONTROLS,
            "invalid_or_duplicate_form_field"
        );
        let multiple = value.attr("multiple").is_some();
        ensure!(
            !multiple || value.name() == "select",
            "omitted_or_multiple_form_fields_unsupported"
        );
        let kind = value.attr("type").unwrap_or("text").to_ascii_lowercase();
        if value.name() == "input" {
            ensure!(
                [
                    "text",
                    "url",
                    "email",
                    "search",
                    "tel",
                    "password",
                    "number",
                    "range",
                    "date",
                    "time",
                    "datetime-local",
                    "month",
                    "week",
                    "color",
                    "hidden",
                    "checkbox",
                    "radio"
                ]
                .contains(&kind.as_str()),
                "form_field_mode_unsupported: use scalar controls or select"
            );
        }
        let native = value.name() == "input" && matches!(kind.as_str(), "checkbox" | "radio");
        let disabled = effectively_disabled(element);
        ensure!(
            !disabled || native,
            "omitted_or_multiple_form_fields_unsupported"
        );
        controls.push(Control {
            id: element.id(),
            name: name.into(),
            tag: value.name().into(),
            hidden: value.name() == "input" && kind == "hidden",
            value: value.attr("value").unwrap_or("").into(),
            input_type: kind,
            checked: value.attr("checked").is_some(),
            disabled,
            multiple,
            choices: if value.name() == "select" && multiple {
                let options = element
                    .descendants()
                    .filter_map(ElementRef::wrap)
                    .filter(|option| option.value().name() == "option")
                    .map(|option| {
                        ensure!(
                            !effectively_disabled(option),
                            "multiple_select_disabled_choice"
                        );
                        option
                            .value()
                            .attr("value")
                            .context("multiple_select_option_requires_value")
                            .map(str::to_owned)
                    })
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    options.len() <= crate::input_shape::MAX_LIST_ITEMS,
                    "multiple_select_choice_bound"
                );
                options
            } else {
                Vec::new()
            },
        });
    }
    Ok(controls)
}

fn restore_select(document: &mut Html, control: &Control, values: &[String]) -> Result<()> {
    let options: Vec<_> = document
        .tree
        .get(control.id)
        .context("select")?
        .descendants()
        .filter_map(ElementRef::wrap)
        .filter(|element| element.value().name() == "option")
        .map(|element| {
            (
                element.id(),
                element
                    .value()
                    .attr("value")
                    .map(str::to_owned)
                    .unwrap_or_else(|| element.text().collect()),
            )
        })
        .collect();
    for (id, option) in options {
        remove_attr(document, id, "selected")?;
        if values.contains(&option) {
            set_attr(document, id, "selected", "")?;
        }
    }
    Ok(())
}

fn restore(document: &mut Html, control: &Control, value: &str) -> Result<()> {
    match control.tag.as_str() {
        "input" => set_attr(document, control.id, "value", value)?,
        "textarea" => {
            let children: Vec<_> = document
                .tree
                .get(control.id)
                .context("textarea")?
                .children()
                .map(|node| node.id())
                .collect();
            for child in children {
                document
                    .tree
                    .get_mut(child)
                    .context("textarea child")?
                    .detach();
            }
            document
                .tree
                .get_mut(control.id)
                .context("textarea")?
                .append(Node::Text(scraper::node::Text { text: value.into() }));
        }
        "select" => restore_select(document, control, &[value.to_owned()])?,
        _ => unreachable!(),
    }
    Ok(())
}

/// Bind concrete, validated HTML to the same durable command protocol as legacy
/// Roc views. No business operation or visual markup is inferred from field names.
pub(crate) fn bind(view: &View<'_>, markup: &str) -> Result<Markup> {
    ensure!(markup.len() <= 524_288, "rendered_html_budget");
    let mut document = Html::parse_fragment(markup);
    ensure!(
        document.errors.is_empty(),
        "invalid_rendered_html: {:?}",
        document.errors
    );
    let forms: Vec<_> = document
        .select(&selector("form"))
        .map(|form| form.id())
        .collect();
    ensure!(forms.len() <= 128, "rendered_form_budget");
    for form_id in forms {
        let form = ElementRef::wrap(document.tree.get(form_id).context("form missing")?)
            .context("form element")?;
        let page_binding = form.value().attr("data-page").map(str::to_owned);
        let operation = form.value().attr("data-command").map(str::to_owned);
        if let Some(page) = page_binding {
            ensure!(
                operation.is_none() && form.value().attr("data-platform").is_none(),
                "page_form_mixed_binding"
            );
            for (name, _) in form.value().attrs() {
                ensure!(
                    !["action", "method", "enctype", "target"].contains(&name),
                    "reserved_form_transport_attribute"
                );
            }
            let routes =
                crate::routing::Catalog::from_artifact(view.runtime.artifact().contract())?;
            if form.value().attr("data-query-on").is_some() {
                let definition = view.runtime.artifact().page(&page)?;
                crate::web_query_bindings::validate_page_appearance(
                    definition.live,
                    definition.live_refresh_ms,
                )?;
            }
            crate::web_query_bindings::validate_document(&document, form)?;
            bind_query_transport(&mut document, form_id, &routes, &page)?;
            continue;
        }
        let live_form_id = view
            .runtime
            .artifact()
            .page(view.page)?
            .live
            .then(|| form.value().attr("id").map(str::to_owned))
            .flatten();
        if operation.is_some() && view.runtime.artifact().page(view.page)?.live {
            let id = live_form_id
                .as_deref()
                .context("live_command_form_requires_id")?;
            ensure!(
                document
                    .select(&selector("[id]"))
                    .filter(|element| element.value().attr("id") == Some(id))
                    .count()
                    == 1,
                "live_command_form_id_must_be_unique"
            );
        }
        let sign_out = form.value().attr("data-platform") == Some("sign-out");
        ensure!(
            operation.is_some() != sign_out,
            "form_requires_one_platform_binding"
        );
        for (name, _) in form.value().attrs() {
            ensure!(
                !["action", "method", "enctype", "target"].contains(&name)
                    && !name.starts_with("data-on:submit")
                    && !name.starts_with("data-day2-")
                    && !name.starts_with("data-attr:action")
                    && !name.starts_with("data-attr:method"),
                "reserved_form_transport_attribute"
            );
        }
        let controls = controls(form)?;
        if sign_out {
            ensure!(controls.is_empty(), "sign_out_fields_forbidden");
            set_attr(&mut document, form_id, "method", "post")?;
            set_attr(&mut document, form_id, "action", "/logout")?;
            hidden(
                &mut document,
                form_id,
                "_csrf",
                &security::csrf(view.secret, view.session)?,
            )?;
            continue;
        }
        let operation = operation.context("command binding")?;
        let definition = view.runtime.artifact().operation(&operation)?;
        ensure!(definition.kind == "command", "form_requires_command");
        let record = &view.runtime.artifact().contract().schema.inputs[&definition.input_type];
        // A control may name a map key, so completeness is checked on the declared
        // field rather than the raw control name.
        let names: BTreeSet<_> = controls
            .iter()
            .map(|control| split_control(&control.name).0)
            .collect();
        ensure!(
            names == record.fields.keys().map(String::as_str).collect(),
            "incomplete_or_unknown_form_binding"
        );
        let mut bound = Map::new();
        let mut editable = Vec::new();
        let mut native = BTreeMap::new();
        let mut groups: BTreeMap<&str, Vec<&Control>> = BTreeMap::new();
        for control in &controls {
            let (field, _) = split_control(&control.name);
            groups.entry(field).or_default().push(control);
        }
        let mut keys: BTreeSet<(&str, &str)> = BTreeSet::new();
        for (field, group) in groups {
            let kind = &record.fields[field];
            let carried = carrier(kind);
            ensure!(
                !matches!(kind, Kind::OptionalText)
                    && (!matches!(kind, Kind::InputShape { .. }) || carried != Carrier::Scalar),
                "optional_or_structured_form_field_unsupported"
            );
            for control in &group {
                let (control_field, key) = split_control(&control.name);
                ensure!(control_field == field, "invalid_or_duplicate_form_field");
                match carried {
                    Carrier::Map => {
                        let key = key.context("map_form_field_requires_key")?;
                        day2_contracts::names::identifier(key)?;
                        ensure!(keys.insert((field, key)), "invalid_or_duplicate_form_field");
                    }
                    _ => ensure!(key.is_none(), "unexpected_form_field_key"),
                }
            }
            if let Some((metadata, disabled)) = native_field(&group, kind)? {
                ensure!(carried != Carrier::Map, "native_form_schema_mismatch");
                if disabled {
                    let selected: Vec<String> = group
                        .iter()
                        .filter(|control| control.checked)
                        .map(|control| control.value.clone())
                        .collect();
                    let value = if metadata.mode == security::NativeMode::BooleanCheckbox {
                        Value::Bool(!selected.is_empty())
                    } else if selected.is_empty() {
                        metadata.omitted.clone()
                    } else {
                        security::field_values(kind, &selected)?
                    };
                    Record {
                        fields: BTreeMap::from([(field.to_owned(), kind.clone())]),
                        roc_type: None,
                        identity: None,
                    }
                    .validate_input(&serde_json::json!({field: value}))?;
                    bound.insert(field.to_owned(), value);
                } else {
                    native.insert(field.to_owned(), metadata);
                    editable.push(field.to_owned());
                }
                continue;
            }
            ensure!(
                group.len() == 1 || carried != Carrier::Scalar,
                "invalid_or_duplicate_form_field"
            );
            ensure!(
                carried == Carrier::Scalar || group.iter().all(|control| !control.hidden),
                "hidden_collection_form_field_unsupported"
            );
            for control in group {
                if control.hidden {
                    let value = security::field_value(kind, &control.value)?;
                    Record {
                        fields: BTreeMap::from([(control.name.clone(), kind.clone())]),
                        roc_type: None,
                        identity: None,
                    }
                    .validate_input(&serde_json::json!({ &control.name: &value }))?;
                    bound.insert(control.name.clone(), value);
                }
            }
            if !controls
                .iter()
                .any(|control| split_control(&control.name).0 == field && control.hidden)
            {
                editable.push(field.to_owned());
            }
        }
        if view
            .runtime
            .authorize(&operation, &view.session.actor)
            .is_err()
        {
            document.tree.get_mut(form_id).context("form")?.detach();
            continue;
        }
        let nonce = security::random(view.entropy)?;
        let ticket = Ticket {
            scope: view.runtime.scope().to_owned(),
            artifact: view.runtime.artifact().id().to_owned(),
            session: view.session.hash.clone(),
            actor: view.session.actor.clone(),
            page: view.page.into(),
            page_input: view.input.clone(),
            operation: operation.clone(),
            form_id: live_form_id,
            bound: Value::Object(bound),
            editable,
            native,
            nonce: nonce.clone(),
            issued: view.now,
            expires: (view.now + 1800).min(view.session.expires),
        };
        for control in &controls {
            if let Some(Kind::StandardText { domain }) = record.fields.get(&control.name) {
                let rules = &view
                    .runtime
                    .artifact()
                    .contract()
                    .app_contract
                    .as_ref()
                    .context("application domain contract required")?
                    .domains[domain];
                remove_attr(&mut document, control.id, "maxlength")?;
                remove_attr(&mut document, control.id, "minlength")?;
                remove_attr(&mut document, control.id, "required")?;
                set_attr(
                    &mut document,
                    control.id,
                    "data-day2-max-utf8-bytes",
                    &rules.maximum_bytes.to_string(),
                )?;
                if rules.nonblank {
                    set_attr(&mut document, control.id, "required", "")?;
                    set_attr(&mut document, control.id, "data-day2-nonblank", "true")?;
                }
            }
            if control.hidden {
                document
                    .tree
                    .get_mut(control.id)
                    .context("bound input")?
                    .detach();
            } else if let Some(submitted) = view.submitted.filter(|submitted| {
                !control.disabled
                    && submitted.operation == operation
                    && submitted.bound == &ticket.bound
            }) {
                if let Some(native_field) = ticket.native.get(&control.name) {
                    let values = submitted
                        .fields
                        .get(&control.name)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    if native_field.mode == security::NativeMode::MultipleSelect {
                        restore_select(&mut document, control, values)?;
                    } else {
                        let checked = match native_field.mode {
                            security::NativeMode::BooleanCheckbox => {
                                values.iter().any(|value| value == "true")
                            }
                            _ => values.iter().any(|value| value == &control.value),
                        };
                        remove_attr(&mut document, control.id, "checked")?;
                        if checked {
                            set_attr(&mut document, control.id, "checked", "")?;
                        }
                    }
                } else if let Some(value) =
                    submitted.value(&operation, &ticket.bound, &control.name)
                {
                    restore(&mut document, control, value)?;
                }
            }
        }
        for (name, value) in [
            ("method", "post"),
            ("action", "/actions"),
            (
                "data-on:submit__prevent",
                "@post(el.action, {contentType:'form', retry:'never'})",
            ),
            ("data-day2-invocation", &format!("web-{nonce}")),
        ] {
            set_attr(&mut document, form_id, name, value)?;
        }
        hidden(
            &mut document,
            form_id,
            "_ticket",
            &security::sign(view.secret, &serde_json::to_vec(&ticket)?)?,
        )?;
        hidden(
            &mut document,
            form_id,
            "_csrf",
            &security::csrf(view.secret, view.session)?,
        )?;
    }
    if view.runtime.artifact().contract().format >= 7 {
        crate::web_templates::validate_fragments(&document)?;
    }
    Ok(PreEscaped(document.root_element().inner_html()))
}

#[cfg(test)]
mod query_form_tests {
    use super::*;

    fn routes(path_parameter: bool) -> crate::routing::Catalog {
        routes_with_commit(path_parameter, false)
    }

    fn routes_with_commit(path_parameter: bool, with_commit: bool) -> crate::routing::Catalog {
        let root = crate::artifact::Page {
            name: "home".into(),
            title: "Home".into(),
            operation: "home".into(),
            defaults: "{}".into(),
            path: "/".into(),
            template: String::new(),
            input_type: "Empty".into(),
            output_type: "Empty".into(),
            live: false,
            live_refresh_ms: 0,
            preparation: vec![],
            prepare_failure_operation: String::new(),
            failure_page: String::new(),
        };
        let (fields, defaults, path) = if path_parameter {
            (
                BTreeMap::from([("id".into(), Kind::Text)]),
                "{}",
                "/records/{id}",
            )
        } else {
            (
                BTreeMap::from([
                    ("term".into(), Kind::Text),
                    ("archived".into(), Kind::Boolean),
                    ("page".into(), Kind::Integer),
                ]),
                r#"{"archived":false,"page":1}"#,
                "/search",
            )
        };
        let mut fields = fields;
        let mut defaults: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(defaults).unwrap();
        if with_commit && !path_parameter {
            fields.insert("committed".into(), Kind::Boolean);
            defaults.insert("committed".into(), serde_json::Value::Bool(false));
        }
        let page = crate::artifact::Page {
            name: "target".into(),
            title: "Target".into(),
            operation: "target".into(),
            defaults: serde_json::to_string(&defaults).unwrap(),
            path: path.into(),
            template: String::new(),
            input_type: "Target".into(),
            output_type: "Target".into(),
            live: false,
            live_refresh_ms: 0,
            preparation: vec![],
            prepare_failure_operation: String::new(),
            failure_page: String::new(),
        };
        let operations = vec![
            crate::artifact::Operation {
                name: "home".into(),
                kind: "query".into(),
                input_type: "Empty".into(),
                output_type: "Empty".into(),
            },
            crate::artifact::Operation {
                name: "target".into(),
                kind: "query".into(),
                input_type: "Target".into(),
                output_type: "Target".into(),
            },
        ];
        let schema = crate::schema::Schema {
            models: BTreeMap::new(),
            inputs: BTreeMap::from([
                (
                    "Empty".into(),
                    crate::schema::Record {
                        fields: BTreeMap::new(),
                        roc_type: None,
                        identity: None,
                    },
                ),
                (
                    "Target".into(),
                    crate::schema::Record {
                        fields,
                        roc_type: None,
                        identity: None,
                    },
                ),
            ]),
            foreign_keys: vec![],
            indexes: vec![],
            rollups: vec![],
            domains: BTreeMap::new(),
        };
        crate::routing::Catalog::compile(&[root, page], &operations, &schema).unwrap()
    }

    #[test]
    fn multiple_select_is_bound_only_to_scalar_lists_with_closed_option_choices() {
        let html = Html::parse_fragment(
            r#"<form><select name="members" multiple><option value="u1">One</option><option value="u2">Two</option></select></form>"#,
        );
        let form = html.select(&selector("form")).next().unwrap();
        let fields = controls(form).unwrap();
        assert_eq!(fields.len(), 1);
        assert!(fields[0].multiple);
        assert_eq!(fields[0].choices, ["u1", "u2"]);
        let kind = Kind::InputShape {
            shape: crate::output_schema::Type::List(Box::new(crate::output_schema::Type::String)),
            roc_type: "Members".into(),
        };
        let metadata = native_field(&[&fields[0]], &kind).unwrap().unwrap();
        assert_eq!(metadata.0.mode, security::NativeMode::MultipleSelect);
        assert_eq!(metadata.0.omitted, Value::Array(Vec::new()));
        let empty =
            Html::parse_fragment(r#"<form><select name="members" multiple></select></form>"#);
        let empty_controls = controls(empty.select(&selector("form")).next().unwrap()).unwrap();
        let empty_metadata = native_field(&[&empty_controls[0]], &kind).unwrap().unwrap();
        assert!(empty_metadata.0.choices.is_empty());
        assert_eq!(empty_metadata.0.omitted, Value::Array(Vec::new()));
        assert_eq!(
            security::field_values(&kind, &[]).unwrap(),
            Value::Array(Vec::new())
        );
        let mut restored = Html::parse_fragment(
            r#"<form><select name="members" multiple><option value="u1" selected>One</option><option value="u2">Two</option></select></form>"#,
        );
        let form = restored.select(&selector("form")).next().unwrap();
        let control = controls(form).unwrap().remove(0);
        restore_select(&mut restored, &control, &["u2".to_owned()]).unwrap();
        let selected: Vec<_> = restored
            .select(&selector("option[selected]"))
            .map(|option| option.value().attr("value").unwrap().to_owned())
            .collect();
        assert_eq!(selected, ["u2"]);
        assert!(
            restored
                .select(&selector("select[checked]"))
                .next()
                .is_none()
        );
        assert!(native_field(&[&fields[0]], &Kind::Text).is_err());
        let missing_value = Html::parse_fragment(
            r#"<form><select name="members" multiple><option>One</option></select></form>"#,
        );
        assert!(controls(missing_value.select(&selector("form")).next().unwrap()).is_err());
        let duplicate = Html::parse_fragment(
            r#"<form><select name="members" multiple><option value="u1">One</option><option value="u1">Duplicate</option></select></form>"#,
        );
        let fields = controls(duplicate.select(&selector("form")).next().unwrap()).unwrap();
        assert!(native_field(&[&fields[0]], &kind).is_err());
    }

    #[test]
    fn boolean_control_flags_preserve_choices_and_select_exactly_one() {
        let mut document = Html::parse_fragment(
            r#"<select data-ui-choice-set="true" data-ui-choice-value="2"><option value="1" selected data-ui-selected-flag="false">One</option><option value="2" data-ui-selected-flag="true">Two</option><option value="3" data-ui-selected-flag="false">Three</option></select><input type="checkbox" checked data-ui-checked-flag="false"><fieldset data-ui-hidden-flag="true"><legend>Specimen options</legend></fieldset>"#,
        );
        assert!(materialize_control_flags(&mut document).unwrap());
        let markup = document.root_element().inner_html();
        assert_eq!(document.select(&selector("option")).count(), 3);
        assert_eq!(
            document
                .select(&selector("option[selected]"))
                .next()
                .unwrap()
                .value()
                .attr("value"),
            Some("2")
        );
        assert!(
            document
                .select(&selector("input[checked]"))
                .next()
                .is_none()
        );
        assert!(
            document
                .select(&selector("fieldset[hidden]"))
                .next()
                .is_some()
        );
        assert!(!markup.contains("-flag="));
        crate::ui_values::validate_selects(&markup).unwrap();
        for bad in [
            r#"<option data-ui-selected-flag="yes">Bad</option>"#,
            r#"<input type="text" data-ui-checked-flag="true">"#,
            r#"<form data-ui-hidden-flag="true"></form>"#,
        ] {
            assert!(materialize_control_flags(&mut Html::parse_fragment(bad)).is_err());
        }
    }

    #[test]
    fn reactive_query_form_admits_closed_config_and_rejects_unsafe_boundaries() {
        let catalog = routes_with_commit(false, true);
        let valid = r#"<form id="search" data-page="target" data-query-on="input" data-query-results="results values" data-query-status="status" data-query-commit-field="committed" data-query-commit-input="term"><input name="term" type="text"><input name="archived" type="hidden" value="false"><input name="page" type="hidden" value="1"><input name="committed" type="hidden" value="false"><div id="results"></div><section id="values"></section><p id="status" role="status"></p></form>"#;
        let document = Html::parse_fragment(valid);
        validate_query_form(
            document.select(&selector("form")).next().unwrap(),
            &catalog,
            "target",
        )
        .unwrap();
        for bad in [
            valid.replace(
                "name=\"archived\" type=\"hidden\" value=\"false\"",
                "name=\"archived\" type=\"checkbox\" value=\"true\"",
            ),
            valid.replace("type=\"text\"", "type=\"radio\" value=\"a\""),
            valid.replace(
                "<input name=\"term\" type=\"text\">",
                "<select name=\"term\"><option value=\"one\">One</option></select>",
            ),
            valid.replace("</form>", "<button type=\"reset\">Reset</button></form>"),
            valid.replace(
                "</form>",
                "<button type=\"submit\" formaction=\"/other\">Other</button></form>",
            ),
            valid.replace("data-query-on=\"input\"", "data-query-on=\"change\""),
            valid.replace("role=\"status\"", ""),
            valid.replace(
                "id=\"results\"></div>",
                "id=\"results\"><input name=\"term\"></div>",
            ),
            valid.replace(
                "data-query-results=\"results values\"",
                "data-query-results=\"missing values\"",
            ),
            valid.replace("data-query-on=\"input\"", "data-query-other=\"x\""),
            valid.replace(
                "data-query-results=\"results values\"",
                "data-query-results=\"results results\"",
            ),
            valid
                .replace(
                    "data-query-results=\"results values\"",
                    "data-query-results=\"results\"",
                )
                .replace("id=\"values\"", "id=\"results\""),
            valid.replace(
                "id=\"results\"></div>",
                "id=\"results\" data-cui-component=widget></div>",
            ),
            valid.replace(
                "data-query-results=\"results values\"",
                "data-query-results=\"status values\"",
            ),
            valid.replace(
                "data-query-results=\"results values\"",
                "data-query-results=\" results values\"",
            ),
            valid.replace(
                "data-query-results=\"results values\"",
                "data-query-results=\"results  values\"",
            ),
            valid.replace(
                "id=\"results\"></div>",
                "id=\"results\" contenteditable=\"true\"></div>",
            ),
            valid.replace(
                "id=\"status\" role=\"status\"",
                "id=\"status\" role=\"status\" contenteditable=\"true\"",
            ),
            valid.replace(
                "<p id=\"status\" role=\"status\"></p>",
                "<button id=\"status\" role=\"status\"></button>",
            ),
            valid.replace(
                "<div id=\"results\"></div>",
                "<div id=\"results\"><p id=\"status\" role=\"status\"></p></div>",
            ),
        ] {
            let document = Html::parse_fragment(&bad);
            assert!(
                validate_query_form(
                    document.select(&selector("form")).next().unwrap(),
                    &catalog,
                    "target"
                )
                .is_err(),
                "accepted {bad}"
            );
        }
        let widget_child = valid.replace(
            "<div id=\"results\"></div>",
            "<div id=\"results\"><div data-cui-component=\"Number\"></div></div>",
        );
        let document = Html::parse_fragment(&widget_child);
        validate_query_form(
            document.select(&selector("form")).next().unwrap(),
            &catalog,
            "target",
        )
        .unwrap();
        let widget_root = valid.replace(
            "<div id=\"results\"></div>",
            "<div id=\"results\" data-cui-component=\"Number\"></div>",
        );
        let document = Html::parse_fragment(&widget_root);
        assert!(
            validate_query_form(
                document.select(&selector("form")).next().unwrap(),
                &catalog,
                "target",
            )
            .is_err()
        );
    }

    #[test]
    fn query_status_is_text_only_and_disjoint_from_results_at_source_and_render() {
        let catalog = routes_with_commit(false, true);
        let valid = r#"<form id="search" data-page="target" data-query-on="input" data-query-results="results" data-query-status="status" data-query-commit-field="committed" data-query-commit-input="term"><input name="term" type="text"><input name="archived" type="hidden" value="false"><input name="page" type="hidden" value="1"><input name="committed" type="hidden" value="false"><div id="results"></div><p id="status" role="status">Ready</p></form>"#;
        let admit = |markup: &str, source: bool| {
            let document = Html::parse_fragment(markup);
            let form = document.select(&selector("form")).next().unwrap();
            if source {
                validate_query_form_source(form, &catalog, "target")
            } else {
                validate_query_form(form, &catalog, "target")
            }
        };
        let status = "<p id=\"status\" role=\"status\">Ready</p>";
        let rejected = [
            // Status inside a result region: replacing results detaches it.
            valid.replace(status, "").replace(
                "<div id=\"results\"></div>",
                "<div id=\"results\"><p id=\"status\" role=\"status\"></p></div>",
            ),
            // Result region inside the status: setting the status text deletes it.
            valid.replace(status, "").replace(
                "<div id=\"results\"></div>",
                "<div id=\"status\" role=\"status\"><section id=\"results\"></section></div>",
            ),
            // A named control inside the status.
            valid
                .replace("<input name=\"page\" type=\"hidden\" value=\"1\">", "")
                .replace(
                    status,
                    "<div id=\"status\" role=\"status\"><input name=\"page\" type=\"hidden\" value=\"1\"></div>",
                ),
            // A submit button inside the status.
            valid.replace(
                status,
                "<div id=\"status\" role=\"status\"><button type=\"submit\">Search</button></div>",
            ),
            // Any other markup is deleted on mount as well.
            valid.replace(
                status,
                "<p id=\"status\" role=\"status\"><strong>Ready</strong></p>",
            ),
        ];
        for source in [true, false] {
            admit(valid, source).unwrap();
            for bad in &rejected {
                let Err(error) = admit(bad, source) else {
                    panic!("source={source} accepted {bad}");
                };
                let error = error.to_string();
                assert!(error.starts_with("query_status_"), "{error}: {bad}");
            }
        }
        let range = r#"<form id="lookup" data-page="target" data-query-on="input" data-query-results="results" data-query-status="status"><input name="term" type="search"><input name="archived" type="hidden" value="false"><input name="page" type="hidden" value="1"><section id="results"></section><div id="status" aria-live="polite"><input id="mirror" type="range" data-query-input="term" data-query-labels="choices" min="1" max="2" step="1" value="1"><datalist id="choices"><option value="1" label="One"></option><option value="2" label="Two"></option></datalist><button id="preset" type="button" data-query-input="term" data-query-value="2" data-query-label="Two">Two</button></div></form>"#;
        for source in [true, false] {
            let error = admit(range, source).unwrap_err().to_string();
            assert!(error.contains("query_status_must_be_text_only"), "{error}");
        }
    }

    #[test]
    fn concrete_query_binding_checks_each_result_id_for_document_uniqueness() {
        let catalog = routes_with_commit(false, true);
        let markup = r#"<form id="search" data-page="target" data-query-on="input" data-query-results="results values" data-query-status="status" data-query-commit-field="committed" data-query-commit-input="term"><input name="term" type="text"><input name="archived" type="hidden" value="false"><input name="page" type="hidden" value="1"><input name="committed" type="hidden" value="false"><div id="results"></div><section id="values"></section><p id="status" role="status"></p></form>"#;
        let document = Html::parse_fragment(markup);
        let form = document.select(&selector("form")).next().unwrap();
        validate_query_form(form, &catalog, "target").unwrap();
        crate::web_query_bindings::validate_document(&document, form).unwrap();

        for extra in [
            "<aside id=\"values\"></aside>",
            "<input form=\"search\" name=\"term\" value=\"outside\">",
        ] {
            let duplicate = Html::parse_fragment(&format!("{markup}{extra}"));
            let form = duplicate.select(&selector("form")).next().unwrap();
            assert!(crate::web_query_bindings::validate_document(&duplicate, form).is_err());
        }
    }

    #[test]
    fn query_presets_require_an_editable_text_target_even_without_a_range() {
        let catalog = routes(false);
        let markup = r#"<form id="choices" data-page="target" data-query-on="input" data-query-results="results" data-query-status="status"><input name="term" type="text"><button id="preset" type="button" data-query-input="term" data-query-value="literal" data-query-label="Literal">Literal</button><div id="results"></div><p id="status" role="status"></p></form>"#;
        for (field, valid) in [
            ("type=\"text\"", true),
            ("type=\"hidden\"", false),
            ("type=\"text\" readonly", false),
        ] {
            let source = markup.replace("type=\"text\"", field);
            let document = Html::parse_fragment(&source);
            let form = document.select(&selector("form")).next().unwrap();
            assert_eq!(
                validate_query_form(form, &catalog, "target").is_ok(),
                valid,
                "{source}"
            );
        }
    }

    #[test]
    fn reactive_query_forms_reject_live_and_timed_page_appearances() {
        assert!(crate::web_query_bindings::validate_page_appearance(false, 0).is_ok());
        assert!(crate::web_query_bindings::validate_page_appearance(true, 0).is_err());
        assert!(crate::web_query_bindings::validate_page_appearance(false, 5_000).is_err());
    }

    #[test]
    fn query_range_choice_bound_admits_equity_slider_and_rejects_larger_ranges() {
        let catalog = routes(false);
        let form = |step: i64, maximum: i64| {
            let mut options = String::new();
            let mut value = 500_000_000_i64;
            while value <= maximum {
                options.push_str(&format!(
                    "<option value=\"{value}\" label=\"V{value}\"></option>"
                ));
                value += step;
            }
            format!(
                "<form id=\"lookup\" data-page=\"target\" data-query-on=\"input\" data-query-results=\"results\" data-query-status=\"status\"><input id=\"term\" name=\"term\" type=\"search\"><input id=\"mirror\" type=\"range\" data-query-input=\"term\" data-query-labels=\"choices\" min=\"500000000\" max=\"{maximum}\" step=\"{step}\" value=\"500000000\"><datalist id=\"choices\">{options}</datalist><section id=\"results\"></section><p id=\"status\" aria-live=\"polite\"></p></form>"
            )
        };
        let check = |markup: String| {
            let document = Html::parse_fragment(&markup);
            validate_query_form(
                document.select(&selector("form")).next().unwrap(),
                &catalog,
                "target",
            )
        };
        // 1,191 reachable $50M steps from $500M to $60B.
        check(form(50_000_000, 60_000_000_000)).unwrap();
        let limit = crate::web_query_bindings::MAX_RANGE_CHOICES;
        check(form(1, 500_000_000 + limit - 1)).unwrap();
        assert!(check(form(1, 500_000_000 + limit)).is_err());
    }

    #[test]
    fn query_range_accepts_large_label_attribute_lookup_and_validates_reachable_steps() {
        let catalog = routes(false);
        let mut options = String::new();
        for index in 0..596 {
            let value = 500_000_000_i64 + index * 100_000_000;
            options.push_str(&format!(
                "<option value=\"{value}\" label=\"Market cap {index}\"></option>"
            ));
        }
        options
            .push_str("<option value=\"550000000\" label=\"Initial off-step scenario\"></option>");
        let markup = format!(
            "<form id=\"lookup\" data-page=\"target\" data-query-on=\"input\" data-query-results=\"results\" data-query-status=\"status\"><input id=\"term\" name=\"term\" type=\"search\"><input id=\"mirror\" type=\"range\" data-query-input=\"term\" data-query-labels=\"choices\" min=\"500000000\" max=\"60000000000\" step=\"100000000\" value=\"550000000\"><datalist id=\"choices\">{options}</datalist><button id=\"preset\" type=\"button\" data-query-input=\"term\" data-query-value=\"550000000\" data-query-label=\"Mid-market\">Mid</button><section id=\"results\"><div data-cui-component=\"Number\"></div></section><p id=\"status\" aria-live=\"polite\"></p></form>"
        );
        let document = Html::parse_fragment(&markup);
        validate_query_form(
            document.select(&selector("form")).next().unwrap(),
            &catalog,
            "target",
        )
        .unwrap();

        let dynamic = markup.replacen(
            "value=\"550000000\"",
            "value=\"day2templatevalue000000end\"",
            1,
        );
        let document = Html::parse_fragment(&dynamic);
        validate_query_form_source(
            document.select(&selector("form")).next().unwrap(),
            &catalog,
            "target",
        )
        .unwrap();
        let dynamic_id =
            dynamic.replace("id=\"mirror\"", "id=\"mirror-day2templatevalue000000end\"");
        let document = Html::parse_fragment(&dynamic_id);
        assert!(
            validate_query_form_source(
                document.select(&selector("form")).next().unwrap(),
                &catalog,
                "target"
            )
            .is_err()
        );
        let duplicate =
            Html::parse_fragment(&format!("{markup}<datalist id=\"choices\"></datalist>"));
        assert!(
            crate::web_query_bindings::validate_document(
                &duplicate,
                duplicate.select(&selector("form")).next().unwrap()
            )
            .is_err()
        );
        let out_of_bounds = markup.replace("Initial off-step scenario\"></option>", "Initial off-step scenario\"></option><option value=\"60000000001\" label=\"Outside\"></option>");
        let document = Html::parse_fragment(&out_of_bounds);
        assert!(
            validate_query_form(
                document.select(&selector("form")).next().unwrap(),
                &catalog,
                "target"
            )
            .is_err()
        );
        let incomplete = markup.replace(
            "value=\"60000000000\" label=\"Market cap 595\"",
            "value=\"59999000000\" label=\"Market cap 595\"",
        );
        let document = Html::parse_fragment(&incomplete);
        assert!(
            validate_query_form(
                document.select(&selector("form")).next().unwrap(),
                &catalog,
                "target",
            )
            .is_err()
        );
        let bad_preset = markup.replace(
            "data-query-value=\"550000000\"",
            "data-query-value=\"555125000\"",
        );
        let document = Html::parse_fragment(&bad_preset);
        assert!(
            validate_query_form(
                document.select(&selector("form")).next().unwrap(),
                &catalog,
                "target",
            )
            .is_err()
        );
    }

    #[test]
    fn query_form_admission_and_binding_use_registered_route_contract() {
        let route_catalog = routes(false);
        let markup = r#"<form data-page="target"><input name="term" type="search"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#;
        let mut document = Html::parse_fragment(markup);
        let form = document.select(&selector("form")).next().unwrap();
        let id = form.id();
        validate_query_form(form, &route_catalog, "target").unwrap();
        bind_query_transport(&mut document, id, &route_catalog, "target").unwrap();
        let form = document.select(&selector("form")).next().unwrap();
        assert_eq!(form.value().attr("method"), Some("get"));
        assert_eq!(form.value().attr("action"), Some("/search"));
        assert_eq!(
            route_catalog
                .resolve("/search", "term=acme&archived=true&page=2")
                .unwrap()
                .unwrap()
                .1,
            serde_json::json!({"term":"acme","archived":true,"page":2})
        );
        assert_eq!(
            route_catalog
                .resolve("/search", "term=acme&page=2")
                .unwrap()
                .unwrap()
                .1,
            serde_json::json!({"term":"acme","archived":false,"page":2})
        );
        assert!(
            route_catalog
                .resolve("/search", "term=acme&term=other")
                .is_err()
        );
        assert!(
            route_catalog
                .resolve("/search", "term=acme&unknown=x")
                .is_err()
        );
    }

    #[test]
    fn query_forms_preserve_typed_hidden_fields_and_checked_flags() {
        let catalog = routes(false);
        for markup in [
            r#"<form data-page="target"><input name="term" type="hidden" value="hello"><input name="archived" type="checkbox" value="true" checked><select name="page"><option value="1">First</option><option value="2" selected>Second</option></select></form>"#,
            r#"<form data-page="target"><input name="term" type="search"><input name="archived" type="hidden" value="true"><input name="page" type="hidden" value="2"></form>"#,
        ] {
            let doc = Html::parse_fragment(markup);
            validate_query_form(
                doc.select(&selector("form")).next().unwrap(),
                &catalog,
                "target",
            )
            .unwrap();
        }
        for markup in [
            r#"<form data-page="target"><input name="term"><input name="page" type="hidden" value="two"></form>"#,
            r#"<form data-page="target"><input name="term"><input name="archived" type="hidden" value="yes"></form>"#,
            r#"<form data-page="target"><input name="term"><select name="page"><option value="two">Second</option></select></form>"#,
        ] {
            let doc = Html::parse_fragment(markup);
            assert!(
                validate_query_form(
                    doc.select(&selector("form")).next().unwrap(),
                    &catalog,
                    "target"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn query_forms_reject_browser_omission_and_noncanonical_checkbox_values() {
        let catalog = routes(false);
        for markup in [
            r#"<form data-page="target"><input name="term"><input name="archived" type="checkbox"></form>"#,
            r#"<form data-page="target"><input name="term"><input name="archived" type="checkbox" value="on"></form>"#,
            r#"<form data-page="target"><fieldset disabled><input name="term"></fieldset></form>"#,
            r#"<form data-page="target"><input name="term"><fieldset disabled><input name="archived" type="checkbox" value="true"></fieldset></form>"#,
            r#"<form data-page="target"><fieldset disabled><legend>First</legend><legend><input name="term"></legend></fieldset></form>"#,
        ] {
            let document = Html::parse_fragment(markup);
            let form = document.select(&selector("form")).next().unwrap();
            assert!(
                validate_query_form(form, &catalog, "target").is_err(),
                "{markup}"
            );
            assert!(
                validate_query_form_source(form, &catalog, "target").is_err(),
                "{markup}"
            );
        }
        let document = Html::parse_fragment(
            r#"<form data-page="target"><fieldset disabled><legend><input name="term"></legend></fieldset><input name="archived" type="checkbox" value="true" checked></form>"#,
        );
        let form = document.select(&selector("form")).next().unwrap();
        validate_query_form(form, &catalog, "target").unwrap();
        validate_query_form_source(form, &catalog, "target").unwrap();
        assert_eq!(
            catalog
                .resolve("/search", "term=acme&archived=true")
                .unwrap()
                .unwrap()
                .1,
            serde_json::json!({"term":"acme","archived":true,"page":1})
        );
    }

    #[test]
    fn named_control_budgets_distinguish_list_choices_from_field_names() {
        let markup = |count: usize, distinct: bool| {
            format!(
                "<form>{}</form>",
                (0..count)
                    .map(|index| format!(
                        "<input type='checkbox' name='{}' value='choice-{index}'>",
                        if distinct {
                            format!("field-{index}")
                        } else {
                            "choices".into()
                        },
                    ))
                    .collect::<String>()
            )
        };
        for (count, distinct, valid) in [
            (100, false, true),
            (MAX_FORM_CONTROLS, false, true),
            (MAX_FORM_CONTROLS + 1, false, false),
            (MAX_FORM_FIELDS, true, true),
            (MAX_FORM_FIELDS + 1, true, false),
        ] {
            let document = Html::parse_fragment(&markup(count, distinct));
            let form = document.select(&selector("form")).next().unwrap();
            assert_eq!(controls(form).is_ok(), valid, "{count} distinct={distinct}");
        }
        let document = Html::parse_fragment(&markup(100, false));
        let parsed = controls(document.select(&selector("form")).next().unwrap()).unwrap();
        let list = Kind::InputShape {
            shape: crate::output_schema::Type::List(Box::new(crate::output_schema::Type::String)),
            roc_type: "List(Str)".into(),
        };
        let group = parsed.iter().collect::<Vec<_>>();
        assert_eq!(
            native_field(&group, &list)
                .unwrap()
                .unwrap()
                .0
                .choices
                .len(),
            100
        );
        assert!(
            native_field(&group, &Kind::Text).is_err(),
            "fanout never admits a scalar checkbox field"
        );
    }

    #[test]
    fn native_choices_exclude_disabled_options_from_editable_ticket_authority() {
        let list = Kind::InputShape {
            shape: crate::output_schema::Type::List(Box::new(crate::output_schema::Type::String)),
            roc_type: "List(Str)".into(),
        };
        for (input_type, kind, expected_mode) in [
            ("checkbox", list, security::NativeMode::ListCheckbox),
            ("radio", Kind::Text, security::NativeMode::Radio),
        ] {
            let document = Html::parse_fragment(&format!(
                "<form><input type='{input_type}' name='field' value='blocked' checked disabled><input type='{input_type}' name='field' value='available' checked></form>"
            ));
            let controls = controls(document.select(&selector("form")).next().unwrap()).unwrap();
            let group = controls.iter().collect::<Vec<_>>();
            let (metadata, disabled) = native_field(&group, &kind).unwrap().unwrap();
            assert!(!disabled);
            assert_eq!(metadata.mode, expected_mode);
            assert_eq!(metadata.choices, ["available"]);
        }
    }

    #[test]
    fn native_disabled_fieldsets_preserve_the_first_legend_exception() {
        let document = Html::parse_fragment(
            "<form><fieldset disabled><legend>Context <input name='context' type='checkbox' value='true'></legend><input name='setting' type='checkbox' value='true' checked><fieldset><legend>Nested</legend><input name='nested' type='radio' value='one' checked></fieldset><legend>Later <input name='later' type='radio' value='two'></legend></fieldset></form>",
        );
        let controls = controls(document.select(&selector("form")).next().unwrap()).unwrap();
        assert_eq!(
            controls
                .iter()
                .map(|c| (c.name.as_str(), c.disabled))
                .collect::<Vec<_>>(),
            [
                ("context", false),
                ("setting", true),
                ("nested", true),
                ("later", true)
            ]
        );
        let (metadata, disabled) = native_field(&[&controls[1]], &Kind::Boolean)
            .unwrap()
            .unwrap();
        assert!(disabled);
        assert_eq!(metadata.mode, security::NativeMode::BooleanCheckbox);
        assert!(controls[1].checked);
        let invalid = Html::parse_fragment(
            "<form><fieldset disabled><input name='ordinary' type='text' value='fixed'></fieldset></form>",
        );
        assert!(super::controls(invalid.select(&selector("form")).next().unwrap()).is_err());
    }

    #[test]
    fn native_choices_keep_schema_and_duplicate_value_checks() {
        for markup in [
            "<input name='field' type='checkbox' value='same'><input name='field' type='checkbox' value='same' disabled>",
            "<input name='field' type='checkbox' value='true'><input name='field' type='text'>",
            "<input name='field' type='radio' value='one' checked><input name='field' type='radio' value='two' checked>",
        ] {
            let document = Html::parse_fragment(&format!("<form>{markup}</form>"));
            let controls = controls(document.select(&selector("form")).next().unwrap()).unwrap();
            assert!(native_field(&controls.iter().collect::<Vec<_>>(), &Kind::Text).is_err());
        }
    }

    #[test]
    fn query_form_dynamic_options_are_revalidated_after_source_projection() {
        let catalog = routes(false);
        let doc = Html::parse_fragment(
            r#"<form data-page="target"><input name="term"><select name="page"><option value="day2templatevalue0">Page</option></select></form>"#,
        );
        let form = doc.select(&selector("form")).next().unwrap();
        validate_query_form_source(form, &catalog, "target").unwrap();
        assert!(validate_query_form(form, &catalog, "target").is_err());
    }

    #[test]
    fn query_selects_admit_only_closed_literal_scalar_options() {
        let route_catalog = routes(false);
        let valid = Html::parse_fragment(
            r#"<form data-page="target"><select name="term"><option value="acme">Acme</option><option value="contoso">Contoso</option></select><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
        );
        validate_query_form(
            valid.select(&selector("form")).next().unwrap(),
            &route_catalog,
            "target",
        )
        .unwrap();
        for options in [
            r#"<option value="">Choose</option>"#,
            r#"<option value="same">One</option><option value="same">Two</option>"#,
            r#"<option value="day2templatevalue000000end">Dynamic</option>"#,
            r#"<option value="valid">   </option>"#,
        ] {
            let markup = format!(
                r#"<form data-page="target"><select name="term">{options}</select><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#
            );
            let document = Html::parse_fragment(&markup);
            assert!(
                validate_query_form(
                    document.select(&selector("form")).next().unwrap(),
                    &route_catalog,
                    "target"
                )
                .is_err(),
                "{markup}"
            );
        }
    }

    #[test]
    fn query_forms_reject_ambiguous_or_unsafe_declarations() {
        let route_catalog = routes(false);
        for markup in [
            r#"<form data-page="target"><input name="term"><input name="unknown"></form>"#,
            r#"<form data-page="target"><input name="page" type="number"></form>"#,
            r#"<form data-page="target"><input name="term"><input name="term"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
            r#"<form data-page="target" data-command="update"><input name="term"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
            r#"<form data-page="target" data-platform="sign-out"><input name="term"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
            r#"<form data-page="target" action="/actions"><input name="term"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
            r#"<form data-page="target" method="post"><input name="term"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
            r#"<form data-page="target" enctype="text/plain"><input name="term"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
            r#"<form data-page="target" target="_blank"><input name="term"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
            r#"<form data-page="target"><input name="term" type="checkbox"><input name="archived" type="checkbox" value="true"><input name="page" type="number"></form>"#,
        ] {
            let document = Html::parse_fragment(markup);
            let parsed = document.select(&selector("form")).next().unwrap();
            assert!(
                validate_query_form(parsed, &route_catalog, "target").is_err(),
                "{markup}"
            );
        }
        let route_catalog = routes(true);
        let document = Html::parse_fragment(r#"<form data-page="target"><input name="id"></form>"#);
        let parsed = document.select(&selector("form")).next().unwrap();
        assert!(
            format!(
                "{:#}",
                validate_query_form(parsed, &route_catalog, "target").unwrap_err()
            )
            .contains("path_page_form_unsupported")
        );
        let document = Html::parse_fragment(r#"<form data-page="missing"></form>"#);
        assert!(
            validate_query_form(
                document.select(&selector("form")).next().unwrap(),
                &route_catalog,
                "missing"
            )
            .is_err()
        );
    }
}

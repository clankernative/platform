//! Requirement-specific invocation handles. Neither the generic transport nor
//! the private constructors survive both native admission profiles.
use anyhow::{Result, ensure};
use day2_capabilities::oauth::ConnectionDeclaration;
use std::collections::BTreeSet;

pub const MODULE: &str = "Connections.roc";
pub const RESOLVE: &str = "connection.resolve.v1";
pub const LIST_EVENTS: &str = "google_calendar.list_events.v1";
pub const USE_PREFIX: &str = "Day2ConnectionUse_";

pub fn invocation_type(name: &str) -> bool {
    name.strip_prefix("Connections.")
        .unwrap_or(name)
        .starts_with(USE_PREFIX)
}

pub fn module(declarations: &[ConnectionDeclaration], admission: bool) -> Result<String> {
    let prefix = if admission { "admission_" } else { "" };
    let mut source = String::from(
        "import pf.Connection\nimport pf.Observe\nimport pf.GoogleCalendar\n\nConnections :: [].{\n",
    );
    let mut seen = BTreeSet::new();
    for declaration in declarations {
        let name = declaration.registration.as_str();
        day2_contracts::names::identifier(name)?;
        ensure!(
            seen.insert(name) && seen.len() <= 64,
            "connection registration budget"
        );
        declaration.requirement.validate()?;
        let identity = declaration.requirement.nominal_identity()?;
        let nominal = format!(
            "{USE_PREFIX}{}",
            identity.as_str().trim_start_matches("sha256:")
        );
        append(
            &mut source,
            name,
            &nominal,
            prefix,
            false,
            declaration.requirement.capability == "google_calendar_events"
                && declaration.requirement.actions.contains("list_events"),
        )?;
    }
    source.push_str("}\n");
    Ok(source)
}

/// Only discover callback types. These clients cannot execute provider reads
/// and are replaced with the checked declaration inventory before admission.
pub fn provisional_module<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<String> {
    let mut source = String::from(
        "import pf.Connection\nimport pf.Observe\nimport pf.GoogleCalendar\n\nConnections :: [].{\n",
    );
    let mut seen = BTreeSet::new();
    for name in names {
        day2_contracts::names::identifier(name)?;
        ensure!(
            seen.insert(name) && seen.len() <= 64,
            "connection registration budget"
        );
        append(
            &mut source,
            name,
            &format!("{USE_PREFIX}inference_{name}"),
            "",
            true,
            true,
        )?;
    }
    source.push_str("}\n");
    Ok(source)
}

fn append(
    source: &mut String,
    name: &str,
    nominal: &str,
    prefix: &str,
    provisional: bool,
    calendar: bool,
) -> Result<()> {
    source.push_str(&format!(
        "    {nominal} :: {{ reference : Str }}.{{}}\n\n    Use_{name} : {nominal}\n\n"
    ));
    let resolve = if provisional {
        "|_| Observe.value(Unavailable(BindingUnavailable))".to_owned()
    } else {
        format!("|_| {prefix}day2_resolve_{name}({{}})")
    };
    let mut fields = format!("resolve : {{}} -> Observe(Connection.Resolution(Use_{name}))");
    let mut values = format!("resolve: {resolve}");
    if calendar {
        fields.push_str(&format!(", list_events : Use_{name}, GoogleCalendar.Window -> Observe(GoogleCalendar.ListOutcome)"));
        let list = if provisional {
            "|_use, _window| Observe.value(Unavailable(BindingUnavailable))".into()
        } else {
            format!("|connection, window| {prefix}day2_list_{name}(connection, window)")
        };
        values.push_str(&format!(", list_events: {list}"));
    }
    source.push_str(&format!(
        "    {name} : {{ {fields} }}\n    {name} = {{ {values} }}\n\n"
    ));
    if !provisional {
        source.push_str(&format!(
            "    {prefix}day2_wrap_{name} : Str -> Use_{name}\n    {prefix}day2_wrap_{name} = |reference| {{ reference: reference }}\n\n"
        ));
        source.push_str(&format!(
            "    {prefix}day2_resolve_{name} : {{}} -> Observe(Connection.Resolution(Use_{name}))\n    {prefix}day2_resolve_{name} = |_| Connection.{prefix}resolve(\"{name}\").map(|resolution| match resolution {{\n        Available(reference) => Available({prefix}day2_wrap_{name}(reference))\n        Unavailable(problem) => Unavailable(problem)\n    }})\n\n"
        ));
        if calendar {
            source.push_str(&format!(
                "    {prefix}day2_list_{name} : Use_{name}, GoogleCalendar.Window -> Observe(GoogleCalendar.ListOutcome)\n    {prefix}day2_list_{name} = |connection, window| GoogleCalendar.{prefix}list_events(\"{name}\", connection.reference, window)\n\n"
            ));
        }
    }
    Ok(())
}

pub fn probe(catalog: &crate::registry::Catalog) -> String {
    let declarations = catalog.connections.keys().map(|name| format!(
        "{{ registration: \"{name}\", requirement: App.definition.connections.{name}.metadata() }}"
    )).collect::<Vec<_>>().join(", ");
    format!(
        "app [step] {{ pf: platform \"../sdk/main.roc\" }}\nimport App\nstep : Str -> Str\nstep = |_| Json.to_str([{declarations}])\n"
    )
}

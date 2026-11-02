//! Family-specific metadata clients, regenerated for both admission profiles.
use anyhow::{Context, Result, ensure};
use day2_capabilities::credentials::{GrantMode, ManifestFamily};
use std::collections::BTreeSet;

pub const MODULE: &str = "Credentials.roc";
pub const LIST: &str = "credential.metadata.list.v1";
pub const INSPECT: &str = "credential.metadata.inspect.v1";
pub const ISSUE: &str = "credential.issue.v1";
pub const ROTATE: &str = "credential.rotate.v1";
pub const REVOKE: &str = "credential.revoke.v1";

pub fn observation(name: &str) -> bool {
    [LIST, INSPECT].contains(&name)
}

/// Shape only. The reader checks namespace, family, policy and principal.
pub fn cursor_shape(raw: &str) -> bool {
    let Some(value) = raw.strip_prefix("cm1_") else {
        return false;
    };
    !value.is_empty()
        && raw.len() <= 2200
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn module(families: &[ManifestFamily], admission: bool) -> Result<String> {
    render(
        families.iter().map(|family| {
            (
                family.registration.as_str(),
                Some(family),
                Some(&family.grant),
            )
        }),
        admission,
        false,
    )
}

/// Inference needs exact nominal signatures without executable host programs.
/// The checked catalog replaces these handles before both admission checks.
pub fn provisional_module<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<String> {
    render(
        names.into_iter().map(|name| (name, None, None)),
        false,
        true,
    )
}

/// Close callback shapes from compiler-checked mode witnesses before compiling
/// the pure probe. These stubs cannot execute an app lifecycle action.
pub fn probe_module(catalog: &crate::registry::Catalog) -> Result<String> {
    render(
        catalog
            .credentials
            .iter()
            .map(|(name, registration)| (name.as_str(), None, Some(&registration.grant))),
        false,
        true,
    )
}

/// Evaluate only pure App.definition metadata, never an application handler.
pub fn probe(catalog: &crate::registry::Catalog) -> String {
    let projection = crate::credential_declaration::projection(catalog, "product");
    let mut operations = Vec::new();
    for (kind, definitions) in [("command", &catalog.commands), ("query", &catalog.queries)] {
        for name in definitions.keys() {
            let execution = crate::app_contract::execution_projection("operation", kind);
            operations.push(format!("{{\n        operation = product.operations.{name}\n        {execution}\n        {{ operation: product.namespace.concat(\".{name}\"), definition: {{ execution: execution_metadata, credential_access: operation.credential_access(), required_all_rows: operation.required_all_rows(), export_version: operation.export_version() }} }}\n}}"));
        }
    }
    let operations = operations.join(", ");
    format!(
        "app [step] {{ pf: platform \"../sdk/main.roc\" }}\nimport App\nimport pf.Api\nstep : Str -> Str\nstep = |_| {{\n    product = App.definition\n    Json.to_str({{ families: {projection}, operations: [{operations}] }})\n}}\n"
    )
}

fn render<'a>(
    families: impl IntoIterator<Item = (&'a str, Option<&'a ManifestFamily>, Option<&'a GrantMode>)>,
    admission: bool,
    provisional: bool,
) -> Result<String> {
    let prefix = if admission { "admission_" } else { "" };
    let mut source = String::from(
        "import pf.Observe\nimport pf.Tx\nimport pf.InteractiveContext\nimport pf.Credential\nimport pf.Cursor as PlatformCursor\nimport pf.PageSize\nimport pf.CollectionPage\nimport pf.TextSet\n\nCredentials :: [].{\n",
    );
    let mut seen = BTreeSet::new();
    for (name, family, mode) in families {
        day2_contracts::names::identifier(name)?;
        if let Some(family) = family {
            family.verify()?;
            for root in family.roots.keys() {
                let (namespace, operation) = root
                    .split_once('.')
                    .context("unqualified credential option")?;
                day2_contracts::names::identifier(namespace)?;
                day2_contracts::names::identifier(operation)?;
            }
            ensure!(
                matches!(
                    family.profile,
                    day2_capabilities::credentials::ManagedProfile::Client
                        | day2_capabilities::credentials::ManagedProfile::Personal
                ),
                "unsupported generated credential profile"
            );
        }
        ensure!(seen.insert(name), "duplicate generated credential family");
        ensure!(seen.len() <= 64, "generated credential family budget");
        // Concrete nominals avoid return-only phantom specialization in the
        // pinned compiler. Exact labels prevent lowered-name collisions.
        let selectable = mode.is_none_or(|mode| *mode == GrantMode::Selectable);
        let mut common = COMMON.to_owned();
        if selectable {
            common.push_str(SELECTABLE);
            let roots = family
                .map(|family| family.roots.keys().collect::<Vec<_>>())
                .unwrap_or_default();
            common = common.replace("$ROOTS$", &serde_json::to_string(&roots)?);
            common = common.replace(
                "$CONTRACT$",
                family.map(|family| family.contract.as_str()).unwrap_or(""),
            );
        }
        let mut body = common
            .split_once("Credentials :: [].{\n")
            .unwrap()
            .1
            .replace("$PREFIX$", prefix);
        for ty in [
            "ManagementSnapshot",
            "VersionRef",
            "ListRequest",
            "Inspection",
            "Summary",
            "Cursor",
            "Page",
            "Ref",
            "Issued",
            "RotationOutcome",
            "RevocationOutcome",
            "GrantOption",
            "GrantSelection",
            "RotationChoice",
        ] {
            body = body.replace(&format!("{ty}(family)"), &format!("{ty}_{name}"));
        }
        body = body
            .replace(", witness : List(family)", "")
            .replace(", witness: []", "");
        for ty in [
            "ManagementState",
            "ListFailure",
            "InspectionFailure",
            "WireSummary",
            "WirePage",
            "WireInspection",
            "SelectionWire",
            "RotationWire",
        ] {
            body = body.replace(ty, &format!("{ty}_{name}"));
        }
        for function in [
            "cursor_from_str",
            "ref_from_str",
            "decode_summary",
            "read_list",
            "read_inspect",
            "issue_fixed",
            "rotate_fixed",
            "rotate_selected",
            "rotate_request",
            "revoke_lineage",
            "snapshot_from_parts",
            "selection_from_options",
            "selection_from_str",
            "issue_selected",
            "issue_request",
            "known_grant_root",
            "valid_grant_contract",
            "rotation_from_str",
            "rotation_to_str",
            "rotation_to_wire",
        ] {
            body = body.replace(function, &format!("day2_{function}_{name}"));
        }
        source.push_str(&body);
        let list = if provisional {
            "|_request| Observe.value(Err(Unavailable))".into()
        } else {
            format!("|request| {prefix}day2_read_list_{name}(\"{name}\", request)")
        };
        let inspect = if provisional {
            "|_request| Observe.value(Err(Unavailable))".into()
        } else {
            format!("|request| {prefix}day2_read_inspect_{name}(\"{name}\", request.lineage)")
        };
        let issue = if provisional {
            "|_context, _request| Tx.host_reject(\"credential_issuance_unavailable\")".into()
        } else if selectable {
            format!(
                "|context, request| {prefix}day2_issue_selected_{name}(\"{name}\", context, request.label, request.grant)"
            )
        } else {
            format!(
                "|context, request| {prefix}day2_issue_fixed_{name}(\"{name}\", context, request.label)"
            )
        };
        let rotate = if provisional {
            "|_context, _request| Tx.host_reject(\"credential_rotation_unavailable\")".into()
        } else if selectable {
            format!("|context, request| {prefix}day2_rotate_selected_{name}(\"{name}\", context, request.expected, request.grant)")
        } else {
            format!(
                "|context, request| {prefix}day2_rotate_fixed_{name}(\"{name}\", context, request.expected)"
            )
        };
        let revoke = if provisional {
            "|_context, _request| Tx.host_reject(\"credential_revocation_unavailable\")".into()
        } else {
            format!(
                "|context, request| {prefix}day2_revoke_lineage_{name}(\"{name}\", context, request.lineage)"
            )
        };
        let issue_input = if provisional && mode.is_none() {
            "_".to_owned()
        } else if selectable {
            format!("{{ label : Credential.Label, grant : GrantSelection_{name} }}")
        } else {
            "{ label : Credential.Label }".to_owned()
        };
        let rotation_input = if provisional && mode.is_none() {
            "_".to_owned()
        } else if selectable {
            format!("{{ expected : ManagementSnapshot_{name}, grant : RotationChoice_{name} }}")
        } else {
            format!("{{ expected : ManagementSnapshot_{name} }}")
        };
        let (selection_fields, selection_values) = if selectable {
            (
                format!(
                    ", grant_options : List(GrantOption_{name}), selection_from_options : List(GrantOption_{name}) -> Try(GrantSelection_{name}, [InvalidGrantSelection]), selection_from_str : Str -> Try(GrantSelection_{name}, [InvalidGrantSelection]), rotation_from_str : Str -> Try(RotationChoice_{name}, [InvalidRotationGrant]), rotation_to_str : RotationChoice_{name} -> Str"
                ),
                format!(
                    "        grant_options: {},\n        selection_from_options: day2_selection_from_options_{name},\n        selection_from_str: day2_selection_from_str_{name},\n        rotation_from_str: day2_rotation_from_str_{name},\n        rotation_to_str: day2_rotation_to_str_{name},\n",
                    family
                        .map(|family| format!(
                            "{}.map(|root| {{ family_contract: \"{}\", root }})",
                            serde_json::to_string(&family.roots.keys().collect::<Vec<_>>())
                                .expect("root DATA serializes"),
                            family.contract.as_str()
                        ))
                        .unwrap_or("[]".into())
                ),
            )
        } else {
            (String::new(), String::new())
        };
        let family_api = format!(
            "    {name} : {{ issue : InteractiveContext, {issue_input} -> Tx(Issued_{name}), rotate : InteractiveContext, {rotation_input} -> Tx(RotationOutcome_{name}), revoke : InteractiveContext, {{ lineage : Ref_{name} }} -> Tx(RevocationOutcome_{name}), snapshot_from_parts : {{ lineage : Ref_{name}, head : Str, revision : U64 }} -> Try(ManagementSnapshot_{name}, [InvalidSnapshot]), list : ListRequest_{name} -> Observe(Try(Page_{name}, ListFailure_{name})), inspect : {{ lineage : Ref_{name} }} -> Observe(Try(Inspection_{name}, InspectionFailure_{name})), start : Cursor_{name}, cursor_from_str : Str -> Try(Cursor_{name}, [InvalidCursor]), ref_from_str : Str -> Try(Ref_{name}, [InvalidRef]){selection_fields} }}\n    {name} = {{\n        issue: {issue},\n        rotate: {rotate},\n        revoke: {revoke},\n        snapshot_from_parts: day2_snapshot_from_parts_{name},\n        list: {list},\n        inspect: {inspect},\n        start: {{ value: PlatformCursor.start }},\n        cursor_from_str: |raw| day2_cursor_from_str_{name}(\"{name}\", raw),\n        ref_from_str: |raw| day2_ref_from_str_{name}(\"{name}\", raw),\n{selection_values}    }}\n\n"
        );
        source.push_str(&family_api);
    }
    source.push_str("}\n");
    Ok(source)
}

const COMMON: &str = r#"import pf.Observe
import pf.Cursor as PlatformCursor
import pf.PageSize
import pf.CollectionPage

# Generated safe metadata. Decoding proves shape, never visibility or authority.
Credentials :: [].{
    RotationOutcome(family) : [Rotated(Issued(family)), Conflict]
    RevocationOutcome(family) : [Revoked({ lineage : Ref(family), revision : U64 }), AlreadyRevoked({ lineage : Ref(family), revision : U64 })]

    # Pure shape codec for a stale-able management precondition, never authority.
    snapshot_from_parts : { lineage : Ref(family), head : Str, revision : U64 } -> Try(ManagementSnapshot(family), [InvalidSnapshot])
    snapshot_from_parts = |parts| {
        if parts.revision == 0 or parts.head.is_empty() or parts.head.count_utf8_bytes() > 160 or !parts.head.to_utf8().all(|byte| (byte >= 48 and byte <= 57) or (byte >= 65 and byte <= 90) or (byte >= 97 and byte <= 122) or byte == 45 or byte == 95) {
            return Err(InvalidSnapshot)
        }
        Ok({ lineage: parts.lineage, head: { lineage: parts.lineage, id: parts.head }, revision: parts.revision, state: Active })
    }

    $PREFIX$rotate_fixed : Str, InteractiveContext, ManagementSnapshot(family) -> Tx(RotationOutcome(family))
    $PREFIX$rotate_fixed = |registration, context, expected| $PREFIX$rotate_request(registration,
        Json.to_str({ registration, invocation: context.invocation_id(), lineage: expected.lineage().to_str(), head: expected.head().id(), revision: expected.revision(), grant: { mode: "fixed", selections: [] } }),
    )

    $PREFIX$rotate_request : Str, Str -> Tx(RotationOutcome(family))
    $PREFIX$rotate_request = |registration, input| Tx.$PREFIX$capability(
        "credential_rotate", "credential.rotate.v1", input,
    ).and_then(|raw| {
        parsed : Try({ conflict : Bool, lineage : Str, version : Str, label : Str, expires_at : I64 }, _)
        parsed = Json.parse(raw)
        Tx.$PREFIX$from_host(parsed.map_err(|_| "invalid_credential_rotation")).and_then(|wire| {
            if wire.conflict { return Tx.succeed(Conflict) }
            decoded = ref_from_str(registration, wire.lineage).map_err(|_| "invalid_credential_rotation")
            Tx.$PREFIX$from_host(decoded).map(|lineage| Rotated({ lineage, version: { lineage, id: wire.version }, label: wire.label, expires_at: wire.expires_at }))
        })
    })

    $PREFIX$revoke_lineage : Str, InteractiveContext, Ref(family) -> Tx(RevocationOutcome(family))
    $PREFIX$revoke_lineage = |registration, context, lineage| Tx.$PREFIX$capability(
        "credential_revoke", "credential.revoke.v1",
        Json.to_str({ registration, invocation: context.invocation_id(), lineage: lineage.to_str() }),
    ).and_then(|raw| {
        parsed : Try({ already_revoked : Bool, lineage : Str, revision : U64 }, _)
        parsed = Json.parse(raw)
        Tx.$PREFIX$from_host(parsed.map_err(|_| "invalid_credential_revocation")).and_then(|wire| {
            decoded = ref_from_str(registration, wire.lineage).map_err(|_| "invalid_credential_revocation")
            Tx.$PREFIX$from_host(decoded).map(|reference| {
                result = { lineage: reference, revision: wire.revision }
                if wire.already_revoked { AlreadyRevoked(result) } else { Revoked(result) }
            })
        })
    })

    Issued(family) :: { lineage : Ref(family), version : VersionRef(family), label : Str, expires_at : I64 }.{
        lineage : Issued(family) -> Ref(family)
        lineage = |issued| issued.lineage

        version : Issued(family) -> VersionRef(family)
        version = |issued| issued.version

        label : Issued(family) -> Str
        label = |issued| issued.label

        expires_at : Issued(family) -> I64
        expires_at = |issued| issued.expires_at
    }

    $PREFIX$issue_fixed : Str, InteractiveContext, Credential.Label -> Tx(Issued(family))
    $PREFIX$issue_fixed = |registration, context, label| $PREFIX$issue_request(registration,
        Json.to_str({ registration, invocation: context.invocation_id(), label: label.to_str(), grant: { mode: "fixed" } }),
    )

    $PREFIX$issue_request : Str, Str -> Tx(Issued(family))
    $PREFIX$issue_request = |registration, request| Tx.$PREFIX$capability(
        "credential_issue", "credential.issue.v1",
        request,
    ).and_then(|raw| {
        parsed : Try({ lineage : Str, version : Str, label : Str, expires_at : I64 }, _)
        parsed = Json.parse(raw)
        Tx.$PREFIX$from_host(parsed.map_err(|_| "invalid_credential_issuance")).and_then(|wire| {
            decoded = ref_from_str(registration, wire.lineage).map_err(|_| "invalid_credential_issuance")
            Tx.$PREFIX$from_host(decoded).map(|lineage| {
                { lineage, version: { lineage, id: wire.version }, label: wire.label, expires_at: wire.expires_at }
            })
        })
    })

    Ref(family) :: { value : Str, witness : List(family) }.{
        to_str : Ref(family) -> Str
        to_str = |reference| reference.value

        is_eq : Ref(family), Ref(family) -> Bool
        is_eq = |left, right| left.value == right.value
    }

    Cursor(family) :: { value : PlatformCursor, witness : List(family) }.{
        to_str : Cursor(family) -> Str
        to_str = |cursor| cursor.value.to_str()

        is_eq : Cursor(family), Cursor(family) -> Bool
        is_eq = |left, right| PlatformCursor.is_eq(left.value, right.value)
    }

    VersionRef(family) :: { lineage : Ref(family), id : Str }.{
        lineage : VersionRef(family) -> Ref(family)
        lineage = |version| version.lineage

        id : VersionRef(family) -> Str
        id = |version| version.id
    }

    ManagementState : [Active, Rotating, Revoked]
    ListFailure : [Denied, InvalidCursor, Unavailable, Throttled]
    InspectionFailure : [NotVisible, Unavailable, Throttled]
    ListRequest(family) : { after : Cursor(family), limit : PageSize }
    Summary(family) : {
        lineage : Ref(family), current_version : VersionRef(family), label : [None, Some(Str)],
        principal : Str, state : ManagementState, grant : Str, expires_at : I64,
    }

    ManagementSnapshot(family) :: {
        lineage : Ref(family), head : VersionRef(family), revision : U64, state : ManagementState,
    }.{
        lineage : ManagementSnapshot(family) -> Ref(family)
        lineage = |snapshot| snapshot.lineage

        head : ManagementSnapshot(family) -> VersionRef(family)
        head = |snapshot| snapshot.head

        revision : ManagementSnapshot(family) -> U64
        revision = |snapshot| snapshot.revision

        state : ManagementSnapshot(family) -> ManagementState
        state = |snapshot| snapshot.state
    }

    Inspection(family) : { summary : Summary(family), rotation : [None, Some(ManagementSnapshot(family))] }

    Page(family) :: { value : CollectionPage(Summary(family)) }.{
        items : Page(family) -> List(Summary(family))
        items = |page| page.value.items()

        has_more : Page(family) -> Bool
        has_more = |page| page.value.has_more()

        next_after : Page(family) -> Cursor(family)
        next_after = |page| { value: page.value.next_after(), witness: [] }

        map : Page(family), (Summary(family) -> output) -> CollectionPage(output)
        map = |page, transform| page.value.map(transform)
    }

    cursor_from_str : Str, Str -> Try(Cursor(family), [InvalidCursor])
    cursor_from_str = |registration, raw| {
        if !raw.is_empty() and (!raw.starts_with("cm1_${registration}_") or raw.count_utf8_bytes() <= "cm1_${registration}_".count_utf8_bytes()) { return Err(InvalidCursor) }
        value = PlatformCursor.from_str(raw)?
        Ok({ value: value, witness: [] })
    }

    ref_from_str : Str, Str -> Try(Ref(family), [InvalidRef])
    ref_from_str = |registration, raw| {
        bytes = raw.to_utf8()
        prefix = "cr1_${registration}_"
        if !raw.starts_with(prefix) or bytes.len() <= prefix.to_utf8().len() or bytes.len() > 2048 {
            return Err(InvalidRef)
        }
        if !bytes.all(|byte| (byte >= 48 and byte <= 57) or (byte >= 65 and byte <= 90) or (byte >= 97 and byte <= 122) or byte == 95 or byte == 45) {
            return Err(InvalidRef)
        }
        Ok({ value: raw, witness: [] })
    }

    WireSummary : {
        lineage : Str, version : Str, label : List(Str), principal : Str, state : Str, grant : Str, expires_at : I64,
    }
    WirePage : { error : Str, items : List(WireSummary), has_more : Bool, next_after : Str }
    WireInspection : { error : Str, items : List(WireSummary), revisions : List(U64) }

    decode_summary : Str, WireSummary -> Try(Summary(family), Str)
    decode_summary = |registration, raw| {
        lineage = ref_from_str(registration, raw.lineage).map_err(|_| "invalid_credential_metadata")?
        state = match raw.state {
            "active" => Active
            "rotating" => Rotating
            "revoked" => Revoked
            _ => return Err("invalid_credential_metadata")
        }
        label = match raw.label {
            [] => None
            [value] => Some(value)
            _ => return Err("invalid_credential_metadata")
        }
        if raw.version.is_empty() or raw.version.count_utf8_bytes() > 128 { return Err("invalid_credential_metadata") }
        Ok({ lineage, current_version: { lineage, id: raw.version }, label, principal: raw.principal, state, grant: raw.grant, expires_at: raw.expires_at })
    }

    # These host constructors disappear in the restricted admission profile.
    # Only the registered family adapters below retain their public names.
    $PREFIX$read_list : Str, ListRequest(family) -> Observe(Try(Page(family), ListFailure))
    $PREFIX$read_list = |registration, request| Observe.$PREFIX$capability(
        "credential.metadata.list.v1",
        Json.to_str({ registration, after: request.after.to_str(), limit: request.limit.to_i64() }),
    ).and_then(|raw| {
        parsed : Try(WirePage, _)
        parsed = Json.parse(raw)
        Observe.$PREFIX$from_host(parsed.map_err(|_| "invalid_credential_metadata")).and_then(|wire| {
            if !wire.error.is_empty() {
                return Observe.value(Err(match wire.error {
                    "denied" => Denied
                    "invalid_cursor" => InvalidCursor
                    "throttled" => Throttled
                    _ => Unavailable
                }))
            }
            decoded = wire.items.map_try(|item| decode_summary(registration, item))
            Observe.$PREFIX$from_host(decoded).and_then(|items| {
                next = cursor_from_str(registration, wire.next_after).map_err(|_| "invalid_credential_metadata")
                Observe.$PREFIX$from_host(next).and_then(|cursor| {
                    page = CollectionPage.from_parts(items, wire.has_more, cursor.value)
                    Observe.$PREFIX$from_host(page).map(|value| Ok({ value: value }))
                })
            })
        })
    })

    $PREFIX$read_inspect : Str, Ref(family) -> Observe(Try(Inspection(family), InspectionFailure))
    $PREFIX$read_inspect = |registration, lineage| Observe.$PREFIX$capability(
        "credential.metadata.inspect.v1", Json.to_str({ registration, lineage: lineage.to_str() }),
    ).and_then(|raw| {
        parsed : Try(WireInspection, _)
        parsed = Json.parse(raw)
        Observe.$PREFIX$from_host(parsed.map_err(|_| "invalid_credential_metadata")).and_then(|wire| {
            if !wire.error.is_empty() {
                return Observe.value(Err(match wire.error {
                    "not_visible" => NotVisible
                    "throttled" => Throttled
                    _ => Unavailable
                }))
            }
            decoded = match wire.items {
                [item] => decode_summary(registration, item)
                _ => Err("invalid_credential_metadata")
            }
            Observe.$PREFIX$from_host(decoded).and_then(|summary| {
                rotation = match wire.revisions {
                    [] => Ok(None)
                    [revision] if revision > 0 => Ok(Some({ lineage: summary.lineage, head: summary.current_version, revision, state: summary.state }))
                    _ => Err("invalid_credential_metadata")
                }
                Observe.$PREFIX$from_host(rotation).map(|snapshot| Ok({ summary, rotation: snapshot }))
            })
        })
    })

"#;

// Only selectable families receive these nominal DATA types and pure codecs.
// Static options carry the full canonical authority contract derived by the
// pure compiler probe and compared with the final admitted worker.
const SELECTABLE: &str = r#"
    GrantOption(family) :: { family_contract : Str, root : Str }.{
        operation : GrantOption(family) -> Str
        operation = |option| option.root
    }

    SelectionWire : { family_contract : Str, roots : List(Str) }

    GrantSelection(family) :: { value : SelectionWire }.{
        to_str : GrantSelection(family) -> Str
        to_str = |selection| Json.to_str(selection.value)

        options : GrantSelection(family) -> List(GrantOption(family))
        options = |selection| selection.value.roots.map(|root| { family_contract: selection.value.family_contract, root })
    }

    RotationChoice(family) : [KeepExisting, Narrow(GrantSelection(family))]
    RotationWire : { mode : Str, selections : List(SelectionWire) }

    rotation_to_wire : RotationChoice(family) -> RotationWire
    rotation_to_wire = |choice| match choice {
        KeepExisting => { mode: "keep_existing", selections: [] }
        Narrow(selection) => { mode: "narrow", selections: [selection.value] }
    }

    rotation_to_str : RotationChoice(family) -> Str
    rotation_to_str = |choice| Json.to_str(rotation_to_wire(choice))

    rotation_from_str : Str -> Try(RotationChoice(family), [InvalidRotationGrant])
    rotation_from_str = |raw| {
        if raw.count_utf8_bytes() > 16384 { return Err(InvalidRotationGrant) }
        parsed : Try(RotationWire, _)
        parsed = Json.parse(raw)
        wire = parsed.map_err(|_| InvalidRotationGrant)?
        choice = match (wire.mode, wire.selections) {
            ("keep_existing", []) => KeepExisting
            ("narrow", [selection]) => Narrow(selection_from_str(Json.to_str(selection)).map_err(|_| InvalidRotationGrant)?)
            _ => return Err(InvalidRotationGrant)
        }
        if rotation_to_str(choice) != raw { return Err(InvalidRotationGrant) }
        Ok(choice)
    }

    $PREFIX$rotate_selected : Str, InteractiveContext, ManagementSnapshot(family), RotationChoice(family) -> Tx(RotationOutcome(family))
    $PREFIX$rotate_selected = |registration, context, expected, choice| $PREFIX$rotate_request(registration,
        Json.to_str({ registration, invocation: context.invocation_id(), lineage: expected.lineage().to_str(), head: expected.head().id(), revision: expected.revision(), grant: rotation_to_wire(choice) }),
    )

    known_grant_root : Str -> Bool
    known_grant_root = |root| $ROOTS$.any(|known| known == root)

    valid_grant_contract : Str -> Bool
    valid_grant_contract = |contract| {
        contract.starts_with("sha256:") and contract.count_utf8_bytes() == 71 and
            contract.drop_prefix("sha256:").to_utf8().all(|byte| (byte >= 48 and byte <= 57) or (byte >= 97 and byte <= 102))
    }

    selection_from_options : List(GrantOption(family)) -> Try(GrantSelection(family), [InvalidGrantSelection])
    selection_from_options = |options| {
        first = match options {
            [head, ..] => head
            [] => return Err(InvalidGrantSelection)
        }
        if options.len() > 64 or first.family_contract != "$CONTRACT$" or !valid_grant_contract(first.family_contract) or !options.all(|option| option.family_contract == first.family_contract and known_grant_root(option.root)) {
            return Err(InvalidGrantSelection)
        }
        canonical = TextSet.from_list(options.map(|option| option.root)).map_err(|_| InvalidGrantSelection)?
        Ok({ value: { family_contract: first.family_contract, roots: canonical.to_list() } })
    }

    selection_from_str : Str -> Try(GrantSelection(family), [InvalidGrantSelection])
    selection_from_str = |raw| {
        if raw.count_utf8_bytes() > 8192 { return Err(InvalidGrantSelection) }
        parsed : Try(SelectionWire, _)
        parsed = Json.parse(raw)
        wire = parsed.map_err(|_| InvalidGrantSelection)?
        options = wire.roots.map(|root| { family_contract: wire.family_contract, root })
        selected = selection_from_options(options)?
        # Accept only our complete canonical encoding. Unknown/duplicate JSON
        # members or discarded input cannot silently become typed selection.
        if Json.to_str(selected.value) != raw { return Err(InvalidGrantSelection) }
        Ok(selected)
    }

    $PREFIX$issue_selected : Str, InteractiveContext, Credential.Label, GrantSelection(family) -> Tx(Issued(family))
    $PREFIX$issue_selected = |registration, context, label, selection| $PREFIX$issue_request(registration,
        Json.to_str({ registration, invocation: context.invocation_id(), label: label.to_str(), grant: { mode: "selected", selection: selection.value } }),
    )

"#;

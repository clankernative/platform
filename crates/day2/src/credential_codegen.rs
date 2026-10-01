//! Family-specific metadata clients, regenerated for both admission profiles.
use anyhow::{Result, ensure};
use std::collections::BTreeSet;

pub const MODULE: &str = "Credentials.roc";
pub const LIST: &str = "credential.metadata.list.v1";
pub const INSPECT: &str = "credential.metadata.inspect.v1";
pub const ISSUE: &str = "credential.issue.v1";

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

pub fn module<'a>(names: impl IntoIterator<Item = &'a str>, admission: bool) -> Result<String> {
    render(names, admission, false)
}

/// Inference needs exact nominal signatures without executable host programs.
/// The checked catalog replaces these handles before both admission checks.
pub fn provisional_module<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<String> {
    render(names, false, true)
}

fn render<'a>(
    names: impl IntoIterator<Item = &'a str>,
    admission: bool,
    provisional: bool,
) -> Result<String> {
    let prefix = if admission { "admission_" } else { "" };
    let mut source = String::from(
        "import pf.Observe\nimport pf.Tx\nimport pf.InteractiveContext\nimport pf.Credential\nimport pf.Cursor as PlatformCursor\nimport pf.PageSize\nimport pf.CollectionPage\n\nCredentials :: [].{\n",
    );
    let mut seen = BTreeSet::new();
    for name in names {
        crate::schema::identifier(name)?;
        ensure!(seen.insert(name), "duplicate generated credential family");
        ensure!(seen.len() <= 64, "generated credential family budget");
        // Concrete nominals avoid return-only phantom specialization in the
        // pinned compiler. Exact labels prevent lowered-name collisions.
        let mut body = COMMON
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
        } else {
            format!(
                "|context, request| {prefix}day2_issue_fixed_{name}(\"{name}\", context, request.label)"
            )
        };
        source.push_str(&format!(
            "    {name} : {{ issue : InteractiveContext, {{ label : Credential.Label }} -> Tx(Issued_{name}), list : ListRequest_{name} -> Observe(Try(Page_{name}, ListFailure_{name})), inspect : {{ lineage : Ref_{name} }} -> Observe(Try(Inspection_{name}, InspectionFailure_{name})), start : Cursor_{name}, cursor_from_str : Str -> Try(Cursor_{name}, [InvalidCursor]), ref_from_str : Str -> Try(Ref_{name}, [InvalidRef]) }}\n    {name} = {{\n        issue: {issue},\n        list: {list},\n        inspect: {inspect},\n        start: {{ value: PlatformCursor.start }},\n        cursor_from_str: |raw| day2_cursor_from_str_{name}(\"{name}\", raw),\n        ref_from_str: |raw| day2_ref_from_str_{name}(\"{name}\", raw),\n    }}\n\n"
        ));
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
    $PREFIX$issue_fixed = |registration, context, label| Tx.$PREFIX$capability(
        "credential_issue", "credential.issue.v1",
        Json.to_str({ registration, invocation: context.invocation_id(), label: label.to_str() }),
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

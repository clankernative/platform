//! Private SQLite transitions for managed lineages and human delivery.
//! Staging accepts the caller's existing app transaction. A pending result has
//! no secret or permit. The caller's coordinator owns the product commit.

use super::crypto::{
    KeyLease, MaterialIdentity, PreparedMaterial, decrypt_for_human, prepare_managed,
    token_selector, verify_managed,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{
        CollectionPage, FamilyCursor, GrantMode, Inspection, LineageRef, ListFailure, ListRequest,
        ManagedProfile, ManagementPolicy, ManagementPredicate, ManagementSnapshot, ManagementState,
        ManifestFamily, Namespace, Summary, VersionRef,
    },
    oauth::{GrantCeiling, OperationAuthorityContract},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

const CREDENTIAL_DDL: &str = "
        CREATE TABLE IF NOT EXISTS day2_credential_schema_version (
            version INTEGER PRIMARY KEY
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_lineages (
            id TEXT PRIMARY KEY,
            namespace TEXT NOT NULL,
            namespace_json TEXT NOT NULL,
            family TEXT NOT NULL,
            family_contract TEXT NOT NULL,
            principal TEXT NOT NULL,
            creator TEXT NOT NULL,
            label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 128),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            grant_json TEXT NOT NULL,
            grant_digest TEXT NOT NULL,
            grant_valid_until INTEGER NOT NULL,
            security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
            state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
            head TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_versions (
            id TEXT PRIMARY KEY,
            lineage TEXT NOT NULL REFERENCES day2_credential_lineages(id),
            predecessor TEXT UNIQUE REFERENCES day2_credential_versions(id),
            selector TEXT NOT NULL UNIQUE,
            verifier BLOB NOT NULL CHECK(length(verifier) = 32),
            verifier_key_version TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
            security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
            grant_digest TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'superseded', 'revoked'))
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_material (
            version TEXT PRIMARY KEY REFERENCES day2_credential_versions(id),
            identity_json TEXT NOT NULL,
            material_revision INTEGER NOT NULL CHECK(material_revision > 0),
            envelope_revision INTEGER NOT NULL CHECK(envelope_revision > 0),
            encryption_key_version TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK(length(nonce) = 12),
            ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 32 AND 512)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_deliveries (
            version TEXT PRIMARY KEY REFERENCES day2_credential_versions(id),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('available', 'closed')),
            closed_reason TEXT NOT NULL DEFAULT ''
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_receipts (
            namespace TEXT NOT NULL,
            invocation TEXT NOT NULL,
            instruction_slot INTEGER NOT NULL CHECK(instruction_slot >= 0),
            family_contract TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('issue', 'rotate', 'revoke')),
            lineage TEXT NOT NULL REFERENCES day2_credential_lineages(id),
            version TEXT REFERENCES day2_credential_versions(id),
            PRIMARY KEY(namespace, invocation, instruction_slot)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_revocations (
            namespace TEXT NOT NULL, invocation TEXT NOT NULL, instruction_slot INTEGER NOT NULL,
            request_digest TEXT NOT NULL, outcome TEXT NOT NULL,
            PRIMARY KEY(namespace, invocation, instruction_slot),
            FOREIGN KEY(namespace, invocation, instruction_slot)
                REFERENCES day2_credential_receipts(namespace, invocation, instruction_slot)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_credential_reveals (
            attempt TEXT PRIMARY KEY,
            version TEXT NOT NULL REFERENCES day2_credential_versions(id),
            recipient TEXT NOT NULL,
            session TEXT NOT NULL,
            authorized_at INTEGER NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS day2_credential_visible_creator
            ON day2_credential_lineages(namespace, family, creator, id);
        CREATE INDEX IF NOT EXISTS day2_credential_visible_principal
            ON day2_credential_lineages(namespace, family, principal, id);";

const CREDENTIAL_TABLES: &[&str] = &[
    "day2_credential_schema_version",
    "day2_credential_lineages",
    "day2_credential_versions",
    "day2_credential_material",
    "day2_credential_deliveries",
    "day2_credential_receipts",
    "day2_credential_revocations",
    "day2_credential_reveals",
];

const CREDENTIAL_PEER_TABLES: &[&str] = &[
    "day2_credential_browser",
    "day2_credential_confirmations",
    "day2_credential_origins",
];

/// Raw connections grant this installer ownership of a temporary progress
/// callback. Runtime connections must enter `admit_with_runtime_hook` first;
/// nested admission preserves their existing callback and cumulative counter.
pub(crate) fn install_schema(db: &Connection) -> Result<()> {
    crate::oauth::schema::admit(db, install_schema_in)
}

fn install_schema_in(db: &Connection) -> Result<()> {
    use crate::oauth::schema;
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(CREDENTIAL_DDL)?;
    // These sibling installers are the authoritative definitions, not a second
    // schema catalog. Their tables may be absent before a standalone store is
    // attached to the ordinary runtime, but any present object must be exact.
    super::issuance::install(&expected)?;
    let predicates = credential_predicates();
    let mut fresh = true;
    let mut peers = Vec::new();
    // SQLite resolves identifiers without ASCII case distinctions. Debit raw
    // metadata before inspecting imported operands, then require the exact
    // canonical object identity supplied by the owning installers. This same
    // scan determines freshness and optional peers before target DDL can run.
    let mut statement = db.prepare("SELECT type,name,tbl_name FROM sqlite_master")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        schema::materialize(row)?;
        let kind = row.get_ref(0)?.as_str()?;
        let name = row.get_ref(1)?.as_str()?;
        let table = row.get_ref(2)?.as_str()?;
        let owned = |value: &str| {
            value
                .get(.."day2_credential_".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("day2_credential_"))
        };
        if !owned(name) && !owned(table) {
            continue;
        }
        fresh = false;
        let canonical: bool = expected.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2 AND tbl_name=?3)",
            [kind, name, table],
            |row| row.get(0),
        )?;
        let guard = kind == "trigger"
            && predicates.iter().any(|(owner, _)| {
                table == *owner
                    && ["INSERT", "UPDATE"]
                        .iter()
                        .any(|operation| name == format!("{owner}_shape_{operation}_v2"))
            });
        ensure!(
            canonical || guard,
            "unsupported credential schema object {name}"
        );
        if kind == "table"
            && let Some(peer) = CREDENTIAL_PEER_TABLES.iter().find(|peer| **peer == name)
        {
            peers.push(*peer);
        }
    }
    drop(rows);
    drop(statement);
    ensure!(
        peers.is_empty() || peers.len() == CREDENTIAL_PEER_TABLES.len(),
        "incomplete credential peer schema unit"
    );
    if !fresh {
        let mut statement = db.prepare("SELECT version FROM day2_credential_schema_version")?;
        let mut rows = statement.query([])?;
        let mut version = None;
        while let Some(row) = rows.next()? {
            schema::materialize(row)?;
            ensure!(version.is_none(), "unsupported credential schema version");
            version = Some(row.get::<_, i64>(0)?);
        }
        ensure!(version == Some(2), "unsupported credential schema version");
    }
    let invariants: Vec<_> = predicates
        .iter()
        .map(|(table, predicate)| schema::Invariant { table, predicate })
        .collect();
    schema::install_current(
        db,
        "day2_credential_schema_version",
        2,
        CREDENTIAL_DDL,
        &invariants,
    )?;
    for table in CREDENTIAL_TABLES {
        schema::exact_layout(db, &expected, table)?;
    }
    for &table in &peers {
        schema::exact_layout(db, &expected, table)?;
    }
    validate_credential_rows(db)?;
    validate_credential_peers(db, &peers)
}

fn validate_credential_peers(db: &Connection, peers: &[&str]) -> Result<()> {
    use crate::oauth::schema::materialize;
    let mut pending = std::collections::BTreeMap::new();
    if peers.contains(&"day2_credential_browser") {
        let mut statement =
            db.prepare("SELECT invocation,attempt,intent,expires_at FROM day2_credential_browser")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            materialize(row)?;
            let navigation: super::browser::Pending =
                crate::json::decode(row.get_ref(2)?.as_str()?.as_bytes())?;
            ensure!(
                navigation.invocation == row.get_ref(0)?.as_str()?
                    && navigation.attempt == row.get_ref(1)?.as_str()?
                    && navigation.created_at >= 0
                    && navigation.expires_at == row.get::<_, i64>(3)?
                    && navigation.expires_at.checked_sub(navigation.created_at) == Some(300),
                "invalid restored credential navigation identity or time"
            );
            for value in [
                &navigation.invocation,
                &navigation.attempt,
                &navigation.operation,
                &navigation.family,
            ] {
                validate_id(value)?;
            }
            crate::authority::valid_actor(&navigation.actor)?;
            Digest::try_from(navigation.artifact.clone())?;
            Digest::try_from(navigation.authority.epoch.clone())?;
            ensure!(
                navigation.authority.revision > 0 && navigation.input.is_object(),
                "invalid restored credential navigation authority or input"
            );
            if let Some(page) = &navigation.product_return {
                validate_id(page)?;
            }
            validate_restored_intent(&navigation.intent, &navigation.family)?;
            pending.insert(navigation.invocation.clone(), navigation);
        }
    }
    if peers.contains(&"day2_credential_confirmations") {
        let mut statement =
            db.prepare("SELECT invocation,confirmation FROM day2_credential_confirmations")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            materialize(row)?;
            let confirmation: super::issuance::Confirmation =
                crate::json::decode(row.get_ref(1)?.as_str()?.as_bytes())?;
            ensure!(
                confirmation.invocation == row.get_ref(0)?.as_str()?,
                "invalid restored credential confirmation identity"
            );
            for value in [
                &confirmation.invocation,
                &confirmation.operation,
                &confirmation.session,
                &confirmation.family,
            ] {
                validate_id(value)?;
            }
            crate::authority::valid_actor(&confirmation.actor)?;
            ensure!(
                !confirmation.subject.is_empty()
                    && confirmation.subject.len() <= 256
                    && confirmation
                        .subject
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic()),
                "invalid restored credential confirmation subject"
            );
            Digest::try_from(confirmation.artifact.clone())?;
            Digest::try_from(confirmation.authority.epoch.clone())?;
            ensure!(
                confirmation.security_epoch > 0
                    && confirmation.authority.revision > 0
                    && confirmation.input.is_object()
                    && confirmation.authenticated_at >= 0
                    && confirmation.authenticated_at <= confirmation.approved_at
                    && confirmation.approved_at < confirmation.expires_at
                    && confirmation
                        .expires_at
                        .checked_sub(confirmation.authenticated_at)
                        .is_some_and(|seconds| seconds <= 300),
                "invalid restored credential confirmation authority or time"
            );
            validate_restored_intent(&confirmation.intent, &confirmation.family)?;
            if let Some(navigation) = pending.get(&confirmation.invocation) {
                ensure!(
                    confirmation.operation == navigation.operation
                        && confirmation.actor == navigation.actor
                        && confirmation.input == navigation.input
                        && confirmation.family == navigation.family
                        && confirmation.intent == navigation.intent
                        && confirmation.artifact == navigation.artifact
                        && confirmation.authority == navigation.authority
                        && confirmation.binding == navigation.binding
                        && confirmation.authenticated_at > navigation.created_at
                        && confirmation.expires_at <= navigation.expires_at,
                    "restored credential confirmation changed navigation intent"
                );
            }
        }
    }
    if peers.contains(&"day2_credential_origins") {
        super::ingress::validate_restored(db)?;
    }
    Ok(())
}

fn validate_restored_intent(intent: &super::lifecycle::Intent, family: &str) -> Result<()> {
    use super::lifecycle::Intent;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let reference = |value: &str| -> Result<()> {
        ensure!(
            value.len() <= 2048
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
            "invalid restored credential lineage reference"
        );
        let encoded = value
            .strip_prefix("cr1_")
            .context("invalid restored credential lineage reference")?;
        // References carry a source registration alias, not the durable family
        // ID. Historical aliases may contain underscores and may have changed
        // compatibly. Examine only the at-most-48-byte identifier prefix; do not
        // infer its boundary from the current artifact or the stored family ID.
        for (offset, byte) in encoded.bytes().take(49).enumerate() {
            if byte != b'_' {
                continue;
            }
            let registration = &encoded[..offset];
            if crate::schema::identifier(registration).is_err() {
                continue;
            }
            let candidate = || -> Result<()> {
                let decoded: LineageRef =
                    crate::json::decode(&URL_SAFE_NO_PAD.decode(&encoded[offset + 1..])?)?;
                decoded.namespace.validate()?;
                validate_id(&decoded.id)?;
                ensure!(
                    decoded.family.as_str() == family
                        && super::encode_ref(registration, &decoded)? == value,
                    "noncanonical restored credential lineage reference"
                );
                Ok(())
            };
            if candidate().is_ok() {
                return Ok(());
            }
        }
        anyhow::bail!("invalid restored credential lineage reference")
    };
    match intent {
        Intent::Issue { label } => ensure!(
            !label.trim().is_empty() && label.len() <= 128 && !label.chars().any(char::is_control),
            "invalid restored credential label"
        ),
        Intent::Rotate {
            lineage,
            head,
            revision,
        } => {
            reference(lineage)?;
            validate_id(head)?;
            ensure!(
                *revision > 0 && *revision <= i64::MAX as u64,
                "invalid restored credential rotation revision"
            );
        }
        Intent::Revoke { lineage } => reference(lineage)?,
    }
    Ok(())
}

fn credential_predicates() -> Vec<(&'static str, String)> {
    let id = |column: &str| {
        format!(
            "length(CAST({column} AS BLOB)) BETWEEN 1 AND 160 AND {column} NOT GLOB '*[^a-zA-Z0-9._/-]*'"
        )
    };
    let digest = |column: &str| {
        format!(
            "length({column}) = 71 AND substr({column},1,7) = 'sha256:' AND substr({column},8) NOT GLOB '*[^0-9a-f]*'"
        )
    };
    let clean = |column: &str| {
        format!(
            "instr({column},char(0)) = 0 AND {column} NOT GLOB '*[' || char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159) || ']*'"
        )
    };
    let trimmed = |column: &str| {
        format!(
            "trim({column},char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288))"
        )
    };
    let actor = |column: &str| {
        format!(
            "length(CAST({column} AS BLOB)) BETWEEN 1 AND 256 AND {} = {column} AND substr({column},1,7) != 'domain:' AND substr({column},1,18) != 'credential_client:' AND {}",
            trimmed(column),
            clean(column)
        )
    };
    let json = |column: &str| {
        format!(
            "length(CAST({column} AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid({column}) AND json_type({column}) = 'object'"
        )
    };
    vec![
        (
            "day2_credential_lineages",
            format!(
                "{} AND {} AND {} AND {} AND {} AND {} AND {} AND {} AND {} AND {} AND {} AND {} AND length(CAST(label AS BLOB)) BETWEEN 1 AND 128 AND length({}) > 0 AND {} AND security_epoch > 0 AND revision > 0 AND state IN ('active','revoked')",
                id("id"),
                digest("namespace"),
                json("namespace_json"),
                id("family"),
                digest("family_contract"),
                actor("principal"),
                actor("creator"),
                actor("recipient"),
                id("session"),
                json("grant_json"),
                digest("grant_digest"),
                id("head"),
                trimmed("label"),
                clean("label")
            ),
        ),
        (
            "day2_credential_versions",
            format!(
                "{} AND {} AND (predecessor IS NULL OR ({} AND predecessor != id)) AND {} AND length(selector)=22 AND selector NOT GLOB '*[^a-zA-Z0-9_-]*' AND substr(selector,22,1) IN ('A','Q','g','w') AND {} AND {} AND length(verifier)=32 AND expires_at > issued_at AND security_epoch > 0 AND state IN ('active','superseded','revoked')",
                id("id"),
                id("lineage"),
                id("predecessor"),
                id("selector"),
                id("verifier_key_version"),
                digest("grant_digest")
            ),
        ),
        (
            "day2_credential_material",
            format!(
                "{} AND {} AND {} AND material_revision > 0 AND envelope_revision > 0 AND length(nonce)=12 AND length(ciphertext) BETWEEN 32 AND 512",
                id("version"),
                json("identity_json"),
                id("encryption_key_version")
            ),
        ),
        (
            "day2_credential_deliveries",
            format!(
                "{} AND {} AND {} AND ((state='available' AND closed_reason='') OR (state='closed' AND closed_reason IN ('acknowledged','expired','session_end','epoch_advance','rotation','revoked')))",
                id("version"),
                actor("recipient"),
                id("session")
            ),
        ),
        (
            "day2_credential_receipts",
            format!(
                "{} AND {} AND {} AND {} AND {} AND instruction_slot BETWEEN 0 AND 4294967295 AND ((action IN ('issue','rotate') AND version IS NOT NULL AND {}) OR (action='revoke' AND version IS NULL))",
                digest("namespace"),
                id("invocation"),
                digest("family_contract"),
                digest("request_digest"),
                id("lineage"),
                id("version")
            ),
        ),
        (
            "day2_credential_revocations",
            format!(
                "{} AND {} AND {} AND {} AND instruction_slot BETWEEN 0 AND 4294967295",
                digest("namespace"),
                id("invocation"),
                digest("request_digest"),
                json("outcome")
            ),
        ),
        (
            "day2_credential_reveals",
            format!(
                "{} AND {} AND {} AND {}",
                id("attempt"),
                id("version"),
                actor("recipient"),
                id("session")
            ),
        ),
    ]
}

struct RestoredLineage {
    namespace: Namespace,
    family: String,
    head: String,
    revision: i64,
    revoked: bool,
}

/// These checks apply to a completed/restored database, not to intermediate
/// rows in the caller's issue/rotation/revocation transaction. All SELECT work
/// shares the admission VM budget and every decoded row is charged first.
fn validate_credential_rows(db: &Connection) -> Result<()> {
    use crate::oauth::schema::materialize;
    use std::collections::{BTreeMap, BTreeSet};
    for (table, predicate) in credential_predicates() {
        let invalid: bool = db.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE NOT COALESCE(({predicate}),0))"),
            [],
            |row| row.get(0),
        )?;
        ensure!(!invalid, "invalid restored credential shape in {table}");
    }
    // Include every version, not merely active heads. Historical material and
    // deliveries remain bound to the recipient/session of that version.
    let invalid: bool = db.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM day2_credential_lineages l
            LEFT JOIN day2_credential_versions h ON h.id=l.head
            LEFT JOIN day2_credential_deliveries d ON d.version=h.id
            WHERE h.id IS NULL OR h.lineage!=l.id OR
                (l.state='active' AND h.state!='active') OR
                (l.state='revoked' AND h.state!='revoked') OR
                d.recipient!=l.recipient OR d.session!=l.session
        ) OR EXISTS(
            SELECT 1 FROM day2_credential_versions v
            JOIN day2_credential_lineages l ON l.id=v.lineage
            LEFT JOIN day2_credential_material m ON m.version=v.id
            LEFT JOIN day2_credential_deliveries d ON d.version=v.id
            LEFT JOIN day2_credential_versions p ON p.id=v.predecessor
            WHERE m.version IS NULL OR d.version IS NULL OR
                v.security_epoch!=l.security_epoch OR v.grant_digest!=l.grant_digest OR
                v.expires_at>l.grant_valid_until OR
                d.expires_at<=v.issued_at OR d.expires_at>v.expires_at OR
                (l.state='revoked' AND v.state!='revoked') OR
                (l.state='active' AND ((v.id=l.head AND v.state!='active') OR
                    (v.id!=l.head AND v.state!='superseded'))) OR
                (v.state!='active' AND d.state!='closed') OR
                (d.closed_reason='rotation' AND v.id=l.head) OR
                (d.closed_reason='revoked' AND l.state!='revoked') OR
                (v.predecessor IS NOT NULL AND (p.id IS NULL OR p.lineage!=v.lineage))
        ) OR EXISTS(
            SELECT 1 FROM day2_credential_receipts r
            JOIN day2_credential_lineages l ON l.id=r.lineage
            LEFT JOIN day2_credential_versions v ON v.id=r.version
            LEFT JOIN day2_credential_revocations x ON x.namespace=r.namespace AND
                x.invocation=r.invocation AND x.instruction_slot=r.instruction_slot
            WHERE r.namespace!=l.namespace OR r.family_contract!=l.family_contract OR
                (r.action IN ('issue','rotate') AND (v.id IS NULL OR v.lineage!=r.lineage)) OR
                (r.action='issue' AND v.predecessor IS NOT NULL) OR
                (r.action='rotate' AND v.predecessor IS NULL) OR
                (r.action='revoke' AND (l.state!='revoked' OR x.namespace IS NULL OR x.request_digest!=r.request_digest)) OR
                (x.namespace IS NOT NULL AND r.action!='revoke')
        ) OR EXISTS(
            SELECT 1 FROM day2_credential_versions v
            WHERE (SELECT count(*) FROM day2_credential_receipts r
                WHERE r.version=v.id AND r.action IN ('issue','rotate'))!=1
        ) OR EXISTS(
            SELECT 1 FROM day2_credential_reveals r
            JOIN day2_credential_versions v ON v.id=r.version
            JOIN day2_credential_deliveries d ON d.version=v.id
            WHERE r.recipient!=d.recipient OR r.session!=d.session OR
                r.authorized_at<v.issued_at OR r.authorized_at>=d.expires_at
        )",
        [], |row| row.get(0),
    )?;
    ensure!(!invalid, "invalid restored credential relationships");

    let mut lineages = BTreeMap::new();
    let mut statement = db.prepare(
        "SELECT id,namespace,namespace_json,family,family_contract,principal,creator,label,
                recipient,session,grant_json,grant_digest,head,revision,state
         FROM day2_credential_lineages",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        let id: String = row.get(0)?;
        validate_id(&id)?;
        let namespace: Namespace = crate::json::decode(row.get_ref(2)?.as_str()?.as_bytes())?;
        namespace.validate()?;
        ensure!(
            namespace_key(&namespace)? == row.get::<_, String>(1)?,
            "restored credential namespace mismatch"
        );
        let family: String = row.get(3)?;
        day2_capabilities::Name::try_from(family.clone())?;
        Digest::try_from(row.get::<_, String>(4)?)?;
        let principal: String = row.get(5)?;
        for index in [5, 6, 8] {
            crate::authority::valid_actor(row.get_ref(index)?.as_str()?)?;
        }
        let label = row.get_ref(7)?.as_str()?;
        ensure!(
            !label.trim().is_empty() && label.len() <= 128 && !label.chars().any(char::is_control),
            "invalid restored credential label"
        );
        validate_id(row.get_ref(9)?.as_str()?)?;
        let grant: GrantCeiling = crate::json::decode(row.get_ref(10)?.as_str()?.as_bytes())?;
        grant.verify()?;
        ensure!(
            grant.subject == principal && grant.digest.as_str() == row.get_ref(11)?.as_str()?,
            "restored credential grant mismatch"
        );
        lineages.insert(
            id,
            RestoredLineage {
                namespace,
                family,
                head: row.get(12)?,
                revision: row.get(13)?,
                revoked: row.get_ref(14)?.as_str()? == "revoked",
            },
        );
    }
    drop(rows);
    drop(statement);

    let mut predecessors = BTreeMap::new();
    let mut statement =
        db.prepare("SELECT id,lineage,predecessor FROM day2_credential_versions")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        predecessors.insert(
            row.get::<_, String>(0)?,
            (row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?),
        );
    }
    drop(rows);
    drop(statement);
    let mut visited = BTreeSet::new();
    for (id, lineage) in &lineages {
        let mut cursor = Some(lineage.head.as_str());
        let mut count = 0i64;
        while let Some(version) = cursor {
            ensure!(
                visited.insert(version),
                "cyclic or shared restored credential chain"
            );
            let (owner, predecessor) = predecessors
                .get(version)
                .context("missing restored credential chain member")?;
            ensure!(owner == id, "cross-lineage restored credential chain");
            count += 1;
            cursor = predecessor.as_deref();
        }
        ensure!(
            lineage.revision == count + i64::from(lineage.revoked),
            "restored credential revision mismatch"
        );
    }
    ensure!(
        visited.len() == predecessors.len(),
        "disconnected restored credential chain"
    );

    let mut statement = db.prepare(
        "SELECT m.identity_json,m.material_revision,v.id,v.lineage,v.security_epoch,d.recipient
         FROM day2_credential_material m JOIN day2_credential_versions v ON v.id=m.version
         JOIN day2_credential_deliveries d ON d.version=v.id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        let identity: MaterialIdentity = crate::json::decode(row.get_ref(0)?.as_str()?.as_bytes())?;
        let lineage_id: String = row.get(3)?;
        let lineage = lineages
            .get(&lineage_id)
            .context("missing restored credential lineage")?;
        ensure!(
            identity.namespace == lineage.namespace
                && identity.family == lineage.family
                && identity.lineage == lineage_id
                && identity.version == row.get_ref(2)?.as_str()?
                && identity.security_epoch == u64::try_from(row.get::<_, i64>(4)?)?
                && identity.material_revision == u64::try_from(row.get::<_, i64>(1)?)?
                && identity.recipient == row.get_ref(5)?.as_str()?,
            "restored credential material identity mismatch"
        );
    }
    drop(rows);
    drop(statement);

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RevocationOutcome {
        already_revoked: bool,
        lineage: String,
        revision: u64,
    }
    let mut statement = db.prepare(
        "SELECT x.outcome,r.lineage FROM day2_credential_revocations x
         JOIN day2_credential_receipts r ON r.namespace=x.namespace AND r.invocation=x.invocation
            AND r.instruction_slot=x.instruction_slot",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        materialize(row)?;
        let outcome: RevocationOutcome = crate::json::decode(row.get_ref(0)?.as_str()?.as_bytes())?;
        let id: String = row.get(1)?;
        let lineage = lineages
            .get(&id)
            .context("missing revoked credential lineage")?;
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&LineageRef {
                namespace: lineage.namespace.clone(),
                family: day2_capabilities::Name::try_from(lineage.family.clone())?,
                id,
            })?,
        );
        let suffix = format!("_{encoded}");
        let registration = outcome
            .lineage
            .strip_prefix("cr1_")
            .and_then(|rest| rest.strip_suffix(&suffix))
            .context("restored credential revocation reference mismatch")?;
        day2_capabilities::Name::try_from(registration.to_owned())?;
        ensure!(
            outcome.revision > 0
                && outcome.revision <= u64::try_from(lineage.revision)?
                && lineage.revoked,
            "restored credential revocation revision mismatch"
        );
        // The recorded bool is historical: a later retry need not equal the
        // currently revoked state. Deserializing it still requires a bool.
        let _ = outcome.already_revoked;
    }
    Ok(())
}

/// All fields are immutable accepted-invocation evidence supplied by the host.
/// The host must establish direct interactive authorization before preparation.
pub(crate) struct IssueIntent {
    pub namespace: Namespace,
    pub family: String,
    pub family_contract: Digest,
    pub invocation: String,
    pub instruction_slot: u32,
    pub principal: String,
    pub creator: String,
    pub recipient: String,
    pub session: String,
    pub label: String,
    pub ceiling: GrantCeiling,
    pub issued_at: i64,
    pub expires_at: i64,
    pub grant_valid_until: i64,
    pub reveal_until: i64,
    pub security_epoch: u64,
}

pub(crate) struct PreparedIssue {
    intent: IssueIntent,
    lineage: String,
    version: String,
    material: PreparedMaterial,
    request_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicReceipt {
    pub lineage: String,
    pub version: Option<String>,
}

/// This value remains pending until the containing product transaction commits.
pub(crate) struct PendingIssue(PublicReceipt);

impl PendingIssue {
    pub fn public_identity(&self) -> &PublicReceipt {
        &self.0
    }
}

pub(crate) fn prepare_issue(
    lease: &KeyLease,
    family: &ManifestFamily,
    intent: IssueIntent,
) -> Result<PreparedIssue> {
    family.verify()?;
    ensure!(
        family.id.as_str() == intent.family && family.contract == intent.family_contract,
        "credential issuance family contract mismatch"
    );
    ensure!(
        !matches!(family.profile, ManagedProfile::Impersonation { .. }),
        "impersonation requires protected session handoff"
    );
    ensure!(
        intent
            .expires_at
            .checked_sub(intent.issued_at)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .is_some_and(|seconds| seconds > 0 && seconds <= family.lifetime_seconds),
        "credential issuance exceeds family lifetime"
    );
    intent.namespace.validate()?;
    intent.ceiling.verify()?;
    ensure!(
        matches!(family.grant, GrantMode::Selectable)
            || intent.ceiling.roots.len() == family.roots.len(),
        "fixed credential grant must include every family root"
    );
    for (name, selected) in &intent.ceiling.roots {
        let declared = family
            .roots
            .get(name)
            .context("credential grant selected an undeclared root")?;
        ensure!(
            selected.operation == declared.operation
                && selected.version == declared.version
                && selected.operation_contract == declared.operation_contract
                && selected.kind == declared.kind
                && selected.closure.is_within(&declared.closure),
            "credential grant exceeds declared family authority"
        );
        ensure!(
            matches!(family.grant, GrantMode::Selectable) || selected == declared,
            "fixed credential grant cannot narrow a declared root"
        );
    }
    for id in [&intent.family, &intent.invocation, &intent.session] {
        validate_id(id)?;
    }
    for actor in [&intent.principal, &intent.creator, &intent.recipient] {
        crate::authority::valid_actor(actor)?;
    }
    ensure!(
        !intent.label.trim().is_empty()
            && intent.label.len() <= 128
            && !intent.label.chars().any(char::is_control),
        "invalid credential label"
    );
    ensure!(
        intent.issued_at < intent.expires_at
            && intent.expires_at <= intent.grant_valid_until
            && intent.issued_at < intent.reveal_until
            && intent.reveal_until <= intent.expires_at
            && intent.security_epoch > 0,
        "invalid credential time or epoch bounds"
    );
    ensure!(
        intent.ceiling.subject == intent.principal,
        "credential principal and grant subject mismatch"
    );
    let lineage = random_id()?;
    let version = random_id()?;
    let identity = MaterialIdentity {
        namespace: intent.namespace.clone(),
        family: intent.family.clone(),
        lineage: lineage.clone(),
        version: version.clone(),
        recipient: intent.recipient.clone(),
        security_epoch: intent.security_epoch,
        material_revision: 1,
    };
    let material = prepare_managed(lease, identity)?;
    let request_digest = Digest::of(&(
        "credential-issue-intent-v1",
        (
            &intent.namespace,
            &intent.family,
            &intent.family_contract,
            &intent.invocation,
            intent.instruction_slot,
            &intent.principal,
            &intent.creator,
            &intent.recipient,
        ),
        (
            &intent.session,
            &intent.label,
            &intent.ceiling.digest,
            intent.issued_at,
            intent.expires_at,
            intent.grant_valid_until,
            intent.reveal_until,
            intent.security_epoch,
        ),
    ))?;
    Ok(PreparedIssue {
        intent,
        lineage,
        version,
        material,
        request_digest,
    })
}

/// Stage alongside ordinary product rows. Same accepted invocation and intent
/// returns the original public identity; changed intent is a hard conflict.
pub(crate) fn stage_issue(tx: &Transaction<'_>, prepared: PreparedIssue) -> Result<PendingIssue> {
    let issue = &prepared.intent;
    let namespace = namespace_key(&issue.namespace)?;
    ensure!(
        prepared.material.identity.namespace == issue.namespace
            && prepared.material.identity.family == issue.family,
        "credential material namespace or family mismatch"
    );
    if let Some(ReceiptRow {
        contract,
        digest,
        action,
        lineage,
        version,
    }) = receipt(tx, &namespace, &issue.invocation, issue.instruction_slot)?
    {
        ensure!(
            contract == issue.family_contract.as_str()
                && digest == prepared.request_digest.as_str()
                && action == "issue",
            "credential issuance identity reused with changed intent"
        );
        return Ok(PendingIssue(PublicReceipt { lineage, version }));
    }
    let grant_json = serde_json::to_string(&issue.ceiling)?;
    tx.execute(
        "INSERT INTO day2_credential_lineages
         (id, namespace, namespace_json, family, family_contract, principal, creator, label, recipient, session,
          grant_json, grant_digest, grant_valid_until, security_epoch, state, head, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 'active', ?15, 1)",
        params![
            prepared.lineage,
            namespace,
            serde_json::to_string(&issue.namespace)?,
            issue.family,
            issue.family_contract.as_str(),
            issue.principal,
            issue.creator,
            issue.label,
            issue.recipient,
            issue.session,
            grant_json,
            issue.ceiling.digest.as_str(),
            issue.grant_valid_until,
            i64::try_from(issue.security_epoch)?,
            prepared.version
        ],
    )?;
    insert_version(
        tx,
        VersionWrite {
            lineage: &prepared.lineage,
            version: &prepared.version,
            predecessor: None,
            material: &prepared.material,
            issued_at: issue.issued_at,
            expires_at: issue.expires_at,
            security_epoch: issue.security_epoch,
            grant_digest: issue.ceiling.digest.as_str(),
            recipient: &issue.recipient,
            session: &issue.session,
            reveal_until: issue.reveal_until,
        },
    )?;
    tx.execute(
        "INSERT INTO day2_credential_receipts
         (namespace, invocation, instruction_slot, family_contract, request_digest, action, lineage, version)
         VALUES (?1, ?2, ?3, ?4, ?5, 'issue', ?6, ?7)",
        params![namespace, issue.invocation, issue.instruction_slot, issue.family_contract.as_str(),
            prepared.request_digest.as_str(), prepared.lineage, prepared.version],
    )?;
    Ok(PendingIssue(PublicReceipt {
        lineage: prepared.lineage,
        version: Some(prepared.version),
    }))
}

struct VersionWrite<'a> {
    lineage: &'a str,
    version: &'a str,
    predecessor: Option<&'a str>,
    material: &'a PreparedMaterial,
    issued_at: i64,
    expires_at: i64,
    security_epoch: u64,
    grant_digest: &'a str,
    recipient: &'a str,
    session: &'a str,
    reveal_until: i64,
}

fn insert_version(tx: &Transaction<'_>, write: VersionWrite<'_>) -> Result<()> {
    let VersionWrite {
        lineage,
        version,
        predecessor,
        material,
        issued_at,
        expires_at,
        security_epoch,
        grant_digest,
        recipient,
        session,
        reveal_until,
    } = write;
    ensure!(
        material.identity.lineage == lineage
            && material.identity.version == version
            && material.identity.security_epoch == security_epoch
            && material.identity.recipient == recipient,
        "credential material binding mismatch"
    );
    tx.execute(
        "INSERT INTO day2_credential_versions
         (id, lineage, predecessor, selector, verifier, verifier_key_version, issued_at,
          expires_at, security_epoch, grant_digest, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'active')",
        params![
            version,
            lineage,
            predecessor,
            material.selector,
            material.verifier.as_slice(),
            material.verifier_version,
            issued_at,
            expires_at,
            i64::try_from(security_epoch)?,
            grant_digest
        ],
    )?;
    tx.execute(
        "INSERT INTO day2_credential_material
         (version, identity_json, material_revision, envelope_revision, encryption_key_version, nonce, ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![version, serde_json::to_string(&material.identity)?,
            i64::try_from(material.identity.material_revision)?,
            i64::try_from(material.envelope_revision)?,
            material.encryption_version, material.nonce.as_slice(), material.ciphertext],
    )?;
    tx.execute(
        "INSERT INTO day2_credential_deliveries (version, recipient, session, expires_at, state)
         VALUES (?1, ?2, ?3, ?4, 'available')",
        params![version, recipient, session, reveal_until],
    )?;
    Ok(())
}

pub(crate) enum RotationResult {
    Rotated(PendingIssue),
    Conflict,
}

pub(crate) struct RotationIntent<'a> {
    pub invocation: &'a str,
    pub instruction_slot: u32,
    pub recipient: &'a str,
    pub session: &'a str,
    pub issued_at: i64,
    pub expires_at: i64,
    pub reveal_until: i64,
}

/// The key lease is resolved before SQLite; local material generation runs
/// inside the transaction. Authorization, fresh interaction and current
/// instance policy must be checked by the host before this transition.
pub(crate) fn stage_rotation(
    tx: &Transaction<'_>,
    lease: &KeyLease,
    expected: &ManagementSnapshot,
    intent: RotationIntent<'_>,
) -> Result<RotationResult> {
    let RotationIntent {
        invocation,
        instruction_slot,
        recipient,
        session,
        issued_at,
        expires_at,
        reveal_until,
    } = intent;
    validate_id(invocation)?;
    crate::authority::valid_actor(recipient)?;
    validate_id(session)?;
    let namespace = namespace_key(&expected.lineage.namespace)?;
    let (
        family_contract,
        grant_json,
        grant_digest,
        grant_valid_until,
        epoch,
        state,
        head,
        revision,
    ): (String, String, String, i64, i64, String, String, i64) = tx
        .query_row(
            "SELECT family_contract, grant_json, grant_digest,
                grant_valid_until, security_epoch, state, head, revision
         FROM day2_credential_lineages WHERE id = ?1 AND namespace = ?2 AND family = ?3",
            params![
                expected.lineage.id,
                namespace,
                expected.lineage.family.as_str()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .context("credential lineage is unavailable")?;
    let request_digest = Digest::of(&(
        "credential-rotation-intent-v1",
        &namespace,
        &expected.lineage.id,
        &expected.head.id,
        expected.revision,
        recipient,
        session,
        issued_at,
        expires_at,
        reveal_until,
    ))?;
    if let Some(ReceiptRow {
        contract,
        digest,
        action,
        lineage,
        version,
    }) = receipt(tx, &namespace, invocation, instruction_slot)?
    {
        ensure!(
            contract == family_contract && digest == request_digest.as_str() && action == "rotate",
            "credential rotation identity reused with changed intent"
        );
        return Ok(RotationResult::Rotated(PendingIssue(PublicReceipt {
            lineage,
            version,
        })));
    }
    if state != "active"
        || head != expected.head.id
        || revision != i64::try_from(expected.revision)?
        || expected.head.lineage != expected.lineage
        || issued_at >= grant_valid_until
    {
        return Ok(RotationResult::Conflict);
    }
    ensure!(
        issued_at < expires_at
            && expires_at <= grant_valid_until
            && issued_at < reveal_until
            && reveal_until <= expires_at,
        "invalid rotation time bounds"
    );
    let ceiling: GrantCeiling = serde_json::from_str(&grant_json)?;
    ceiling.verify()?;
    ensure!(
        ceiling.digest.as_str() == grant_digest,
        "stored credential grant mismatch"
    );
    let next = random_id()?;
    let identity = MaterialIdentity {
        namespace: expected.lineage.namespace.clone(),
        family: expected.lineage.family.as_str().to_owned(),
        lineage: expected.lineage.id.clone(),
        version: next.clone(),
        recipient: recipient.to_owned(),
        security_epoch: u64::try_from(epoch)?,
        material_revision: 1,
    };
    let material = prepare_managed(lease, identity)?;
    let changed = tx.execute(
        "UPDATE day2_credential_lineages SET head = ?1, revision = revision + 1,
         recipient = ?2, session = ?3 WHERE id = ?4 AND state = 'active'
         AND head = ?5 AND revision = ?6",
        params![
            next,
            recipient,
            session,
            expected.lineage.id,
            head,
            revision
        ],
    )?;
    if changed != 1 {
        return Ok(RotationResult::Conflict);
    }
    tx.execute("UPDATE day2_credential_versions SET state = 'superseded' WHERE id = ?1 AND state = 'active'",
        [&head])?;
    tx.execute(
        "UPDATE day2_credential_deliveries SET state = 'closed', closed_reason = 'rotation'
                WHERE version = ?1 AND state = 'available'",
        [&head],
    )?;
    insert_version(
        tx,
        VersionWrite {
            lineage: &expected.lineage.id,
            version: &next,
            predecessor: Some(&head),
            material: &material,
            issued_at,
            expires_at,
            security_epoch: u64::try_from(epoch)?,
            grant_digest: &grant_digest,
            recipient,
            session,
            reveal_until,
        },
    )?;
    tx.execute(
        "INSERT INTO day2_credential_receipts
         (namespace, invocation, instruction_slot, family_contract, request_digest, action, lineage, version)
         VALUES (?1, ?2, ?3, ?4, ?5, 'rotate', ?6, ?7)",
        params![namespace, invocation, instruction_slot, family_contract,
            request_digest.as_str(), expected.lineage.id, next],
    )?;
    Ok(RotationResult::Rotated(PendingIssue(PublicReceipt {
        lineage: expected.lineage.id.clone(),
        version: Some(next),
    })))
}

pub(crate) fn stage_revoke(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    lineage: &str,
) -> Result<bool> {
    validate_id(lineage)?;
    let namespace = namespace_key(namespace)?;
    let changed = tx.execute(
        "UPDATE day2_credential_lineages SET state = 'revoked', revision = revision + 1
         WHERE id = ?1 AND namespace = ?2 AND state = 'active'",
        params![lineage, namespace],
    )?;
    if changed == 1 {
        tx.execute(
            "UPDATE day2_credential_versions SET state = 'revoked' WHERE lineage = ?1",
            [lineage],
        )?;
        tx.execute(
            "UPDATE day2_credential_deliveries SET state = 'closed', closed_reason = 'revoked'
                    WHERE version IN (SELECT id FROM day2_credential_versions WHERE lineage = ?1)
                    AND state = 'available'",
            [lineage],
        )?;
    }
    Ok(changed == 1)
}

/// The caller must resolve this policy from the currently selected instance
/// and establish the requester's authenticated identity. Only creator
/// visibility is supported until group-membership evidence has a host verifier.
#[derive(Clone, Copy)]
pub(crate) struct MetadataRead<'a> {
    pub namespace: &'a Namespace,
    pub family: &'a ManifestFamily,
    pub policy: &'a ManagementPolicy,
    pub requester: &'a str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataCursor {
    format: u8,
    namespace: Digest,
    family_contract: Digest,
    policy: Digest,
    requester: Digest,
    after: String,
}

fn metadata_read_key(read: &MetadataRead<'_>) -> Result<(String, Digest, Digest)> {
    read.namespace.validate()?;
    read.family.verify()?;
    crate::authority::valid_actor(read.requester)?;
    ensure!(
        matches!(
            read.family.profile,
            ManagedProfile::Client | ManagedProfile::Personal
        ),
        "resource and impersonation metadata need their qualified target reader"
    );
    Ok((
        namespace_key(read.namespace)?,
        Digest::of(read.policy)?,
        Digest::of(&("credential-metadata-requester-v1", read.requester))?,
    ))
}

fn decode_metadata_cursor(
    cursor: &FamilyCursor,
    read: &MetadataRead<'_>,
    namespace: &str,
    policy: &Digest,
    requester: &Digest,
) -> Option<String> {
    if cursor.family != read.family.id || cursor.opaque.len() > 2048 {
        return None;
    }
    if cursor.opaque.is_empty() {
        return Some(String::new());
    }
    let raw = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &cursor.opaque,
    )
    .ok()?;
    let decoded: MetadataCursor = serde_json::from_slice(&raw).ok()?;
    (decoded.format == 1
        && decoded.namespace.as_str() == namespace
        && decoded.family_contract == read.family.contract
        && decoded.policy == *policy
        && decoded.requester == *requester
        && validate_id(&decoded.after).is_ok())
    .then_some(decoded.after)
}

fn encode_metadata_cursor(
    read: &MetadataRead<'_>,
    namespace: &str,
    policy: &Digest,
    requester: &Digest,
    after: String,
) -> Result<FamilyCursor> {
    let value = MetadataCursor {
        format: 1,
        namespace: Digest::try_from(namespace.to_owned())?,
        family_contract: read.family.contract.clone(),
        policy: policy.clone(),
        requester: requester.clone(),
        after,
    };
    Ok(FamilyCursor {
        family: read.family.id.clone(),
        opaque: base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&value)?,
        ),
    })
}

struct MetadataRow {
    lineage: String,
    namespace_json: String,
    principal: String,
    label: String,
    grant_json: String,
    grant_digest: String,
    state: String,
    head: String,
    revision: i64,
    expires_at: i64,
}

fn metadata_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MetadataRow> {
    Ok(MetadataRow {
        lineage: row.get(0)?,
        namespace_json: row.get(1)?,
        principal: row.get(2)?,
        label: row.get(3)?,
        grant_json: row.get(4)?,
        grant_digest: row.get(5)?,
        state: row.get(6)?,
        head: row.get(7)?,
        revision: row.get(8)?,
        expires_at: row.get(9)?,
    })
}

fn project_metadata(row: MetadataRow, read: &MetadataRead<'_>) -> Result<Inspection> {
    ensure!(
        serde_json::from_str::<Namespace>(&row.namespace_json)? == *read.namespace,
        "stored credential namespace mismatch"
    );
    let ceiling: GrantCeiling = serde_json::from_str(&row.grant_json)?;
    ceiling.verify()?;
    ensure!(
        ceiling.digest.as_str() == row.grant_digest && ceiling.subject == row.principal,
        "stored credential grant mismatch"
    );
    let state = match row.state.as_str() {
        "active" => ManagementState::Active,
        "revoked" => ManagementState::Revoked,
        _ => anyhow::bail!("invalid stored credential state"),
    };
    let lineage = LineageRef {
        namespace: read.namespace.clone(),
        family: read.family.id.clone(),
        id: row.lineage,
    };
    let current_version = VersionRef {
        lineage: lineage.clone(),
        id: row.head,
    };
    let summary = Summary {
        lineage: lineage.clone(),
        current_version: current_version.clone(),
        label: Some(row.label),
        principal: row.principal,
        resource: None,
        state: state.clone(),
        grant: Digest::try_from(row.grant_digest)?,
        expires_at: row.expires_at,
    };
    let rotation = read
        .family
        .profile
        .can_rotate()
        .then_some(ManagementSnapshot {
            lineage,
            head: current_version,
            revision: u64::try_from(row.revision)?,
            state,
        });
    Ok(Inspection { summary, rotation })
}

/// Bounded keyset selection applies visibility in SQL before limiting rows.
/// A cursor only locates the next row; every request rechecks current policy.
pub(crate) fn list_metadata(
    db: &Connection,
    read: &MetadataRead<'_>,
    request: &ListRequest,
) -> Result<std::result::Result<CollectionPage<Summary>, ListFailure>> {
    let (namespace, policy, requester) = metadata_read_key(read)?;
    if !matches!(read.policy.read_metadata, ManagementPredicate::Creator) {
        return Ok(Err(ListFailure::Denied));
    }
    if !(1..=100).contains(&request.limit) {
        return Ok(Err(ListFailure::InvalidCursor));
    }
    let Some(after) = decode_metadata_cursor(&request.after, read, &namespace, &policy, &requester)
    else {
        return Ok(Err(ListFailure::InvalidCursor));
    };
    let mut query = db.prepare(
        "SELECT l.id, l.namespace_json, l.principal, l.label, l.grant_json,
                l.grant_digest, l.state, l.head, l.revision, v.expires_at
         FROM day2_credential_lineages l
         JOIN day2_credential_versions v ON v.id = l.head AND v.lineage = l.id
         WHERE l.namespace = ?1 AND l.family = ?2 AND l.family_contract = ?3
           AND l.creator = ?4 AND l.id > ?5
         ORDER BY l.id LIMIT ?6",
    )?;
    let rows = query
        .query_map(
            params![
                namespace,
                read.family.id.as_str(),
                read.family.contract.as_str(),
                read.requester,
                after,
                i64::from(request.limit) + 1,
            ],
            metadata_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_more = rows.len() > usize::from(request.limit);
    let items = rows
        .into_iter()
        .take(usize::from(request.limit))
        .map(|row| project_metadata(row, read).map(|item| item.summary))
        .collect::<Result<Vec<_>>>()?;
    let next = if has_more {
        Some(encode_metadata_cursor(
            read,
            &namespace,
            &policy,
            &requester,
            items
                .last()
                .context("nonempty credential metadata page")?
                .lineage
                .id
                .clone(),
        )?)
    } else {
        None
    };
    Ok(Ok(CollectionPage { items, next }))
}

/// Unknown and invisible lineages share the same absent result.
pub(crate) fn inspect_metadata(
    db: &Connection,
    read: &MetadataRead<'_>,
    lineage: &LineageRef,
) -> Result<Option<Inspection>> {
    let (namespace, _, _) = metadata_read_key(read)?;
    if !matches!(read.policy.read_metadata, ManagementPredicate::Creator)
        || lineage.namespace != *read.namespace
        || lineage.family != read.family.id
        || validate_id(&lineage.id).is_err()
    {
        return Ok(None);
    }
    let row = db
        .query_row(
            "SELECT l.id, l.namespace_json, l.principal, l.label, l.grant_json,
                    l.grant_digest, l.state, l.head, l.revision, v.expires_at
             FROM day2_credential_lineages l
             JOIN day2_credential_versions v ON v.id = l.head AND v.lineage = l.id
             WHERE l.id = ?1 AND l.namespace = ?2 AND l.family = ?3
               AND l.family_contract = ?4 AND l.creator = ?5",
            params![
                lineage.id,
                namespace,
                read.family.id.as_str(),
                read.family.contract.as_str(),
                read.requester,
            ],
            metadata_row,
        )
        .optional()?;
    row.map(|row| project_metadata(row, read)).transpose()
}

/// Current host evidence, established before a managed token reaches the app
/// dispatcher. The caller must also check the selected instance binding, the
/// principal's current policy, audience and resource authorization.
pub(crate) struct IngressVerification<'a> {
    pub namespace: &'a Namespace,
    pub family: &'a str,
    pub family_contract: &'a Digest,
    pub security_epoch: u64,
    pub now: i64,
    pub operation: &'a OperationAuthorityContract,
}

/// Verified private evidence. It cannot be serialized into an app input or
/// treated as an interactive human session.
pub(crate) struct VerifiedIngress {
    pub principal: String,
    pub lineage: String,
    pub version: String,
    pub ceiling: GrantCeiling,
}

/// Select only an active current version in the expected namespace. A malformed,
/// unknown, expired, rotated or revoked token has the same absent result. Store
/// corruption and unavailable exact key versions are errors, not denials.
pub(crate) fn verify_ingress(
    db: &Connection,
    lease: &impl AsRef<super::crypto::VerifierLease>,
    current: IngressVerification<'_>,
    token: &str,
) -> Result<Option<VerifiedIngress>> {
    current.namespace.validate()?;
    validate_id(current.family)?;
    ensure!(
        current.security_epoch > 0,
        "invalid current credential epoch"
    );
    current.operation.verify()?;
    let Ok(selector) = token_selector(token) else {
        return Ok(None);
    };
    let namespace = namespace_key(current.namespace)?;
    struct IngressRow {
        lineage: String,
        version: String,
        namespace_json: String,
        family: String,
        family_contract: String,
        principal: String,
        recipient: String,
        grant_json: String,
        grant_digest: String,
        grant_valid_until: i64,
        epoch: i64,
        issued_at: i64,
        expires_at: i64,
        verifier: Vec<u8>,
        verifier_version: String,
        material_revision: i64,
        material_identity: String,
    }
    let row: Option<IngressRow> = db
        .query_row(
            "SELECT l.id, v.id, l.namespace_json, l.family, l.family_contract,
                    l.principal, l.recipient, l.grant_json, l.grant_digest,
                    l.grant_valid_until, l.security_epoch, v.issued_at, v.expires_at,
                    v.verifier, v.verifier_key_version, m.material_revision, m.identity_json
             FROM day2_credential_versions v
             JOIN day2_credential_lineages l ON l.id = v.lineage
             JOIN day2_credential_material m ON m.version = v.id
             WHERE v.selector = ?1 AND l.namespace = ?2 AND l.family = ?3
               AND l.head = v.id AND l.state = 'active' AND v.state = 'active'
               AND v.security_epoch = l.security_epoch AND v.grant_digest = l.grant_digest",
            params![selector, namespace, current.family],
            |row| {
                Ok(IngressRow {
                    lineage: row.get(0)?,
                    version: row.get(1)?,
                    namespace_json: row.get(2)?,
                    family: row.get(3)?,
                    family_contract: row.get(4)?,
                    principal: row.get(5)?,
                    recipient: row.get(6)?,
                    grant_json: row.get(7)?,
                    grant_digest: row.get(8)?,
                    grant_valid_until: row.get(9)?,
                    epoch: row.get(10)?,
                    issued_at: row.get(11)?,
                    expires_at: row.get(12)?,
                    verifier: row.get(13)?,
                    verifier_version: row.get(14)?,
                    material_revision: row.get(15)?,
                    material_identity: row.get(16)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.family_contract != current.family_contract.as_str()
        || row.epoch != i64::try_from(current.security_epoch)?
        || current.now < row.issued_at
        || current.now >= row.expires_at
        || current.now >= row.grant_valid_until
    {
        return Ok(None);
    }
    let stored_namespace: Namespace = serde_json::from_str(&row.namespace_json)?;
    ensure!(
        stored_namespace == *current.namespace,
        "stored credential namespace mismatch"
    );
    let expected_identity = MaterialIdentity {
        namespace: stored_namespace,
        family: row.family,
        lineage: row.lineage.clone(),
        version: row.version.clone(),
        recipient: row.recipient,
        security_epoch: u64::try_from(row.epoch)?,
        material_revision: u64::try_from(row.material_revision)?,
    };
    let stored_identity: MaterialIdentity = serde_json::from_str(&row.material_identity)?;
    ensure!(
        stored_identity == expected_identity,
        "stored credential material identity mismatch"
    );
    let ceiling: GrantCeiling = serde_json::from_str(&row.grant_json)?;
    ceiling.verify()?;
    ensure!(
        ceiling.digest.as_str() == row.grant_digest && ceiling.subject == row.principal,
        "stored credential grant mismatch"
    );
    if !ceiling.allows(current.operation)?
        || !verify_managed(
            lease,
            &expected_identity,
            &selector,
            &row.verifier,
            &row.verifier_version,
            token,
        )?
    {
        return Ok(None);
    }
    Ok(Some(VerifiedIngress {
        principal: row.principal,
        lineage: row.lineage,
        version: row.version,
        ceiling,
    }))
}

pub(crate) struct VerifiedHumanPost {
    pub namespace: Namespace,
    pub version: String,
    pub recipient: String,
    pub session: String,
    pub attempt: String,
    pub now: i64,
    pub security_epoch: u64,
}

/// Process-local, non-clone, non-serializable authorization for this exact
/// response. A historical receipt cannot construct or recover this value.
pub(crate) struct HumanRevealPermit {
    identity: MaterialIdentity,
    envelope_revision: u64,
    encryption_version: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl HumanRevealPermit {
    pub(crate) fn encryption_version(&self) -> &str {
        &self.encryption_version
    }
    pub(crate) fn security_epoch(&self) -> u64 {
        self.identity.security_epoch
    }
    pub fn into_response_body(self, lease: &KeyLease) -> Result<String> {
        decrypt_for_human(
            lease,
            &self.identity,
            &self.identity,
            self.envelope_revision,
            &self.encryption_version,
            self.nonce,
            &self.ciphertext,
        )
    }
}

/// A private security-origin handler supplies a verified current POST. The
/// authorization commit is the cutoff: closure first denies; authorization
/// first may finish its already-authorized response.
pub(crate) fn authorize_reveal(
    db: &mut Connection,
    post: VerifiedHumanPost,
) -> Result<Option<HumanRevealPermit>> {
    let tx = crate::write_queue::immediate(db)?;
    let Some(pending) = authorize_reveal_in(&tx, post)? else {
        return Ok(None);
    };
    Ok(Some(pending.commit(tx)?))
}

/// Cannot decrypt or be recovered from a receipt. Only a known successful
/// authorization commit converts this into a response permit.
pub(crate) struct PendingReveal(HumanRevealPermit);

impl PendingReveal {
    pub(crate) fn commit(
        self,
        tx: crate::write_queue::WriteTransaction<'_>,
    ) -> Result<HumanRevealPermit> {
        tx.commit()?;
        Ok(self.0)
    }
}

pub(crate) fn authorize_reveal_in(
    tx: &Transaction<'_>,
    post: VerifiedHumanPost,
) -> Result<Option<PendingReveal>> {
    for id in [&post.version, &post.session, &post.attempt] {
        validate_id(id)?;
    }
    crate::authority::valid_actor(&post.recipient)?;
    let expected_namespace_key = namespace_key(&post.namespace)?;
    struct RevealRow {
        identity_json: String,
        namespace_json: String,
        family: String,
        lineage: String,
        material_revision: i64,
        envelope_revision: i64,
        encryption_version: String,
        epoch: i64,
        recipient: String,
        session: String,
        issued_at: i64,
        version_expires_at: i64,
        grant_valid_until: i64,
        expires_at: i64,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    }
    let row: Option<RevealRow> = tx
        .query_row(
            "SELECT m.identity_json, l.namespace_json, l.family, l.id, m.material_revision,
                m.envelope_revision, m.encryption_key_version, l.security_epoch,
                d.recipient, d.session, v.issued_at, v.expires_at,
                l.grant_valid_until, d.expires_at, m.nonce, m.ciphertext
         FROM day2_credential_deliveries d
         JOIN day2_credential_versions v ON v.id = d.version
         JOIN day2_credential_lineages l ON l.id = v.lineage
         JOIN day2_credential_material m ON m.version = v.id
         WHERE d.version = ?1 AND l.namespace = ?2 AND l.head = v.id
           AND l.state = 'active' AND v.state = 'active' AND d.state = 'available'
           AND v.security_epoch = l.security_epoch AND v.grant_digest = l.grant_digest
           AND d.recipient = l.recipient AND d.session = l.session",
            params![post.version, expected_namespace_key],
            |row| {
                Ok(RevealRow {
                    identity_json: row.get(0)?,
                    namespace_json: row.get(1)?,
                    family: row.get(2)?,
                    lineage: row.get(3)?,
                    material_revision: row.get(4)?,
                    envelope_revision: row.get(5)?,
                    encryption_version: row.get(6)?,
                    epoch: row.get(7)?,
                    recipient: row.get(8)?,
                    session: row.get(9)?,
                    issued_at: row.get(10)?,
                    version_expires_at: row.get(11)?,
                    grant_valid_until: row.get(12)?,
                    expires_at: row.get(13)?,
                    nonce: row.get(14)?,
                    ciphertext: row.get(15)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    if u64::try_from(row.epoch)? != post.security_epoch
        || row.recipient != post.recipient
        || row.session != post.session
        || post.now < row.issued_at
        || post.now >= row.version_expires_at
        || post.now >= row.grant_valid_until
        || post.now >= row.expires_at
    {
        return Ok(None);
    }
    let stored_namespace: Namespace = serde_json::from_str(&row.namespace_json)?;
    ensure!(
        stored_namespace == post.namespace,
        "stored credential namespace mismatch"
    );
    let expected_identity = MaterialIdentity {
        namespace: stored_namespace,
        family: row.family,
        lineage: row.lineage,
        version: post.version.clone(),
        recipient: row.recipient.clone(),
        security_epoch: u64::try_from(row.epoch)?,
        material_revision: u64::try_from(row.material_revision)?,
    };
    let stored_identity: MaterialIdentity = serde_json::from_str(&row.identity_json)?;
    ensure!(
        stored_identity == expected_identity,
        "stored delivery identity mismatch"
    );
    let nonce: [u8; 12] = row
        .nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid material nonce"))?;
    tx.execute(
        "INSERT INTO day2_credential_reveals
                (attempt, version, recipient, session, authorized_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            post.attempt,
            post.version,
            row.recipient,
            row.session,
            post.now
        ],
    )?;
    Ok(Some(PendingReveal(HumanRevealPermit {
        identity: expected_identity,
        envelope_revision: u64::try_from(row.envelope_revision)?,
        encryption_version: row.encryption_version,
        nonce,
        ciphertext: row.ciphertext,
    })))
}

/// Resolve delivery only from the successful product invocation's private
/// receipt. Browser fields never supply a version or lineage selector.
pub(crate) fn issued_version(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    invocation: &str,
    family: &str,
    family_contract: &Digest,
) -> Result<String> {
    let mut statement = tx.prepare(
        "SELECT r.version FROM day2_credential_receipts r
        JOIN day2_invocations i ON i.id=r.invocation
        JOIN day2_credential_versions v ON v.id=r.version AND v.lineage=r.lineage
        JOIN day2_credential_lineages l ON l.id=v.lineage AND l.namespace=r.namespace
        WHERE r.namespace=?1 AND r.invocation=?2 AND r.action IN ('issue','rotate') AND i.status='success'
          AND l.family=?3 AND r.family_contract=?4 AND l.family_contract=r.family_contract LIMIT 2",
    )?;
    let versions = statement
        .query_map(
            params![
                namespace_key(namespace)?,
                invocation,
                family,
                family_contract.as_str()
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        versions.len() == 1,
        "successful credential issue receipt required"
    );
    Ok(versions.into_iter().next().expect("checked receipt"))
}

pub(crate) fn close_delivery(tx: &Transaction<'_>, version: &str, reason: &str) -> Result<bool> {
    validate_id(version)?;
    ensure!(
        matches!(
            reason,
            "acknowledged" | "expired" | "session_end" | "epoch_advance"
        ),
        "invalid delivery closure reason"
    );
    Ok(tx.execute(
        "UPDATE day2_credential_deliveries SET state = 'closed', closed_reason = ?2
                   WHERE version = ?1 AND state = 'available'",
        params![version, reason],
    )? == 1)
}

struct ReceiptRow {
    contract: String,
    digest: String,
    action: String,
    lineage: String,
    version: Option<String>,
}

fn receipt(
    tx: &Transaction<'_>,
    namespace: &str,
    invocation: &str,
    slot: u32,
) -> Result<Option<ReceiptRow>> {
    Ok(tx.query_row(
        "SELECT family_contract, request_digest, action, lineage, version
         FROM day2_credential_receipts WHERE namespace = ?1 AND invocation = ?2 AND instruction_slot = ?3",
        params![namespace, invocation, slot],
        |row| Ok(ReceiptRow { contract: row.get(0)?, digest: row.get(1)?,
            action: row.get(2)?, lineage: row.get(3)?, version: row.get(4)? }),
    ).optional()?)
}

fn namespace_key(namespace: &Namespace) -> Result<String> {
    namespace.validate()?;
    Ok(Digest::of(&("credential-namespace-v1", namespace))?
        .as_str()
        .to_owned())
}

fn random_id() -> Result<String> {
    super::effects::record_id()
}

fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b)),
        "invalid credential identifier"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::{
        BindingRef, Name,
        credentials::{
            CredentialRoot, FamilyDeclaration, LineageRef, ManagementState, SourceLocation,
            VersionRef,
        },
        oauth::{
            AuthorityAction, AuthorityNode, OperationAuthorityContract, OperationKind,
            ResourceAudienceRef,
        },
    };
    use proptest::prelude::*;
    use rusqlite::TransactionBehavior;
    use std::collections::{BTreeMap, BTreeSet};
    use tempfile::TempDir;

    fn current_database() -> Result<Connection> {
        let db = Connection::open_in_memory()?;
        install_schema(&db)?;
        Ok(db)
    }

    type SchemaObject = (String, String, String, Option<String>);
    type TableRows = (String, Vec<Vec<rusqlite::types::Value>>);

    #[derive(Debug, PartialEq)]
    struct DatabaseSnapshot {
        objects: Vec<SchemaObject>,
        tables: Vec<TableRows>,
    }

    fn database_snapshot(db: &Connection) -> Result<DatabaseSnapshot> {
        let objects = db
            .prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<SchemaObject>>>()?;
        let mut tables = Vec::new();
        for (kind, name, _, _) in &objects {
            if kind != "table" {
                continue;
            }
            let quoted = name.replace('"', "\"\"");
            let mut statement =
                db.prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY rowid"))?;
            let count = statement.column_count();
            let values = statement
                .query_map([], |row| {
                    (0..count)
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            tables.push((name.clone(), values));
        }
        Ok(DatabaseSnapshot { objects, tables })
    }

    // Model a corrupted restored snapshot with the complete current guard
    // catalog intact. This fixture-only mutation is never an installer repair.
    fn corrupt_current_snapshot(db: &Connection, sql: &str) -> Result<()> {
        let guards = db
            .prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger'")?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        db.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON")?;
        for (name, _) in &guards {
            db.execute_batch(&format!("DROP TRIGGER {name}"))?;
        }
        db.execute_batch(sql)?;
        for (_, guard) in guards {
            db.execute_batch(&guard)?;
        }
        db.execute_batch("PRAGMA ignore_check_constraints=OFF; PRAGMA foreign_keys=ON")?;
        Ok(())
    }

    #[test]
    fn schema_current_issue_history_reopens_without_mutation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("current.sqlite");
        let mut db = Connection::open(&path)?;
        install_schema(&db)?;
        let receipt = committed_issue(&mut db)?;
        let before: (String, Vec<u8>) = db.query_row(
            "SELECT identity_json,ciphertext FROM day2_credential_material",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let current = database_snapshot(&db)?;
        install_schema(&db)?;
        assert_eq!(database_snapshot(&db)?, current);
        assert_eq!(
            db.query_row(
                "SELECT version FROM day2_credential_schema_version",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        assert_eq!(
            db.query_row("SELECT head FROM day2_credential_lineages", [], |row| {
                row.get::<_, String>(0)
            })?,
            receipt.version.unwrap()
        );
        assert_eq!(
            db.query_row(
                "SELECT identity_json,ciphertext FROM day2_credential_material",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            )?,
            before
        );
        drop(db);
        let db = Connection::open(&path)?;
        install_schema(&db)?;
        assert_eq!(
            db.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?,
            1
        );
        Ok(())
    }

    #[test]
    fn schema_rejects_forged_versions_layouts_indexes_fks_and_guards() -> Result<()> {
        for (altered, refusal) in [
            (CREDENTIAL_DDL.replace("version INTEGER PRIMARY KEY", "version INTEGER"), "table shape"),
            (CREDENTIAL_DDL.replace(" STRICT;", ";"), "table constraints"),
            (CREDENTIAL_DDL.replace("CHECK(length(verifier) = 32)", "CHECK(length(verifier) > 0)"), "table constraints"),
            (CREDENTIAL_DDL.replace("REFERENCES day2_credential_versions(id)", ""), "table shape"),
            (CREDENTIAL_DDL.replace("(namespace, family, creator, id)", "(namespace, creator, family, id)"), "index shape"),
            (CREDENTIAL_DDL.replace("ON day2_credential_lineages(namespace, family, principal, id)", "ON day2_credential_lineages(namespace, family, principal, id) WHERE state='active'"), "index shape"),
            (format!("{CREDENTIAL_DDL} CREATE INDEX hidden_credential_index ON day2_credential_material(identity_json);"), "schema object"),
            (format!("{CREDENTIAL_DDL} CREATE TRIGGER injected AFTER INSERT ON day2_credential_versions BEGIN SELECT 1; END;"), "schema object"),
        ] {
            let db = Connection::open_in_memory()?;
            db.execute_batch(&altered)?;
            db.execute("INSERT INTO day2_credential_schema_version VALUES(2)", [])?;
            let before = database_snapshot(&db)?;
            let error = install_schema(&db).unwrap_err();
            assert!(format!("{error:#}").contains(refusal), "{altered}: {error:#}");
            assert_eq!(database_snapshot(&db)?, before);
        }
        for (corrupt, refusal) in [
            (
                "UPDATE day2_credential_schema_version SET version=1",
                "schema version",
            ),
            (
                "UPDATE day2_credential_schema_version SET version=99",
                "schema version",
            ),
            (
                "DELETE FROM day2_credential_schema_version",
                "schema version",
            ),
            (
                "INSERT INTO day2_credential_schema_version VALUES(1)",
                "schema version",
            ),
            (
                "DROP TRIGGER day2_credential_material_shape_UPDATE_v2",
                "invariant guard",
            ),
            (
                "DROP TRIGGER day2_credential_material_shape_UPDATE_v2; CREATE TRIGGER day2_credential_material_shape_UPDATE_v2 AFTER UPDATE ON day2_credential_material BEGIN SELECT 1; END",
                "invariant guard",
            ),
            ("DROP TABLE day2_credential_material", "table shape"),
        ] {
            let db = current_database()?;
            db.execute_batch(corrupt)?;
            let before = database_snapshot(&db)?;
            let error = install_schema(&db).unwrap_err();
            assert!(
                format!("{error:#}").contains(refusal),
                "{corrupt}: {error:#}"
            );
            assert_eq!(database_snapshot(&db)?, before);
        }
        for (partial, refusal) in [
            ("CREATE TABLE day2_credential_schema_version(version INTEGER PRIMARY KEY) STRICT; INSERT INTO day2_credential_schema_version VALUES(2)".to_owned(), "table shape"),
            (CREDENTIAL_DDL.to_owned(), "schema version"),
            (format!("{CREDENTIAL_DDL} INSERT INTO day2_credential_schema_version VALUES(2)"), "invariant guard"),
        ] {
            let db = Connection::open_in_memory()?;
            db.execute_batch(&partial)?;
            let before = database_snapshot(&db)?;
            let error = install_schema(&db).unwrap_err();
            assert!(format!("{error:#}").contains(refusal), "{partial}: {error:#}");
            assert_eq!(database_snapshot(&db)?, before);
        }
        Ok(())
    }

    #[test]
    fn schema_rejects_malformed_current_imports_without_repair() -> Result<()> {
        for corrupt in [
            "UPDATE day2_credential_lineages SET family='bad family'",
            "UPDATE day2_credential_lineages SET principal='domain:example.com'",
            "UPDATE day2_credential_lineages SET label=char(1)",
            "UPDATE day2_credential_lineages SET namespace_json='null'",
            "UPDATE day2_credential_lineages SET namespace_json='{\"installation\":\"wonderly\",\"installation\":\"wonderly\",\"environment\":\"dev\",\"app\":\"transcriber\",\"binding_generation\":2}'",
            "UPDATE day2_credential_lineages SET head='missing'",
            "UPDATE day2_credential_lineages SET revision=5",
            "UPDATE day2_credential_lineages SET grant_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
            "UPDATE day2_credential_versions SET lineage='missing'",
            "UPDATE day2_credential_versions SET predecessor=id",
            "UPDATE day2_credential_versions SET selector='not-canonical'",
            "UPDATE day2_credential_versions SET state='superseded'",
            "UPDATE day2_credential_versions SET security_epoch=8",
            "UPDATE day2_credential_versions SET expires_at=4000",
            "UPDATE day2_credential_material SET identity_json='{}'",
            "UPDATE day2_credential_material SET material_revision=2",
            "DELETE FROM day2_credential_material",
            "DELETE FROM day2_credential_deliveries",
            "UPDATE day2_credential_deliveries SET recipient='different'",
            "UPDATE day2_credential_deliveries SET expires_at=4000",
            "UPDATE day2_credential_deliveries SET state='closed',closed_reason=''",
            "UPDATE day2_credential_receipts SET version=NULL",
            "UPDATE day2_credential_receipts SET action='rotate'",
            "UPDATE day2_credential_receipts SET family_contract='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
            "DELETE FROM day2_credential_receipts",
            "INSERT INTO day2_credential_reveals SELECT 'attempt',id,'different','session-1',1100 FROM day2_credential_versions",
            "INSERT INTO day2_credential_reveals SELECT 'attempt',id,'issuer/human-1','session-1',1300 FROM day2_credential_versions",
        ] {
            let mut db = current_database()?;
            committed_issue(&mut db)?;
            corrupt_current_snapshot(&db, corrupt)?;
            let before = database_snapshot(&db)?;
            let error = install_schema(&db).unwrap_err();
            let message = format!("{error:#}");
            assert!(
                !message.contains("schema version") && !message.contains("invariant guard"),
                "{corrupt}: {message}"
            );
            assert_eq!(database_snapshot(&db)?, before);
            assert_eq!(
                db.query_row(
                    "SELECT version FROM day2_credential_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='trigger'",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                i64::try_from(credential_predicates().len() * 2)?
            );
        }
        Ok(())
    }

    #[test]
    fn schema_guards_reject_direct_new_malformed_rows_and_partial_fields() -> Result<()> {
        let (_directory, mut db) = database()?;
        committed_issue(&mut db)?;
        for corrupt in [
            "UPDATE day2_credential_lineages SET id=NULL",
            "UPDATE day2_credential_lineages SET family=''",
            "UPDATE day2_credential_lineages SET label=char(1)",
            "UPDATE day2_credential_lineages SET label=char(160)",
            "UPDATE day2_credential_lineages SET label='éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé'",
            "UPDATE day2_credential_lineages SET creator='domain:example.com'",
            "UPDATE day2_credential_lineages SET namespace_json='[]'",
            "UPDATE day2_credential_versions SET predecessor=id",
            "UPDATE day2_credential_versions SET selector='not-canonical'",
            "UPDATE day2_credential_material SET identity_json='null'",
            "UPDATE day2_credential_deliveries SET state='closed'",
            "UPDATE day2_credential_deliveries SET closed_reason='rotation'",
            "UPDATE day2_credential_receipts SET action='revoke'",
            "UPDATE day2_credential_receipts SET instruction_slot=4294967296",
            "INSERT INTO day2_credential_reveals SELECT '',id,'issuer/human-1','session-1',1100 FROM day2_credential_versions",
        ] {
            assert!(db.execute_batch(corrupt).is_err(), "accepted {corrupt}");
        }
        install_schema(&db)?;
        Ok(())
    }

    #[test]
    fn schema_budget_refusal_rolls_back_fresh_creation_and_preserves_current_rows() -> Result<()> {
        use crate::oauth::schema::admit_with_limits;
        let fresh = Connection::open_in_memory()?;
        assert!(admit_with_limits(&fresh, 1000, 16_384, 8 * 1_048_576, install_schema).is_err());
        assert_eq!(
            fresh.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name GLOB 'day2_credential_*'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        let mut current = current_database()?;
        let original = committed_issue(&mut current)?;
        let before = database_snapshot(&current)?;
        let error =
            admit_with_limits(&current, 1_000_000, 16_384, 512, install_schema).unwrap_err();
        assert!(format!("{error:#}").contains("materialization budget"));
        assert_eq!(
            current.query_row(
                "SELECT version FROM day2_credential_schema_version",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        assert_eq!(
            current.query_row("SELECT head FROM day2_credential_lineages", [], |row| {
                row.get::<_, String>(0)
            })?,
            original.version.unwrap()
        );
        assert_eq!(database_snapshot(&current)?, before);
        install_schema(&current)?;
        Ok(())
    }

    #[test]
    fn schema_history_keeps_historical_reveal_binding_after_rotation_and_revocation() -> Result<()>
    {
        let mut db = current_database()?;
        let first = committed_issue(&mut db)?;
        let permit = authorize_reveal(
            &mut db,
            post(first.version.as_ref().unwrap(), "historical-reveal"),
        )?
        .unwrap();
        let tx = db.transaction()?;
        let rotated = stage_rotation(
            &tx,
            &lease(),
            &snapshot(&first),
            RotationIntent {
                invocation: "rotation-history",
                instruction_slot: 0,
                recipient: "issuer/human-2",
                session: "session-2",
                issued_at: 1200,
                expires_at: 2100,
                reveal_until: 1400,
            },
        )?;
        assert!(matches!(rotated, RotationResult::Rotated(_)));
        tx.commit()?;
        install_schema(&db)?;
        assert!(!permit.into_response_body(&lease())?.is_empty());
        let tx = db.transaction()?;
        assert!(stage_revoke(&tx, &namespace(), &first.lineage)?);
        let key = namespace_key(&namespace())?;
        let digest = Digest::of(&"historical-revoke")?;
        let reference = super::super::encode_ref("transcription", &snapshot(&first).lineage)?;
        let outcome = serde_json::json!({"already_revoked":false,"lineage":reference,"revision":3})
            .to_string();
        tx.execute("INSERT INTO day2_credential_receipts VALUES(?1,'revocation-history',0,?2,?3,'revoke',?4,NULL)",
            params![key,family().contract.as_str(),digest.as_str(),first.lineage])?;
        tx.execute(
            "INSERT INTO day2_credential_revocations VALUES(?1,'revocation-history',0,?2,?3)",
            params![key, digest.as_str(), outcome],
        )?;
        tx.commit()?;
        install_schema(&db)?;
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM day2_credential_versions WHERE state='revoked'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        db.execute("UPDATE day2_credential_revocations SET outcome='{\"already_revoked\":false,\"lineage\":\"foreign\",\"revision\":3}'",[])?;
        assert!(install_schema(&db).is_err());
        Ok(())
    }

    #[test]
    fn schema_current_restored_rows_are_checked_without_repairing_them() -> Result<()> {
        let (_directory, mut db) = database()?;
        committed_issue(&mut db)?;
        db.execute("UPDATE day2_credential_material SET identity_json='{}'", [])?;
        assert!(install_schema(&db).is_err());
        assert_eq!(
            db.query_row(
                "SELECT version FROM day2_credential_schema_version",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        assert_eq!(
            db.query_row(
                "SELECT identity_json FROM day2_credential_material",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "{}"
        );
        Ok(())
    }

    #[test]
    fn schema_installation_preserves_the_callers_transaction() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", true)?;
        let tx = db.transaction()?;
        install_schema(&tx)?;
        assert!(!tx.is_autocommit());
        tx.rollback()?;
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name GLOB 'day2_credential_*'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn schema_refuses_caller_transaction_that_started_without_foreign_keys() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", false)?;
        assert_eq!(
            db.pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))?,
            0
        );
        db.execute_batch("CREATE TABLE caller(value INTEGER)")?;
        let tx = db.transaction()?;
        tx.execute("INSERT INTO caller VALUES(7)", [])?;
        assert!(install_schema(&tx).is_err());
        assert!(!tx.is_autocommit());
        assert_eq!(
            tx.query_row("SELECT value FROM caller", [], |row| row.get::<_, i64>(0))?,
            7
        );
        tx.rollback()?;
        Ok(())
    }

    #[test]
    fn combined_oauth_and_credential_admission_rolls_back_as_one_scope() -> Result<()> {
        let db = current_database()?;
        db.execute("UPDATE day2_credential_schema_version SET version=99", [])?;
        assert!(
            crate::oauth::schema::admit(&db, |db| {
                crate::oauth::connect::install_schema(db)?;
                install_schema(db)
            })
            .is_err()
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name GLOB 'oauth_*'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT version FROM day2_credential_schema_version",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            99
        );
        Ok(())
    }

    #[test]
    fn schema_refuses_partial_peer_units_before_runtime_creation() -> Result<()> {
        for retained in 1u8..7 {
            let db = current_database()?;
            db.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY)")?;
            super::super::issuance::install(&db)?;
            for (index, table) in CREDENTIAL_PEER_TABLES.iter().enumerate() {
                if retained & (1 << index) == 0 {
                    db.execute_batch(&format!("DROP TABLE {table}"))?;
                }
            }
            let before = database_snapshot(&db)?;
            let error = crate::oauth::schema::admit(&db, |db| {
                install_schema(db)?;
                super::super::issuance::install(db)?;
                install_schema(db)
            })
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("incomplete credential peer schema unit"),
                "retained peer mask {retained}: {error:#}"
            );
            assert_eq!(database_snapshot(&db)?, before);
        }
        Ok(())
    }

    #[test]
    fn schema_recognizes_exact_peer_tables_and_rejects_substituted_peer_layouts() -> Result<()> {
        let db = current_database()?;
        db.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY)")?;
        super::super::issuance::install(&db)?;
        install_schema(&db)?;
        install_schema(&db)?;
        for substitution in [
            "DROP INDEX day2_credential_browser_expiry; CREATE INDEX day2_credential_browser_expiry ON day2_credential_browser(attempt)",
            "DROP TABLE day2_credential_confirmations; CREATE TABLE day2_credential_confirmations(invocation TEXT PRIMARY KEY,confirmation TEXT NOT NULL)",
            "DROP TABLE day2_credential_origins; CREATE TABLE day2_credential_origins(invocation TEXT PRIMARY KEY,evidence TEXT NOT NULL) STRICT",
            "CREATE TABLE day2_credential_unknown(value TEXT)",
        ] {
            let candidate = current_database()?;
            candidate.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY)")?;
            super::super::issuance::install(&candidate)?;
            candidate.execute_batch(substitution)?;
            assert!(
                install_schema(&candidate).is_err(),
                "accepted {substitution}"
            );
            assert_eq!(
                candidate.query_row(
                    "SELECT version FROM day2_credential_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
        }
        Ok(())
    }

    #[test]
    fn schema_rejects_case_substituted_peers_before_runtime_installers_can_reuse_them() -> Result<()>
    {
        for (table, corrupt) in [
            (
                "day2_credential_browser",
                "INSERT INTO DAY2_CREDENTIAL_BROWSER VALUES('invocation','attempt','{}',300)",
            ),
            (
                "day2_credential_confirmations",
                "INSERT INTO DAY2_CREDENTIAL_CONFIRMATIONS VALUES('invocation','{}')",
            ),
            (
                "day2_credential_origins",
                "INSERT INTO day2_invocations VALUES('invocation'); INSERT INTO DAY2_CREDENTIAL_ORIGINS VALUES('invocation','{}')",
            ),
        ] {
            let db = current_database()?;
            db.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY)")?;
            super::super::issuance::install(&db)?;
            let uppercase = table.to_ascii_uppercase();
            let definition: String = db.query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )?;
            db.execute_batch(&format!(
                "DROP TABLE {table}; {}",
                definition.replace(table, &uppercase)
            ))?;
            if table == "day2_credential_browser" {
                db.execute_batch("CREATE INDEX DAY2_CREDENTIAL_BROWSER_EXPIRY ON DAY2_CREDENTIAL_BROWSER(expires_at)")?;
            }
            db.execute_batch(corrupt)?;
            // The actual sibling installers resolve the uppercase objects and
            // do not replace them. Admission must reject before trusting them.
            super::super::issuance::install(&db)?;
            let error = install_schema(&db).unwrap_err();
            assert!(
                format!("{error:#}").contains("unsupported credential schema object"),
                "{error:#}"
            );
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))?,
                1
            );
            assert_eq!(
                db.query_row(
                    "SELECT version FROM day2_credential_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='trigger'",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                i64::try_from(credential_predicates().len() * 2)?
            );
        }
        Ok(())
    }

    #[test]
    fn schema_rejects_case_substituted_owned_objects_before_creating_or_admitting_core()
    -> Result<()> {
        for imported in [
            "CREATE TABLE DAY2_CREDENTIAL_BROWSER(invocation TEXT PRIMARY KEY,attempt TEXT NOT NULL UNIQUE,intent TEXT NOT NULL,expires_at INTEGER NOT NULL) STRICT",
            "CREATE TABLE DAY2_CREDENTIAL_CONFIRMATIONS(invocation TEXT PRIMARY KEY,confirmation TEXT NOT NULL) STRICT",
            "CREATE TABLE DAY2_CREDENTIAL_ORIGINS(invocation TEXT PRIMARY KEY,evidence TEXT NOT NULL) STRICT",
            "CREATE TABLE DAY2_CREDENTIAL_UNKNOWN(value TEXT)",
            "CREATE VIEW DAY2_CREDENTIAL_BROWSER AS SELECT 1 AS value",
            "CREATE VIEW day2_credential_browser AS SELECT 1 AS value",
            "CREATE TABLE unrelated(value TEXT); CREATE TRIGGER DAY2_CREDENTIAL_UNKNOWN AFTER INSERT ON unrelated BEGIN SELECT 1; END",
        ] {
            let db = Connection::open_in_memory()?;
            db.execute_batch(imported)?;
            let before: i64 =
                db.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
            let error = install_schema(&db).unwrap_err();
            assert!(
                format!("{error:#}").contains("unsupported credential schema object"),
                "accepted {imported}: {error:#}"
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM sqlite_master", [], |row| row
                    .get::<_, i64>(0))?,
                before
            );
            assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name='day2_credential_schema_version'", [], |row| row.get::<_, i64>(0))?, 0);
        }
        for imported in [
            "DROP INDEX day2_credential_visible_creator; CREATE INDEX DAY2_CREDENTIAL_VISIBLE_CREATOR ON day2_credential_lineages(namespace,family,creator,id)",
            "CREATE INDEX unrelated_index ON day2_credential_lineages(label)",
            "CREATE TRIGGER unrelated_trigger AFTER INSERT ON day2_credential_reveals BEGIN SELECT 1; END",
            "DROP TRIGGER day2_credential_reveals_shape_INSERT_v2; CREATE TRIGGER DAY2_CREDENTIAL_REVEALS_SHAPE_INSERT_V2 AFTER INSERT ON day2_credential_reveals BEGIN SELECT 1; END",
        ] {
            let db = current_database()?;
            db.execute_batch(imported)?;
            let error = install_schema(&db).unwrap_err();
            assert!(
                format!("{error:#}").contains("unsupported credential schema object"),
                "accepted {imported}: {error:#}"
            );
            assert_eq!(
                db.query_row(
                    "SELECT version FROM day2_credential_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
        }
        Ok(())
    }

    #[test]
    fn schema_raw_metadata_is_debited_before_namespace_classification() -> Result<()> {
        for prefix in ["DAY2_CREDENTIAL_", "unrelated_"] {
            let db = Connection::open_in_memory()?;
            let imported = format!("{prefix}{}", "x".repeat(65_537));
            db.execute_batch(&format!("CREATE TABLE \"{imported}\"(value TEXT)"))?;
            let error = crate::oauth::schema::admit_with_limits(
                &db,
                1_000_000,
                16_384,
                65_536,
                install_schema,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("materialization budget"),
                "{error:#}"
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name=?1 AND tbl_name=?1",
                    [&imported],
                    |row| row.get::<_, i64>(0)
                )?,
                1
            );
            assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name='day2_credential_schema_version'", [], |row| row.get::<_, i64>(0))?, 0);
        }
        Ok(())
    }

    #[test]
    fn schema_canonical_peers_survive_the_same_runtime_sequence_and_reopen() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("canonical-peers.sqlite");
        let db = Connection::open(&path)?;
        install_schema(&db)?;
        db.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY)")?;
        crate::oauth::schema::admit(&db, |db| {
            install_schema(db)?;
            super::super::issuance::install(db)?;
            install_schema(db)
        })?;
        drop(db);
        let db = Connection::open(&path)?;
        crate::oauth::schema::admit(&db, |db| {
            install_schema(db)?;
            super::super::issuance::install(db)?;
            install_schema(db)
        })?;
        assert_eq!(
            db.query_row(
                "SELECT version FROM day2_credential_schema_version",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        for peer in CREDENTIAL_PEER_TABLES {
            assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1 AND tbl_name=?1", [*peer], |row| row.get::<_, i64>(0))?, 1);
        }
        Ok(())
    }

    #[test]
    fn schema_rejects_malformed_peer_rows_without_deleting_history() -> Result<()> {
        for (table, corrupt) in [
            (
                "day2_credential_browser",
                "INSERT INTO day2_credential_browser VALUES('invocation','attempt','{}',300)",
            ),
            (
                "day2_credential_confirmations",
                "INSERT INTO day2_credential_confirmations VALUES('invocation','{}')",
            ),
            (
                "day2_credential_origins",
                "INSERT INTO day2_invocations VALUES('invocation'); INSERT INTO day2_credential_origins VALUES('invocation','{}')",
            ),
        ] {
            let db = current_database()?;
            db.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY)")?;
            super::super::issuance::install(&db)?;
            db.execute_batch(corrupt)?;
            assert!(install_schema(&db).is_err(), "accepted {corrupt}");
            assert_eq!(
                db.query_row(
                    "SELECT version FROM day2_credential_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))?,
                1
            );
        }
        Ok(())
    }

    fn restored_peer_database() -> Result<Connection> {
        let db = current_database()?;
        db.execute_batch(
            "CREATE TABLE day2_invocations(id TEXT PRIMARY KEY, operation TEXT, actor TEXT)",
        )?;
        super::super::issuance::install(&db)?;
        let authority = crate::authority_state::AuthorityStamp {
            epoch: Digest::of(&"historical-authority")?.as_str().to_owned(),
            revision: 2,
        };
        let navigation = super::super::browser::Pending {
            attempt: "attempt".into(),
            invocation: "invocation".into(),
            operation: "IssueCredential".into(),
            actor: "alice@example.com".into(),
            input: serde_json::json!({"label":"integration"}),
            family: "client".into(),
            intent: super::super::lifecycle::Intent::Issue {
                label: "integration".into(),
            },
            artifact: Digest::of(&"historical-artifact")?.as_str().to_owned(),
            authority: authority.clone(),
            binding: Digest::of(&"historical-binding")?,
            created_at: 100,
            expires_at: 400,
            product_return: None,
        };
        let confirmation = super::super::issuance::Confirmation {
            invocation: navigation.invocation.clone(),
            operation: navigation.operation.clone(),
            actor: navigation.actor.clone(),
            subject: "subject-1".into(),
            session: "session-1".into(),
            input: navigation.input.clone(),
            family: navigation.family.clone(),
            intent: navigation.intent.clone(),
            artifact: navigation.artifact.clone(),
            authority,
            binding: navigation.binding.clone(),
            security_epoch: 4,
            authenticated_at: 101,
            approved_at: 102,
            expires_at: 400,
        };
        db.execute(
            "INSERT INTO day2_credential_browser VALUES(?1,?2,?3,?4)",
            params![
                navigation.invocation,
                navigation.attempt,
                serde_json::to_string(&navigation)?,
                navigation.expires_at
            ],
        )?;
        db.execute(
            "INSERT INTO day2_credential_confirmations VALUES(?1,?2)",
            params![
                confirmation.invocation,
                serde_json::to_string(&confirmation)?
            ],
        )?;
        Ok(db)
    }

    #[test]
    fn schema_preserves_historical_peer_intent_and_rejects_retargeting() -> Result<()> {
        let db = restored_peer_database()?;
        install_schema(&db)?;
        install_schema(&db)?;
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM day2_credential_confirmations",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        for (field, value) in [
            ("invocation", serde_json::json!("other")),
            ("actor", serde_json::json!("bob@example.com")),
            ("family", serde_json::json!("other")),
            ("input", serde_json::json!({"label":"other"})),
            ("authenticated_at", serde_json::json!(100)),
            ("expires_at", serde_json::json!(401)),
            ("binding", serde_json::json!(Digest::of(&"other-binding")?)),
            ("unexpected", serde_json::json!(true)),
        ] {
            let candidate = restored_peer_database()?;
            let raw: String = candidate.query_row(
                "SELECT confirmation FROM day2_credential_confirmations",
                [],
                |row| row.get(0),
            )?;
            let mut changed: serde_json::Value = crate::json::decode(raw.as_bytes())?;
            changed.as_object_mut().unwrap().insert(field.into(), value);
            let changed = changed.to_string();
            candidate.execute(
                "UPDATE day2_credential_confirmations SET confirmation=?1",
                [&changed],
            )?;
            assert!(
                install_schema(&candidate).is_err(),
                "accepted changed {field}"
            );
            assert_eq!(
                candidate.query_row(
                    "SELECT version FROM day2_credential_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
            assert_eq!(
                candidate.query_row(
                    "SELECT confirmation FROM day2_credential_confirmations",
                    [],
                    |row| row.get::<_, String>(0)
                )?,
                changed
            );
        }
        // Confirmation evidence can outlive the disposable navigation row.
        db.execute("DELETE FROM day2_credential_browser", [])?;
        install_schema(&db)?;
        Ok(())
    }

    #[test]
    fn schema_peer_scan_refusal_is_bounded_and_preserves_imported_rows() -> Result<()> {
        let db = restored_peer_database()?;
        let oversized = "x".repeat(8 * 1_048_576 + 1);
        db.execute("UPDATE day2_credential_browser SET intent=?1", [&oversized])?;
        let error = install_schema(&db).unwrap_err();
        assert!(format!("{error:#}").contains("materialization budget"));
        assert_eq!(
            db.query_row(
                "SELECT version FROM day2_credential_schema_version",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        assert_eq!(
            usize::try_from(db.query_row(
                "SELECT length(intent) FROM day2_credential_browser",
                [],
                |row| row.get::<_, i64>(0)
            )?)?,
            oversized.len()
        );
        db.execute("UPDATE day2_credential_browser SET intent='{}'", [])?;
        assert!(install_schema(&db).is_err());
        Ok(())
    }

    #[test]
    fn schema_rejects_negative_historical_peer_times_without_rewriting_import() -> Result<()> {
        for navigation in [true, false] {
            let db = restored_peer_database()?;
            let (table, column) = if navigation {
                db.execute("DELETE FROM day2_credential_confirmations", [])?;
                ("day2_credential_browser", "intent")
            } else {
                db.execute("DELETE FROM day2_credential_browser", [])?;
                ("day2_credential_confirmations", "confirmation")
            };
            let raw: String =
                db.query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            let mut changed: serde_json::Value = crate::json::decode(raw.as_bytes())?;
            if navigation {
                changed["created_at"] = serde_json::json!(-10);
                changed["expires_at"] = serde_json::json!(290);
                db.execute("UPDATE day2_credential_browser SET expires_at=290", [])?;
            } else {
                changed["authenticated_at"] = serde_json::json!(-1);
                changed["approved_at"] = serde_json::json!(0);
                changed["expires_at"] = serde_json::json!(299);
            }
            let changed = changed.to_string();
            db.execute(&format!("UPDATE {table} SET {column}=?1"), [&changed])?;
            let error = install_schema(&db).unwrap_err();
            assert!(format!("{error:#}").contains("time"));
            assert_eq!(
                db.query_row(
                    "SELECT version FROM day2_credential_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
            assert_eq!(
                db.query_row(&format!("SELECT {column} FROM {table}"), [], |row| row
                    .get::<_, String>(
                    0
                ))?,
                changed
            );
        }
        Ok(())
    }

    fn replace_peer_intent(
        db: &Connection,
        family: &str,
        intent: &super::super::lifecycle::Intent,
    ) -> Result<()> {
        for (table, column) in [
            ("day2_credential_browser", "intent"),
            ("day2_credential_confirmations", "confirmation"),
        ] {
            let raw: String =
                db.query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            let mut changed: serde_json::Value = crate::json::decode(raw.as_bytes())?;
            changed["family"] = family.into();
            changed["intent"] = serde_json::to_value(intent)?;
            db.execute(
                &format!("UPDATE {table} SET {column}=?1"),
                [changed.to_string()],
            )?;
        }
        Ok(())
    }

    #[test]
    fn schema_restored_lifecycle_refs_keep_historical_alias_distinct_from_family_id() -> Result<()>
    {
        use super::super::lifecycle::Intent;
        let lineage = LineageRef {
            namespace: namespace(),
            family: name("golinks_agent_search"),
            id: "lineage-1".into(),
        };
        for registration in ["agents", "old_agent_keys"] {
            let reference = super::super::encode_ref(registration, &lineage)?;
            for intent in [
                Intent::Rotate {
                    lineage: reference.clone(),
                    head: "version-1".into(),
                    revision: 1,
                },
                Intent::Revoke {
                    lineage: reference.clone(),
                },
            ] {
                let db = restored_peer_database()?;
                replace_peer_intent(&db, lineage.family.as_str(), &intent)?;
                install_schema(&db)?;
                install_schema(&db)?;
                assert_eq!(
                    db.query_row(
                        "SELECT count(*) FROM day2_credential_confirmations",
                        [],
                        |row| row.get::<_, i64>(0)
                    )?,
                    1
                );
            }
        }
        Ok(())
    }

    #[test]
    fn schema_restored_lifecycle_refs_reject_forged_shape_family_and_noncanonical_encoding()
    -> Result<()> {
        use super::super::lifecycle::Intent;
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let lineage = LineageRef {
            namespace: namespace(),
            family: name("golinks_agent_search"),
            id: "lineage-1".into(),
        };
        let raw = serde_json::to_string(&lineage)?;
        let mut wrong_family = lineage.clone();
        wrong_family.family = name("other_family");
        let mut wrong_namespace = lineage.clone();
        wrong_namespace.namespace.binding_generation = 0;
        let mut wrong_id = lineage.clone();
        wrong_id.id = "bad identifier".into();
        let duplicate = format!("{},\"id\":\"other\"}}", raw.trim_end_matches('}'));
        let unknown = format!("{},\"unknown\":true}}", raw.trim_end_matches('}'));
        for reference in [
            super::super::encode_ref("agents", &wrong_family)?,
            super::super::encode_ref("agents", &wrong_namespace)?,
            super::super::encode_ref("agents", &wrong_id)?,
            super::super::encode_ref("bad_alias!", &lineage)?,
            super::super::encode_ref(&"a".repeat(49), &lineage)?,
            format!("cr1_agents_{}", URL_SAFE_NO_PAD.encode(duplicate)),
            format!("cr1_agents_{}", URL_SAFE_NO_PAD.encode(unknown)),
            format!("cr1_agents_{}=", URL_SAFE_NO_PAD.encode(raw)),
        ] {
            let db = restored_peer_database()?;
            replace_peer_intent(
                &db,
                lineage.family.as_str(),
                &Intent::Revoke { lineage: reference },
            )?;
            assert!(install_schema(&db).is_err());
            assert_eq!(
                db.query_row(
                    "SELECT version FROM day2_credential_schema_version",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                2
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM day2_credential_confirmations",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                1
            );
        }
        Ok(())
    }

    #[test]
    fn schema_native_runtime_initialization_reopens_with_installed_peers() -> Result<()> {
        let artifact=std::path::PathBuf::from(std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
            .context("build credential-metadata-conformance and set DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")?);
        let directory = tempfile::tempdir()?;
        let runtime = crate::development::create_for(
            &artifact,
            &directory.path().join("instance"),
            None,
            "alice@example.com",
        )?;
        runtime.initialize()?;
        let reopened = crate::store::Runtime::load(runtime.instance_path(), runtime.app())?;
        reopened.initialize()?;
        let db = crate::store::open(reopened.db())?;
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('day2_credential_browser','day2_credential_confirmations','day2_credential_origins')",[],|row| row.get::<_,i64>(0))?,3);
        Ok(())
    }

    #[test]
    fn schema_admits_historical_origin_and_rejects_identity_substitution() -> Result<()> {
        let (_directory, mut db) = database()?;
        db.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY, operation TEXT NOT NULL, actor TEXT NOT NULL)")?;
        super::super::issuance::install(&db)?;
        let mut intent = issue("historical-origin-issue");
        intent.principal = format!("client/transcription-client/{}", "a".repeat(64));
        intent.ceiling = GrantCeiling::derive(
            intent.ceiling.client,
            intent.principal.clone(),
            intent.ceiling.audience,
            intent.ceiling.roots,
        )?;
        let namespace = intent.namespace.clone();
        let principal = intent.principal.clone();
        let mut origin = serde_json::json!({
            "namespace": intent.namespace, "family": intent.family,
            "family_contract": intent.family_contract,
            "principal": intent.principal, "actor": intent.principal,
            "binding": Digest::new(b"historical selected binding"), "security_epoch": intent.security_epoch,
            "verifier_version": "verify-v1", "ceiling": intent.ceiling,
            "root": "SubmitTranscription", "path": [],
        });
        let prepared = prepare_issue(&lease(), &family(), intent)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = stage_issue(&tx, prepared)?.public_identity().clone();
        tx.commit()?;
        let version = receipt.version.context("fixture version")?;
        origin["lineage"] = serde_json::json!(receipt.lineage);
        origin["version"] = serde_json::json!(version);
        let encoded = origin.to_string();
        db.execute(
            "INSERT INTO day2_invocations VALUES('historical-origin','SubmitTranscription',?1)",
            [&principal],
        )?;
        db.execute(
            "INSERT INTO day2_credential_origins VALUES('historical-origin',?1)",
            [&encoded],
        )?;
        install_schema(&db)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(stage_revoke(&tx, &namespace, &receipt.lineage)?);
        tx.commit()?;
        // Historical evidence remains admissible after revocation; neither its
        // persisted epoch nor the associated ciphertext becomes current again.
        install_schema(&db)?;
        assert_eq!(
            db.query_row(
                "SELECT security_epoch FROM day2_credential_versions WHERE id=?1",
                [&version],
                |row| row.get::<_, i64>(0)
            )?,
            7
        );
        for (field, bad) in [
            ("family", serde_json::json!("other-family")),
            (
                "family_contract",
                serde_json::json!(Digest::new(b"other family")),
            ),
            ("lineage", serde_json::json!("other-lineage")),
            ("version", serde_json::json!("missing-version")),
            ("principal", serde_json::json!("other-principal")),
            ("actor", serde_json::json!("bob@example.com")),
            ("security_epoch", serde_json::json!(8)),
            ("verifier_version", serde_json::json!("verify-v2")),
            ("root", serde_json::json!("unapproved")),
            ("path", serde_json::json!(["unapproved"])),
            ("path", serde_json::json!(vec!["SubmitTranscription"; 17])),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut changed = origin.clone();
            changed[field] = bad;
            let changed = changed.to_string();
            db.execute("UPDATE day2_credential_origins SET evidence=?1", [&changed])?;
            assert!(install_schema(&db).is_err(), "accepted changed {field}");
            assert_eq!(
                db.query_row("SELECT evidence FROM day2_credential_origins", [], |row| {
                    row.get::<_, String>(0)
                })?,
                changed
            );
        }
        let mut changed = origin;
        changed["actor"] = serde_json::json!("bob@example.com");
        db.execute(
            "UPDATE day2_credential_origins SET evidence=?1",
            [changed.to_string()],
        )?;
        db.execute("UPDATE day2_invocations SET actor='bob@example.com'", [])?;
        assert!(
            install_schema(&db).is_err(),
            "matching actor substitutions retargeted a client credential"
        );
        db.execute("UPDATE day2_credential_origins SET evidence=?1", [&encoded])?;
        db.execute("UPDATE day2_invocations SET actor=?1", [&principal])?;
        install_schema(&db)?;
        Ok(())
    }

    fn name(value: &str) -> Name {
        Name::try_from(value.to_owned()).unwrap()
    }

    fn lease() -> KeyLease {
        KeyLease::new(
            &[3u8; 32],
            &[4u8; 32],
            "verify-v1".into(),
            "encrypt-v1".into(),
        )
        .unwrap()
    }

    fn namespace() -> Namespace {
        Namespace {
            installation: name("wonderly"),
            environment: name("dev"),
            app: name("transcriber"),
            binding_generation: 2,
        }
    }

    fn ceiling() -> GrantCeiling {
        let operation = OperationAuthorityContract::derive(
            "SubmitTranscription".into(),
            1,
            Digest::of(&"submit-v1").unwrap(),
            OperationKind::Command,
            AuthorityNode {
                actions: BTreeSet::from([AuthorityAction::LocalData {
                    category: "transcription".into(),
                    policy: Digest::of(&"own").unwrap(),
                    write: true,
                }]),
                children: BTreeMap::new(),
            },
        )
        .unwrap();
        GrantCeiling::derive(
            BindingRef::pin(name("client"), &"client-v1").unwrap(),
            "client-1".into(),
            ResourceAudienceRef(BindingRef::pin(name("transcriber-api"), &"api-v1").unwrap()),
            BTreeMap::from([("SubmitTranscription".into(), operation)]),
        )
        .unwrap()
    }

    fn family() -> ManifestFamily {
        ManifestFamily::derive(
            FamilyDeclaration {
                registration: name("transcription"),
                id: name("transcription-client"),
                profile: ManagedProfile::Client,
                grant: GrantMode::Fixed,
                roots: vec!["SubmitTranscription".into()],
                lifetime_seconds: 2_000,
                source: SourceLocation {
                    file: "ClientKeys.roc".into(),
                    line: 1,
                },
            },
            &BTreeMap::from([(
                "SubmitTranscription".into(),
                CredentialRoot {
                    authority: ceiling().roots["SubmitTranscription"].clone(),
                    direct_ingress: true,
                    interactive_security: false,
                    single_resource_model: None,
                },
            )]),
        )
        .unwrap()
    }

    fn issue(invocation: &str) -> IssueIntent {
        IssueIntent {
            namespace: namespace(),
            family: "transcription-client".into(),
            family_contract: family().contract,
            invocation: invocation.into(),
            instruction_slot: 0,
            principal: "client-1".into(),
            creator: "issuer/human-1".into(),
            recipient: "issuer/human-1".into(),
            session: "session-1".into(),
            label: "Studio transcription".into(),
            ceiling: ceiling(),
            issued_at: 1_000,
            expires_at: 2_000,
            grant_valid_until: 3_000,
            reveal_until: 1_300,
            security_epoch: 7,
        }
    }

    fn database() -> Result<(TempDir, Connection)> {
        let dir = tempfile::tempdir()?;
        let db = Connection::open(dir.path().join("app.sqlite"))?;
        install_schema(&db)?;
        Ok((dir, db))
    }

    fn committed_issue(db: &mut Connection) -> Result<PublicReceipt> {
        let prepared = prepare_issue(&lease(), &family(), issue("invocation-1"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let receipt = stage_issue(&tx, prepared)?.public_identity().clone();
        tx.commit()?;
        Ok(receipt)
    }

    fn creator_policy() -> ManagementPolicy {
        ManagementPolicy {
            identity_authority: BindingRef::pin(name("people"), &"people-v1").unwrap(),
            issue: ManagementPredicate::Creator,
            read_metadata: ManagementPredicate::Creator,
            rotate: ManagementPredicate::Creator,
            revoke: ManagementPredicate::Creator,
        }
    }

    fn post(version: &str, attempt: &str) -> VerifiedHumanPost {
        VerifiedHumanPost {
            namespace: namespace(),
            version: version.into(),
            recipient: "issuer/human-1".into(),
            session: "session-1".into(),
            attempt: attempt.into(),
            now: 1_100,
            security_epoch: 7,
        }
    }

    fn snapshot(receipt: &PublicReceipt) -> ManagementSnapshot {
        let lineage = LineageRef {
            namespace: namespace(),
            family: name("transcription-client"),
            id: receipt.lineage.clone(),
        };
        ManagementSnapshot {
            head: VersionRef {
                lineage: lineage.clone(),
                id: receipt.version.clone().unwrap(),
            },
            lineage,
            revision: 1,
            state: ManagementState::Active,
        }
    }

    fn ingress<'a>(
        namespace: &'a Namespace,
        contract: &'a Digest,
        operation: &'a OperationAuthorityContract,
        epoch: u64,
        now: i64,
    ) -> IngressVerification<'a> {
        IngressVerification {
            namespace,
            family: "transcription-client",
            family_contract: contract,
            security_epoch: epoch,
            now,
            operation,
        }
    }

    #[test]
    fn email_session_principal_can_read_only_its_own_metadata() -> Result<()> {
        let (_dir, mut db) = database()?;
        let mut intent = issue("email-invocation");
        intent.creator = "alice@example.com".into();
        intent.recipient = "alice@example.com".into();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        stage_issue(&tx, prepare_issue(&lease(), &family(), intent)?)?;
        tx.commit()?;
        let family = family();
        let namespace = namespace();
        let policy = creator_policy();
        let request = ListRequest {
            after: FamilyCursor {
                family: family.id.clone(),
                opaque: String::new(),
            },
            limit: 10,
        };
        let read = MetadataRead {
            namespace: &namespace,
            family: &family,
            policy: &policy,
            requester: "alice@example.com",
        };
        assert_eq!(list_metadata(&db, &read, &request)?.unwrap().items.len(), 1);
        let invisible = MetadataRead {
            requester: "bob@example.com",
            ..read
        };
        assert!(
            list_metadata(&db, &invisible, &request)?
                .unwrap()
                .items
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn metadata_pages_are_bounded_to_current_family_namespace_creator_and_policy() -> Result<()> {
        let (_dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let mut second_intent = issue("invocation-2");
        second_intent.label = "Second key".into();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let second = stage_issue(&tx, prepare_issue(&lease(), &family(), second_intent)?)?
            .public_identity()
            .clone();
        tx.commit()?;
        let mut other_intent = issue("invocation-3");
        other_intent.creator = "issuer/other".into();
        other_intent.recipient = "issuer/other".into();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let other = stage_issue(&tx, prepare_issue(&lease(), &family(), other_intent)?)?
            .public_identity()
            .clone();
        tx.commit()?;

        let family = family();
        let policy = creator_policy();
        let namespace = namespace();
        let read = MetadataRead {
            namespace: &namespace,
            family: &family,
            policy: &policy,
            requester: "issuer/human-1",
        };
        let start = FamilyCursor {
            family: family.id.clone(),
            opaque: String::new(),
        };
        let first_page = list_metadata(
            &db,
            &read,
            &ListRequest {
                after: start,
                limit: 1,
            },
        )?
        .map_err(|_| anyhow::anyhow!("first page refused"))?;
        assert_eq!(first_page.items.len(), 1);
        let cursor = first_page.next.context("expected second page")?;
        let second_page = list_metadata(
            &db,
            &read,
            &ListRequest {
                after: cursor.clone(),
                limit: 1,
            },
        )?
        .map_err(|_| anyhow::anyhow!("second page refused"))?;
        assert_eq!(second_page.items.len(), 1);
        assert!(second_page.next.is_none());
        let found = [
            first_page.items[0].lineage.id.clone(),
            second_page.items[0].lineage.id.clone(),
        ];
        assert!(found.contains(&first.lineage));
        assert!(found.contains(&second.lineage));
        assert!(!found.contains(&other.lineage));
        let visible = inspect_metadata(&db, &read, &snapshot(&first).lineage)?
            .context("creator cannot inspect own credential")?;
        assert_eq!(
            visible.summary.current_version.id.as_str(),
            first.version.as_deref().unwrap()
        );
        assert_eq!(visible.rotation.unwrap().revision, 1);
        assert!(inspect_metadata(&db, &read, &snapshot(&other).lineage)?.is_none());

        let changed_policy = ManagementPolicy {
            identity_authority: BindingRef::pin(name("people"), &"people-v2")?,
            ..policy.clone()
        };
        let changed = MetadataRead {
            policy: &changed_policy,
            ..read
        };
        assert!(matches!(
            list_metadata(
                &db,
                &changed,
                &ListRequest {
                    after: cursor.clone(),
                    limit: 1
                }
            )?,
            Err(ListFailure::InvalidCursor)
        ));
        let other_requester = MetadataRead {
            requester: "issuer/other",
            ..read
        };
        assert!(matches!(
            list_metadata(
                &db,
                &other_requester,
                &ListRequest {
                    after: cursor,
                    limit: 1
                }
            )?,
            Err(ListFailure::InvalidCursor)
        ));
        assert!(matches!(
            list_metadata(
                &db,
                &other_requester,
                &ListRequest {
                    after: FamilyCursor {
                        family: family.id.clone(),
                        opaque: "malformed!".into(),
                    },
                    limit: 1,
                }
            )?,
            Err(ListFailure::InvalidCursor)
        ));
        let group_policy = ManagementPolicy {
            read_metadata: ManagementPredicate::MemberOf {
                group: name("admins"),
            },
            ..policy.clone()
        };
        assert!(matches!(
            list_metadata(
                &db,
                &MetadataRead {
                    policy: &group_policy,
                    ..read
                },
                &ListRequest {
                    after: FamilyCursor {
                        family: family.id.clone(),
                        opaque: String::new(),
                    },
                    limit: 1,
                }
            )?,
            Err(ListFailure::Denied)
        ));
        let mut foreign = snapshot(&second).lineage;
        foreign.namespace.app = name("another-app");
        assert!(inspect_metadata(&db, &read, &foreign)?.is_none());

        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(stage_revoke(&tx, &namespace, &first.lineage)?);
        tx.commit()?;
        let revoked = inspect_metadata(&db, &read, &snapshot(&first).lineage)?
            .context("revoked lineage must remain visible for management")?;
        assert_eq!(revoked.summary.state, ManagementState::Revoked);
        db.execute(
            "UPDATE day2_credential_lineages SET grant_digest = ?1 WHERE id = ?2",
            params![Digest::new(b"substituted").as_str(), first.lineage],
        )?;
        assert!(inspect_metadata(&db, &read, &snapshot(&first).lineage).is_err());
        Ok(())
    }

    #[test]
    fn issuance_requires_exact_declared_family_and_grant() -> Result<()> {
        let family = family();
        let mut wrong = issue("wrong-contract");
        wrong.family_contract = Digest::of(&"another-family")?;
        assert!(prepare_issue(&lease(), &family, wrong).is_err());

        let mut excessive = issue("excessive-grant");
        let extra = OperationAuthorityContract::derive(
            "OtherOperation".into(),
            1,
            Digest::of(&"other")?,
            OperationKind::Command,
            AuthorityNode {
                actions: BTreeSet::new(),
                children: BTreeMap::new(),
            },
        )?;
        let mut roots = excessive.ceiling.roots.clone();
        roots.insert(extra.operation.clone(), extra);
        excessive.ceiling = GrantCeiling::derive(
            excessive.ceiling.client.clone(),
            excessive.principal.clone(),
            excessive.ceiling.audience.clone(),
            roots,
        )?;
        assert!(prepare_issue(&lease(), &family, excessive).is_err());

        let mut too_long = issue("excessive-lifetime");
        too_long.expires_at = too_long.issued_at + 2_001;
        too_long.grant_valid_until = too_long.expires_at;
        assert!(prepare_issue(&lease(), &family, too_long).is_err());
        Ok(())
    }

    #[test]
    fn issue_rolls_back_with_product_write_and_retries_recover_same_receipt() -> Result<()> {
        let (_dir, mut db) = database()?;
        db.execute_batch("CREATE TABLE product_registration (credential TEXT NOT NULL)")?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending = stage_issue(
            &tx,
            prepare_issue(&lease(), &family(), issue("invocation-1"))?,
        )?;
        tx.execute(
            "INSERT INTO product_registration VALUES (?1)",
            [&pending.public_identity().lineage],
        )?;
        tx.rollback()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_credential_lineages", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM product_registration", [], |r| r
                .get::<_, i64>(0))?,
            0
        );

        let committed = committed_issue(&mut db)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let retried = stage_issue(
            &tx,
            prepare_issue(&lease(), &family(), issue("invocation-1"))?,
        )?;
        assert_eq!(retried.public_identity(), &committed);
        tx.commit()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_credential_versions", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            1
        );
        let mut changed = issue("invocation-1");
        changed.label = "Changed intent".into();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(stage_issue(&tx, prepare_issue(&lease(), &family(), changed)?).is_err());
        Ok(())
    }

    #[test]
    fn stale_rotation_cannot_create_a_second_successor_and_revoke_is_terminal() -> Result<()> {
        let (_dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let expected = snapshot(&first);
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rotated = match stage_rotation(
            &tx,
            &lease(),
            &expected,
            RotationIntent {
                invocation: "rotation-1",
                instruction_slot: 0,
                recipient: "issuer/human-1",
                session: "session-1",
                issued_at: 1_200,
                expires_at: 2_100,
                reveal_until: 1_400,
            },
        )? {
            RotationResult::Rotated(pending) => pending.public_identity().clone(),
            RotationResult::Conflict => anyhow::bail!("first rotation conflicted"),
        };
        tx.commit()?;
        assert_eq!(rotated.lineage, first.lineage);
        assert_ne!(rotated.version, first.version);
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(matches!(
            stage_rotation(
                &tx,
                &lease(),
                &expected,
                RotationIntent {
                    invocation: "rotation-2",
                    instruction_slot: 0,
                    recipient: "issuer/human-1",
                    session: "session-1",
                    issued_at: 1_200,
                    expires_at: 2_100,
                    reveal_until: 1_400
                }
            )?,
            RotationResult::Conflict
        ));
        tx.commit()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_credential_versions", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            2
        );
        assert!(
            authorize_reveal(
                &mut db,
                post(first.version.as_ref().unwrap(), "old-attempt")
            )?
            .is_none()
        );
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(stage_revoke(&tx, &namespace(), &first.lineage)?);
        tx.commit()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(!stage_revoke(&tx, &namespace(), &first.lineage)?);
        tx.commit()?;
        assert!(
            authorize_reveal(
                &mut db,
                post(rotated.version.as_ref().unwrap(), "after-revoke")
            )?
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn concurrent_sqlite_rotations_create_exactly_one_successor() -> Result<()> {
        let (directory, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let expected = snapshot(&first);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for id in ["race-1", "race-2"] {
            let path = directory.path().join("app.sqlite");
            let expected = expected.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || -> Result<bool> {
                let mut connection = Connection::open(path)?;
                connection.busy_timeout(std::time::Duration::from_secs(10))?;
                barrier.wait();
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let result = stage_rotation(
                    &tx,
                    &lease(),
                    &expected,
                    RotationIntent {
                        invocation: id,
                        instruction_slot: 0,
                        recipient: "issuer/human-1",
                        session: "session-1",
                        issued_at: 1_200,
                        expires_at: 2_100,
                        reveal_until: 1_400,
                    },
                )?;
                let rotated = matches!(result, RotationResult::Rotated(_));
                tx.commit()?;
                Ok(rotated)
            }));
        }
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().expect("rotation thread"))
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(outcomes.iter().filter(|success| **success).count(), 1);
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM day2_credential_versions WHERE predecessor IS NOT NULL",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM day2_credential_receipts WHERE action='rotate'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn reveal_commit_is_the_precise_closure_cutoff() -> Result<()> {
        let (_dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let version = first.version.as_ref().unwrap();
        assert!(
            authorize_reveal(
                &mut db,
                VerifiedHumanPost {
                    now: 999,
                    ..post(version, "before-issuance")
                }
            )?
            .is_none()
        );
        assert!(
            authorize_reveal(
                &mut db,
                VerifiedHumanPost {
                    now: 1_300,
                    ..post(version, "after-delivery-window")
                }
            )?
            .is_none()
        );
        let wrong = VerifiedHumanPost {
            recipient: "issuer/other".into(),
            ..post(version, "wrong")
        };
        assert!(authorize_reveal(&mut db, wrong)?.is_none());
        let permit = authorize_reveal(&mut db, post(version, "allowed"))?.unwrap();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(close_delivery(&tx, version, "acknowledged")?);
        tx.commit()?;
        assert!(authorize_reveal(&mut db, post(version, "too-late"))?.is_none());
        let token = permit.into_response_body(&lease())?;
        assert_eq!(
            super::super::crypto::token_selector(&token)?,
            db.query_row(
                "SELECT selector FROM day2_credential_versions WHERE id = ?1",
                [version],
                |r| r.get::<_, String>(0)
            )?
        );
        assert!(!format!("{first:?}").contains(&token));
        Ok(())
    }

    #[test]
    fn private_state_survives_reopen_without_public_secret_projection() -> Result<()> {
        let (dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        drop(db);
        let mut reopened = Connection::open(dir.path().join("app.sqlite"))?;
        install_schema(&reopened)?;
        let permit = authorize_reveal(
            &mut reopened,
            post(first.version.as_ref().unwrap(), "reopened"),
        )?
        .unwrap();
        let token = permit.into_response_body(&lease())?;
        let public = format!("{first:?}");
        assert!(!public.contains(&token));
        Ok(())
    }

    #[test]
    fn reveal_rejects_foreign_namespace_and_substituted_material_identity() -> Result<()> {
        let (_dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let version = first.version.as_ref().unwrap();
        let mut foreign = post(version, "foreign");
        foreign.namespace.app = name("another-app");
        assert!(authorize_reveal(&mut db, foreign)?.is_none());
        let identity_json: String = db.query_row(
            "SELECT identity_json FROM day2_credential_material WHERE version = ?1",
            [version],
            |row| row.get(0),
        )?;
        let mut identity: MaterialIdentity = serde_json::from_str(&identity_json)?;
        identity.lineage = "different-lineage".into();
        db.execute(
            "UPDATE day2_credential_material SET identity_json = ?2 WHERE version = ?1",
            params![version, serde_json::to_string(&identity)?],
        )?;
        assert!(authorize_reveal(&mut db, post(version, "substituted")).is_err());
        Ok(())
    }

    #[test]
    fn ingress_requires_current_family_epoch_contract_and_operation_ceiling() -> Result<()> {
        let (_dir, mut db) = database()?;
        let receipt = committed_issue(&mut db)?;
        let permit = authorize_reveal(
            &mut db,
            post(receipt.version.as_ref().unwrap(), "ingress-token"),
        )?
        .unwrap();
        let token = permit.into_response_body(&lease())?;
        let namespace = namespace();
        let contract = family().contract;
        let root = ceiling().roots["SubmitTranscription"].clone();
        let verified = verify_ingress(
            &db,
            &lease(),
            ingress(&namespace, &contract, &root, 7, 1_100),
            &token,
        )?
        .context("committed active credential should verify")?;
        assert_eq!(verified.principal, "client-1");
        assert_eq!(verified.lineage, receipt.lineage);
        assert_eq!(verified.version, receipt.version.unwrap());
        assert_eq!(verified.ceiling.digest, ceiling().digest);

        let mut foreign = namespace.clone();
        foreign.app = name("other-app");
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&foreign, &contract, &root, 7, 1_100),
                &token
            )?
            .is_none()
        );
        let changed = Digest::of(&"changed-family")?;
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &changed, &root, 7, 1_100),
                &token
            )?
            .is_none()
        );
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &root, 8, 1_100),
                &token
            )?
            .is_none()
        );
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &root, 7, 999),
                &token
            )?
            .is_none()
        );
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &root, 7, 2_000),
                &token
            )?
            .is_none()
        );
        let ungranted = OperationAuthorityContract::derive(
            "OtherOperation".into(),
            root.version,
            root.operation_contract.clone(),
            root.kind.clone(),
            root.closure.clone(),
        )?;
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &ungranted, 7, 1_100),
                &token
            )?
            .is_none()
        );
        let mut tampered = token.into_bytes();
        let last = tampered.last_mut().context("token byte")?;
        *last = if *last == b'A' { b'B' } else { b'A' };
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &root, 7, 1_100),
                std::str::from_utf8(&tampered)?
            )?
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn ingress_rejects_rotated_and_revoked_versions() -> Result<()> {
        let (_dir, mut db) = database()?;
        let first = committed_issue(&mut db)?;
        let first_token = authorize_reveal(
            &mut db,
            post(first.version.as_ref().unwrap(), "initial-ingress"),
        )?
        .unwrap()
        .into_response_body(&lease())?;
        let namespace = namespace();
        let contract = family().contract;
        let root = ceiling().roots["SubmitTranscription"].clone();
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &root, 7, 1_300),
                &first_token
            )?
            .is_some()
        );

        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rotated = match stage_rotation(
            &tx,
            &lease(),
            &snapshot(&first),
            RotationIntent {
                invocation: "rotation-ingress",
                instruction_slot: 0,
                recipient: "issuer/human-1",
                session: "session-1",
                issued_at: 1_200,
                expires_at: 2_100,
                reveal_until: 1_400,
            },
        )? {
            RotationResult::Rotated(pending) => pending.public_identity().clone(),
            RotationResult::Conflict => anyhow::bail!("first rotation conflicted"),
        };
        tx.commit()?;
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &root, 7, 1_300),
                &first_token
            )?
            .is_none()
        );
        let next_token = authorize_reveal(
            &mut db,
            VerifiedHumanPost {
                now: 1_300,
                ..post(rotated.version.as_ref().unwrap(), "rotated-ingress")
            },
        )?
        .unwrap()
        .into_response_body(&lease())?;
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &root, 7, 1_300),
                &next_token
            )?
            .is_some()
        );
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert!(stage_revoke(&tx, &namespace, &first.lineage)?);
        tx.commit()?;
        assert!(
            verify_ingress(
                &db,
                &lease(),
                ingress(&namespace, &contract, &root, 7, 1_300),
                &next_token
            )?
            .is_none()
        );
        Ok(())
    }

    /// Independent abstract state: no SQL or production transition helper is
    /// called to compute expected outcomes. Each schedule runs on real SQLite.
    fn run_state_schedule(actions: &[u8]) -> Result<()> {
        struct Model {
            active: bool,
            delivery_open: bool,
            head: PublicReceipt,
            revision: u64,
        }
        let (_dir, mut db) = database()?;
        let initial = committed_issue(&mut db)?;
        let mut model = Model {
            active: true,
            delivery_open: true,
            head: initial.clone(),
            revision: 1,
        };
        for (index, action) in actions.iter().enumerate() {
            match action % 5 {
                0 | 1 => {
                    let expected = if action % 5 == 0 {
                        let mut current = snapshot(&model.head);
                        current.revision = model.revision;
                        current
                    } else {
                        snapshot(&initial)
                    };
                    let should_rotate = model.active
                        && expected.revision == model.revision
                        && expected.head.id == model.head.version.as_ref().unwrap().as_str();
                    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    let result = stage_rotation(
                        &tx,
                        &lease(),
                        &expected,
                        RotationIntent {
                            invocation: &format!("rotation-{index}"),
                            instruction_slot: 0,
                            recipient: "issuer/human-1",
                            session: "session-1",
                            issued_at: 1_100,
                            expires_at: 2_000,
                            reveal_until: 1_300,
                        },
                    )?;
                    match result {
                        RotationResult::Rotated(pending) => {
                            ensure!(should_rotate, "model rejected an accepted rotation");
                            model.head = pending.public_identity().clone();
                            model.revision += 1;
                            model.delivery_open = true;
                        }
                        RotationResult::Conflict => {
                            ensure!(!should_rotate, "model accepted a rejected rotation");
                        }
                    }
                    tx.commit()?;
                }
                2 => {
                    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    let changed = stage_revoke(&tx, &namespace(), &model.head.lineage)?;
                    ensure!(changed == model.active, "model and revocation differ");
                    if changed {
                        model.active = false;
                        model.delivery_open = false;
                        model.revision += 1;
                    }
                    tx.commit()?;
                }
                3 => {
                    let found = authorize_reveal(
                        &mut db,
                        post(
                            model.head.version.as_ref().unwrap(),
                            &format!("reveal-{index}"),
                        ),
                    )?
                    .is_some();
                    ensure!(
                        found == (model.active && model.delivery_open),
                        "model and reveal eligibility differ"
                    );
                }
                _ => {
                    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    let closed =
                        close_delivery(&tx, model.head.version.as_ref().unwrap(), "acknowledged")?;
                    ensure!(
                        closed == model.delivery_open,
                        "model and delivery closure differ"
                    );
                    model.delivery_open = false;
                    tx.commit()?;
                }
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn sqlite_lineage_transitions_match_independent_model(actions in prop::collection::vec(0u8..5, 0..24)) {
            run_state_schedule(&actions).unwrap();
        }
    }
}

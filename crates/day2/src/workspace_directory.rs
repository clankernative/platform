//! Workspace Directory capture invariants and bounded read models.
//!
//! Provider parsing and capture integrity live here; Home owns all path policy,
//! ancestry decisions and cache reconciliation.
use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

pub const SOURCE_TTL_SECONDS: i64 = 900;
pub const MAX_ORG_UNITS: usize = 10_000;
pub const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PAGE_ITEMS: usize = 32;
pub const MAX_PAGE_BYTES: usize = 16 * 1024;
pub const MAX_PROVIDER_CALLS: u64 = 5;
pub const MAX_CAPTURE_REQUEST_BYTES: u64 = 32 * 1024;
pub const MAX_CAPTURE_RESPONSE_BYTES: u64 = (MAX_RESPONSE_BYTES + 4 * 16 * 1024) as u64;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_USER_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
pub const USER_READ_SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly";
pub const ORG_UNIT_READ_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly";
const DIRECTORY_ORIGIN: &str = "https://admin.googleapis.com";
const IAM_ORIGIN: &str = "https://iamcredentials.googleapis.com";
const OAUTH_ORIGIN: &str = "https://oauth2.googleapis.com";
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticationPlan {
    DirectServiceAccount {
        service_account: String,
    },
    DomainWideDelegation {
        service_account: String,
        delegated_admin: String,
    },
}

impl AuthenticationPlan {
    pub fn from_connection(
        connection: &day2_capabilities::integrations::LiveConnection,
    ) -> Result<Self> {
        use day2_capabilities::integrations::{LiveConnection, WorkspaceDirectoryAuth};
        let LiveConnection::WorkspaceDirectory {
            service_account,
            auth,
        } = connection
        else {
            anyhow::bail!("workspace_directory_connection_invalid")
        };
        connection
            .validate()
            .map_err(|_| anyhow::anyhow!("workspace_directory_connection_invalid"))?;
        Ok(match auth {
            WorkspaceDirectoryAuth::DirectServiceAccount => Self::DirectServiceAccount {
                service_account: service_account.clone(),
            },
            WorkspaceDirectoryAuth::DomainWideDelegation { delegated_admin } => {
                Self::DomainWideDelegation {
                    service_account: service_account.clone(),
                    delegated_admin: delegated_admin.clone(),
                }
            }
        })
    }

    pub fn scopes(&self) -> [&'static str; 2] {
        [USER_READ_SCOPE, ORG_UNIT_READ_SCOPE]
    }

    pub fn fixed_origins(&self) -> [&'static str; 3] {
        [DIRECTORY_ORIGIN, IAM_ORIGIN, OAUTH_ORIGIN]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureInput {
    pub customer_id: String,
    pub connection_id: String,
    pub actor: String,
    pub captured_at: i64,
}

/// Explicit ports for the reviewed provider calls. Implementations own HTTP,
/// identity tokens and OAuth; this pipeline owns ordering, bounds and all-or-none
/// publication. No provider response or token is returned to the caller.
pub trait DirectoryReadPort {
    fn user_org_unit_path(&mut self, actor: &str) -> Result<String>;
    fn list_org_units(&mut self) -> Result<ProviderPage>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderPage {
    pub units: Vec<OrgUnit>,
    pub response_bytes: usize,
    pub hierarchy_captured_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteCapture {
    pub metadata: Capture,
    pub connection_id: String,
    pub units: Vec<OrgUnit>,
    pub expires_at: i64,
}

/// Deterministic read pipeline. It rejects oversized or incomplete responses;
/// a caller receives a capture only after validating the full source snapshot.
pub fn collect_complete(
    input: CaptureInput,
    port: &mut dyn DirectoryReadPort,
) -> Result<CompleteCapture> {
    ensure!(
        input.captured_at >= 0
            && !input.customer_id.is_empty()
            && input.customer_id.len() <= 256
            && !input.connection_id.is_empty()
            && input.connection_id.len() <= 128
            && !input.actor.is_empty()
            && input.actor.len() <= 320,
        "workspace_directory_capture_identity_invalid"
    );
    let user_path = port
        .user_org_unit_path(&input.actor)
        .map_err(|_| anyhow::anyhow!("workspace_directory_user_lookup_failed"))?;
    validate_path(&user_path)?;
    let result = port
        .list_org_units()
        .map_err(|_| anyhow::anyhow!("workspace_directory_hierarchy_lookup_failed"))?;
    ensure!(
        result.response_bytes <= MAX_RESPONSE_BYTES,
        "workspace_directory_response_too_large"
    );
    ensure!(
        result.response_bytes <= MAX_CAPTURE_BYTES,
        "workspace_directory_capture_too_large"
    );
    ensure!(
        result.hierarchy_captured_at <= input.captured_at
            && input.captured_at - result.hierarchy_captured_at < SOURCE_TTL_SECONDS,
        "workspace_directory_hierarchy_cache_expired"
    );
    let units = validate_complete(result.units, &user_path)?;
    let id = crate::digest(&serde_json::to_vec(&(
        "workspace-directory-capture-v1",
        &input.customer_id,
        &input.connection_id,
        &input.actor,
        input.captured_at,
        &user_path,
        &units,
    ))?);
    let expires_at = result
        .hierarchy_captured_at
        .checked_add(SOURCE_TTL_SECONDS)
        .context("workspace_directory_expiry_overflow")?;
    Ok(CompleteCapture {
        connection_id: input.connection_id,
        metadata: Capture {
            id,
            customer_id: input.customer_id,
            actor: input.actor,
            user_path,
            org_unit_count: u64::try_from(units.len())?,
            captured_at: input.captured_at,
        },
        units,
        expires_at,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrgUnit {
    pub id: String,
    pub name: String,
    pub path: String,
    pub parent_id: Option<String>,
    pub parent_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub id: String,
    pub customer_id: String,
    pub actor: String,
    pub user_path: String,
    pub org_unit_count: u64,
    pub captured_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub items: Vec<OrgUnit>,
    pub next: u64,
    pub done: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryOrgUnit {
    org_unit_id: String,
    name: String,
    org_unit_path: String,
    parent_org_unit_id: Option<String>,
    parent_org_unit_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryUser {
    customer_id: String,
    org_unit_path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryPage {
    organization_units: Vec<DirectoryOrgUnit>,
    next_page_token: Option<String>,
}

/// Parse exactly one provider response under its response-byte ceiling.
pub fn parse_org_unit_response(bytes: &[u8]) -> Result<Vec<OrgUnit>> {
    ensure!(
        bytes.len() <= MAX_RESPONSE_BYTES,
        "workspace_directory_response_too_large"
    );
    let raw: DirectoryPage = crate::json::decode_evidence(bytes)
        .map_err(|_| anyhow::anyhow!("workspace_directory_response_invalid"))?;
    ensure!(
        raw.organization_units.len() <= MAX_ORG_UNITS,
        "workspace_directory_org_unit_count_invalid"
    );
    ensure!(
        raw.next_page_token.is_none(),
        "workspace_directory_unexpected_pagination"
    );
    let items = raw
        .organization_units
        .into_iter()
        .map(|unit| {
            let value = OrgUnit {
                id: unit.org_unit_id,
                name: unit.name,
                path: unit.org_unit_path,
                parent_id: unit.parent_org_unit_id,
                parent_path: unit.parent_org_unit_path,
            };
            validate_org_unit(&value)?;
            Ok(value)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(items)
}

pub fn parse_user_path(bytes: &[u8], expected_customer: &str) -> Result<String> {
    ensure!(
        bytes.len() <= MAX_USER_RESPONSE_BYTES,
        "workspace_directory_response_too_large"
    );
    let user: DirectoryUser = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("workspace_directory_user_response_invalid"))?;
    ensure!(
        !user.customer_id.is_empty() && user.customer_id == expected_customer,
        "workspace_directory_customer_mismatch"
    );
    validate_path(&user.org_unit_path)?;
    Ok(user.org_unit_path)
}

/// Validate the complete source hierarchy before it can be made visible.
pub fn validate_complete(units: Vec<OrgUnit>, user_path: &str) -> Result<Vec<OrgUnit>> {
    validate_path(user_path)?;
    ensure!(
        !units.is_empty() && units.len() <= MAX_ORG_UNITS,
        "workspace_directory_org_unit_count_invalid"
    );
    let mut ids = BTreeMap::new();
    let mut paths = BTreeSet::new();
    let mut bytes = 0usize;
    for unit in &units {
        validate_org_unit(unit)?;
        bytes = bytes
            .checked_add(serde_json::to_vec(unit)?.len())
            .context("workspace_directory_capture_size_overflow")?;
        ensure!(
            bytes <= MAX_CAPTURE_BYTES,
            "workspace_directory_capture_too_large"
        );
        ensure!(
            ids.insert(unit.id.as_str(), unit).is_none(),
            "workspace_directory_duplicate_id"
        );
        ensure!(
            paths.insert(unit.path.as_str()),
            "workspace_directory_duplicate_path"
        );
        ensure!(
            unit.parent_id.is_some() == unit.parent_path.is_some(),
            "workspace_directory_parent_fields_conflict"
        );
    }
    ensure!(
        paths.contains(user_path),
        "workspace_directory_user_scope_missing"
    );
    for unit in &units {
        match (&unit.parent_id, &unit.parent_path) {
            (Some(id), Some(path)) => {
                let parent = ids
                    .get(id.as_str())
                    .context("workspace_directory_parent_missing")?;
                ensure!(parent.path == *path, "workspace_directory_parent_conflict");
                ensure!(unit.id != *id, "workspace_directory_hierarchy_cycle");
            }
            (None, None) => ensure!(unit.path == "/", "workspace_directory_root_missing"),
            _ => anyhow::bail!("workspace_directory_parent_fields_conflict"),
        }
    }
    // Cycle detection is an integrity check on provider-supplied references. It
    // does not derive ancestry or make a Home access decision.
    for start in ids.keys() {
        let mut seen = BTreeSet::new();
        let mut current = Some(*start);
        while let Some(id) = current {
            ensure!(seen.insert(id), "workspace_directory_hierarchy_cycle");
            current = ids.get(id).and_then(|unit| unit.parent_id.as_deref());
        }
    }
    let mut sorted = units;
    sorted.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(sorted)
}

/// Publish a fully validated capture and its records atomically. The store is
/// append-only: no capture can be refreshed in place or partially observed.
pub fn publish(connection: &mut Connection, capture: &CompleteCapture) -> Result<()> {
    ensure!(
        capture.units.len() == usize::try_from(capture.metadata.org_unit_count)?,
        "workspace_directory_capture_count_mismatch"
    );
    ensure!(
        capture.metadata.id.len() == 71
            && capture.metadata.id.starts_with("sha256:")
            && capture.expires_at > capture.metadata.captured_at
            && capture.expires_at
                <= capture
                    .metadata
                    .captured_at
                    .checked_add(SOURCE_TTL_SECONDS)
                    .context("workspace_directory_expiry_overflow")?,
        "workspace_directory_capture_metadata_invalid"
    );
    let verified = validate_complete(capture.units.clone(), &capture.metadata.user_path)?;
    ensure!(
        verified == capture.units,
        "workspace_directory_capture_order_invalid"
    );
    ensure!(
        serde_json::to_vec(&capture.units)?.len() <= MAX_CAPTURE_BYTES,
        "workspace_directory_capture_too_large"
    );
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS workspace_directory_captures (
            id TEXT PRIMARY KEY NOT NULL,
            customer_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            user_path TEXT NOT NULL,
            org_unit_count INTEGER NOT NULL,
            captured_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS workspace_directory_org_units (
            capture_id TEXT NOT NULL REFERENCES workspace_directory_captures(id),
            ordinal INTEGER NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY(capture_id, ordinal)
        ) STRICT;
        CREATE TRIGGER IF NOT EXISTS workspace_directory_captures_no_update
            BEFORE UPDATE ON workspace_directory_captures BEGIN SELECT RAISE(ABORT,'immutable_capture'); END;
        CREATE TRIGGER IF NOT EXISTS workspace_directory_captures_no_delete
            BEFORE DELETE ON workspace_directory_captures BEGIN SELECT RAISE(ABORT,'immutable_capture'); END;
        CREATE TRIGGER IF NOT EXISTS workspace_directory_org_units_no_update
            BEFORE UPDATE ON workspace_directory_org_units BEGIN SELECT RAISE(ABORT,'immutable_capture'); END;
        CREATE TRIGGER IF NOT EXISTS workspace_directory_org_units_no_delete
            BEFORE DELETE ON workspace_directory_org_units BEGIN SELECT RAISE(ABORT,'immutable_capture'); END;",
    )?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO workspace_directory_captures VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            capture.metadata.id,
            capture.metadata.customer_id,
            capture.connection_id,
            capture.metadata.actor,
            capture.metadata.user_path,
            i64::try_from(capture.metadata.org_unit_count)?,
            capture.metadata.captured_at,
            capture.expires_at,
        ],
    )?;
    if inserted == 1 {
        for (index, unit) in capture.units.iter().enumerate() {
            tx.execute(
                "INSERT INTO workspace_directory_org_units VALUES(?1,?2,?3)",
                params![
                    capture.metadata.id,
                    i64::try_from(index)?,
                    serde_json::to_string(unit)?
                ],
            )?;
        }
    } else {
        let old: (String, String, String, String, i64, i64, i64) = tx.query_row(
            "SELECT customer_id,connection_id,actor,user_path,org_unit_count,captured_at,expires_at FROM workspace_directory_captures WHERE id=?1",
            [&capture.metadata.id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        )?;
        ensure!(
            old == (
                capture.metadata.customer_id.clone(),
                capture.connection_id.clone(),
                capture.metadata.actor.clone(),
                capture.metadata.user_path.clone(),
                i64::try_from(capture.metadata.org_unit_count)?,
                capture.metadata.captured_at,
                capture.expires_at,
            ),
            "workspace_directory_capture_id_conflict"
        );
        ensure!(
            units_for_page(
                &tx,
                &capture.metadata.id,
                i64::try_from(capture.metadata.org_unit_count)?
            )? == capture.units,
            "workspace_directory_capture_id_conflict"
        );
    }
    ensure_store_within_bound(&tx, MAX_STORE_BYTES)?;
    tx.commit()?;
    Ok(())
}

/// Page only while the caller's current grant still matches the immutable
/// capture's customer, connection and trusted actor. Expired hierarchy facts
/// fail closed; Home owns any longer-lived persisted membership cache.
pub fn page_for_grant(
    connection: &Connection,
    capture_id: &str,
    customer_id: &str,
    connection_id: &str,
    actor: &str,
    now: i64,
    offset: u64,
) -> Result<Page> {
    let header: Option<(String, String, String, i64, i64)> = connection
        .query_row(
            "SELECT customer_id,connection_id,actor,org_unit_count,expires_at FROM workspace_directory_captures WHERE id=?1",
            [capture_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )
        .optional()?;
    let (saved_customer, saved_connection, saved_actor, count, expires) =
        header.context("workspace_directory_capture_missing")?;
    ensure!(
        saved_customer == customer_id && saved_connection == connection_id && saved_actor == actor,
        "workspace_directory_capture_authority_changed"
    );
    ensure!(now < expires, "workspace_directory_capture_expired");
    ensure!(
        (1..=i64::try_from(MAX_ORG_UNITS)?).contains(&count),
        "workspace_directory_capture_count_invalid"
    );
    let offset_usize = usize::try_from(offset)?;
    ensure!(
        offset_usize <= usize::try_from(count)?,
        "workspace_directory_offset_invalid"
    );
    let units = units_for_page(connection, capture_id, count)?;
    let result = page(&units, offset)?;
    let encoded = serde_json::to_vec(&result)?;
    ensure!(
        encoded.len() <= MAX_PAGE_BYTES,
        "workspace_directory_page_too_large"
    );
    Ok(result)
}

fn units_for_page(connection: &Connection, capture_id: &str, total: i64) -> Result<Vec<OrgUnit>> {
    let mut statement = connection.prepare(
        "SELECT value FROM workspace_directory_org_units WHERE capture_id=?1 ORDER BY ordinal LIMIT ?2 OFFSET ?3",
    )?;
    let rows = statement.query_map(params![capture_id, total, 0], |row| row.get::<_, String>(0))?;
    let mut units = Vec::new();
    for row in rows {
        units.push(crate::json::decode::<OrgUnit>(row?.as_bytes())?);
    }
    ensure!(
        units.len() == usize::try_from(total)?,
        "workspace_directory_capture_incomplete"
    );
    Ok(units)
}

pub fn open_store(path: &std::path::Path) -> Result<Connection> {
    crate::store::open(path)
}

/// Reuse only the source org-unit list while its 15-minute source cache is live.
/// The current user's path is deliberately not part of this lookup.
fn ensure_store_within_bound(connection: &Connection, max_bytes: u64) -> Result<()> {
    let pages: i64 = connection.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let page_size: i64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let store_bytes = u64::try_from(pages)?
        .checked_mul(u64::try_from(page_size)?)
        .context("workspace_directory_store_size_overflow")?;
    ensure!(store_bytes <= max_bytes, "workspace_directory_store_full");
    Ok(())
}

pub fn cached_hierarchy(
    connection: &Connection,
    customer_id: &str,
    connection_id: &str,
    now: i64,
) -> Result<Option<(Vec<OrgUnit>, i64)>> {
    let header: Option<(String, i64, i64, i64)> = connection.query_row(
        "SELECT id,org_unit_count,captured_at,expires_at FROM workspace_directory_captures WHERE customer_id=?1 AND connection_id=?2 AND expires_at>?3 ORDER BY captured_at DESC LIMIT 1",
        params![customer_id, connection_id, now],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional()?;
    let Some((id, count, captured_at, expires_at)) = header else {
        return Ok(None);
    };
    ensure!(
        expires_at
            <= captured_at
                .checked_add(SOURCE_TTL_SECONDS)
                .context("workspace_directory_expiry_overflow")?,
        "workspace_directory_cache_expiry_invalid"
    );
    ensure!(
        (1..=i64::try_from(MAX_ORG_UNITS)?).contains(&count),
        "workspace_directory_capture_count_invalid"
    );
    Ok(Some((units_for_page(connection, &id, count)?, captured_at)))
}

pub fn page(units: &[OrgUnit], offset: u64) -> Result<Page> {
    ensure!(
        units.len() <= MAX_ORG_UNITS,
        "workspace_directory_org_unit_count_invalid"
    );
    let offset = usize::try_from(offset)?;
    ensure!(offset <= units.len(), "workspace_directory_offset_invalid");
    let mut items = Vec::new();
    let mut encoded_bytes = 2usize;
    for unit in units.iter().skip(offset).take(MAX_PAGE_ITEMS) {
        let size = serde_json::to_vec(unit)?.len();
        let separator = usize::from(!items.is_empty());
        ensure!(
            size + 128 <= MAX_PAGE_BYTES,
            "workspace_directory_record_too_large"
        );
        if encoded_bytes + separator + size > MAX_PAGE_BYTES - 128 {
            ensure!(!items.is_empty(), "workspace_directory_record_too_large");
            break;
        }
        encoded_bytes += separator + size;
        items.push(unit.clone());
    }
    let next = offset
        .checked_add(items.len())
        .context("workspace_directory_offset_overflow")?;
    ensure!(
        !items.is_empty() || offset == units.len(),
        "workspace_directory_record_too_large"
    );
    Ok(Page {
        items,
        next: u64::try_from(next)?,
        done: next == units.len(),
    })
}

fn validate_org_unit(unit: &OrgUnit) -> Result<()> {
    bounded(&unit.id, 256, "workspace_directory_org_unit_id_invalid")?;
    bounded(&unit.name, 512, "workspace_directory_org_unit_name_invalid")?;
    validate_path(&unit.path)?;
    if let Some(id) = &unit.parent_id {
        bounded(id, 256, "workspace_directory_parent_id_invalid")?;
    }
    if let Some(path) = &unit.parent_path {
        validate_path(path)?;
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<()> {
    bounded(value, 1024, "workspace_directory_org_unit_path_invalid")?;
    ensure!(
        value.starts_with('/')
            && (value == "/" || !value.ends_with('/'))
            && !value.contains("//")
            && !value.split('/').any(|part| matches!(part, "." | "..")),
        "workspace_directory_org_unit_path_invalid"
    );
    Ok(())
}

fn bounded(value: &str, limit: usize, error: &'static str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= limit
            && value.trim() == value
            && !value.chars().any(char::is_control),
        error
    );
    Ok(())
}

const METADATA_ORIGIN: &str = "http://metadata.google.internal";

/// Native, production-fixed provider adapter. All URLs and methods are built
/// here; no app field or resource can select an origin, path, or HTTP method.
pub struct NativeDirectoryPort {
    client: reqwest::blocking::Client,
    directory_origin: reqwest::Url,
    customer_id: String,
    now: i64,
    cached_hierarchy: Option<(Vec<OrgUnit>, i64)>,
    access_token: String,
}

impl NativeDirectoryPort {
    pub fn new(
        plan: AuthenticationPlan,
        customer_id: &str,
        now: i64,
        cached_hierarchy: Option<(Vec<OrgUnit>, i64)>,
    ) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(20))
            .https_only(false)
            .build()
            .map_err(|_| anyhow::anyhow!("workspace_directory_transport_unavailable"))?;
        let access_token = acquire_access_token(
            &client,
            &plan,
            crate::oauth::effects::wall_time()?,
            reqwest::Url::parse(METADATA_ORIGIN)?,
            reqwest::Url::parse(IAM_ORIGIN)?,
            reqwest::Url::parse(&format!("{OAUTH_ORIGIN}/token"))?,
        )?;
        Ok(Self {
            client,
            directory_origin: reqwest::Url::parse(&format!("{DIRECTORY_ORIGIN}/"))?,
            customer_id: customer_id.into(),
            now,
            cached_hierarchy,
            access_token,
        })
    }

    #[cfg(test)]
    fn transport_fixture(
        plan: AuthenticationPlan,
        customer_id: &str,
        now: i64,
        cached_hierarchy: Option<(Vec<OrgUnit>, i64)>,
        origins: [&str; 4],
    ) -> Result<Self> {
        let [directory_origin, metadata_origin, iam_origin, oauth_origin] = origins;
        let parse = |value: &str| -> Result<reqwest::Url> {
            let url = reqwest::Url::parse(value)?;
            ensure!(
                url.scheme() == "http"
                    && matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && (url.path().is_empty() || url.path() == "/"),
                "invalid_workspace_directory_fixture_origin"
            );
            Ok(url)
        };
        let directory_origin = parse(directory_origin)?;
        let metadata_origin = parse(metadata_origin)?;
        let iam_origin = parse(iam_origin)?;
        let oauth_endpoint = parse(oauth_origin)?.join("/token")?;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        let access_token = acquire_access_token(
            &client,
            &plan,
            now,
            metadata_origin,
            iam_origin,
            oauth_endpoint,
        )?;
        Ok(Self {
            client,
            directory_origin,
            customer_id: customer_id.into(),
            now,
            cached_hierarchy,
            access_token,
        })
    }

    fn get(&self, url: reqwest::Url, max: usize) -> Result<Vec<u8>> {
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.access_token))
                .map_err(|_| anyhow::anyhow!("workspace_directory_authentication_failed"))?;
        authorization.set_sensitive(true);
        let response = self
            .client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .map_err(|_| anyhow::anyhow!("workspace_directory_provider_unavailable"))?;
        bounded_response(response, max)
    }
}

fn bounded_response(response: reqwest::blocking::Response, max: usize) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "workspace_directory_provider_refused"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= max as u64),
        "workspace_directory_response_too_large"
    );
    let mut bytes = Vec::new();
    response
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("workspace_directory_provider_unavailable"))?;
    ensure!(bytes.len() <= max, "workspace_directory_response_too_large");
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IamToken {
    access_token: Option<String>,
    signed_jwt: Option<String>,
    key_id: Option<String>,
}

fn validate_iam_token_shape(token: &IamToken, delegated: bool) -> Result<()> {
    let matches_plan = if delegated {
        token.access_token.is_none()
            && token.signed_jwt.is_some()
            && token.key_id.as_ref().is_some_and(|key| !key.is_empty())
    } else {
        token.access_token.is_some() && token.signed_jwt.is_none() && token.key_id.is_none()
    };
    ensure!(matches_plan, "workspace_directory_authentication_failed");
    Ok(())
}

fn acquire_access_token(
    client: &reqwest::blocking::Client,
    plan: &AuthenticationPlan,
    now: i64,
    metadata_origin: reqwest::Url,
    iam_origin: reqwest::Url,
    oauth_endpoint: reqwest::Url,
) -> Result<String> {
    let metadata_url =
        metadata_origin.join("/computeMetadata/v1/instance/service-accounts/default/token")?;
    let metadata = client
        .get(metadata_url)
        .header("Metadata-Flavor", "Google")
        .send()
        .map_err(|_| anyhow::anyhow!("workspace_directory_workload_identity_unavailable"))?;
    ensure!(
        metadata.status().is_success()
            && metadata
                .headers()
                .get("Metadata-Flavor")
                .is_some_and(|value| value == "Google"),
        "workspace_directory_workload_identity_unavailable"
    );
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    struct MetadataToken {
        access_token: String,
        token_type: String,
    }
    let body = bounded_response(metadata, 16 * 1024)?;
    let token: MetadataToken = crate::json::decode(&body)
        .map_err(|_| anyhow::anyhow!("workspace_directory_workload_identity_unavailable"))?;
    ensure!(
        token.token_type == "Bearer"
            && !token.access_token.is_empty()
            && token.access_token.len() <= 8192
            && token.access_token.bytes().all(|b| b.is_ascii_graphic()),
        "workspace_directory_workload_identity_unavailable"
    );
    let (account, delegated_admin) = match plan {
        AuthenticationPlan::DirectServiceAccount { service_account } => (service_account, None),
        AuthenticationPlan::DomainWideDelegation {
            service_account,
            delegated_admin,
        } => (service_account, Some(delegated_admin.as_str())),
    };
    let mut endpoint = iam_origin;
    endpoint
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("workspace_directory_authentication_failed"))?
        .clear()
        .extend(["v1", "projects", "-", "serviceAccounts"])
        .push(&format!(
            "{account}:{}",
            if delegated_admin.is_some() {
                "signJwt"
            } else {
                "generateAccessToken"
            }
        ));
    let scopes = [USER_READ_SCOPE, ORG_UNIT_READ_SCOPE];
    let payload = if let Some(subject) = delegated_admin {
        let claims = serde_json::json!({"iss":account,"sub":subject,"aud":GOOGLE_TOKEN_ENDPOINT,"iat":now,"exp":now.checked_add(300).ok_or_else(|| anyhow::anyhow!("workspace_directory_authentication_failed"))?,"scope":scopes.join(" ")});
        serde_json::json!({"payload":serde_json::to_string(&claims)?})
    } else {
        serde_json::json!({"scope":scopes,"lifetime":"3600s"})
    };
    let mut iam_auth =
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.access_token))
            .map_err(|_| anyhow::anyhow!("workspace_directory_authentication_failed"))?;
    iam_auth.set_sensitive(true);
    let request_body = serde_json::to_vec(&payload)?;
    let response = client
        .post(endpoint)
        .header(reqwest::header::AUTHORIZATION, iam_auth)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(request_body)
        .send()
        .map_err(|_| anyhow::anyhow!("workspace_directory_authentication_failed"))?;
    let body = bounded_response(response, 16 * 1024)?;
    let result: IamToken = crate::json::decode(&body)
        .map_err(|_| anyhow::anyhow!("workspace_directory_authentication_failed"))?;
    validate_iam_token_shape(&result, delegated_admin.is_some())?;
    let access_token = if let Some(jwt) = result.signed_jwt {
        ensure!(
            jwt.len() <= 8192 && jwt.split('.').count() == 3,
            "workspace_directory_authentication_failed"
        );
        let parts: Vec<_> = jwt.split('.').collect();
        let header: serde_json::Value = crate::json::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?,
        )?;
        let claims: serde_json::Value = crate::json::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?,
        )?;
        ensure!(
            header["alg"] == "RS256"
                && header["kid"].as_str() == result.key_id.as_deref()
                && claims["iss"] == *account
                && claims["sub"] == delegated_admin.unwrap_or_default()
                && claims["aud"] == GOOGLE_TOKEN_ENDPOINT
                && claims["iat"] == now
                && now.checked_add(300) == claims["exp"].as_i64()
                && claims["scope"] == scopes.join(" "),
            "workspace_directory_authentication_failed"
        );
        ensure!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[2])?
                .len()
                >= 64,
            "workspace_directory_authentication_failed"
        );
        let response = client
            .post(oauth_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt.as_str()),
            ])
            .send()
            .map_err(|_| anyhow::anyhow!("workspace_directory_authentication_failed"))?;
        let body = bounded_response(response, 16 * 1024)?;
        #[derive(Deserialize)]
        struct OAuthToken {
            access_token: String,
            token_type: String,
        }
        let token: OAuthToken = crate::json::decode(&body)
            .map_err(|_| anyhow::anyhow!("workspace_directory_authentication_failed"))?;
        ensure!(
            token.token_type == "Bearer",
            "workspace_directory_authentication_failed"
        );
        token.access_token
    } else {
        result
            .access_token
            .ok_or_else(|| anyhow::anyhow!("workspace_directory_authentication_failed"))?
    };
    ensure!(
        !access_token.is_empty()
            && access_token.len() <= 8192
            && access_token.bytes().all(|b| b.is_ascii_graphic()),
        "workspace_directory_authentication_failed"
    );
    Ok(access_token)
}

impl DirectoryReadPort for NativeDirectoryPort {
    fn user_org_unit_path(&mut self, actor: &str) -> Result<String> {
        let mut url = self.directory_origin.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("workspace_directory_request_invalid"))?
            .extend(["admin", "directory", "v1", "users", actor]);
        url.query_pairs_mut()
            .append_pair("projection", "full")
            .append_pair("viewType", "admin_view")
            .append_pair("fields", "customerId,orgUnitPath");
        let body = self.get(url, MAX_USER_RESPONSE_BYTES)?;
        parse_user_path(&body, &self.customer_id)
    }

    fn list_org_units(&mut self) -> Result<ProviderPage> {
        if let Some((units, hierarchy_captured_at)) = self.cached_hierarchy.take() {
            return Ok(ProviderPage {
                units,
                response_bytes: 0,
                hierarchy_captured_at,
            });
        }
        let mut url = self.directory_origin.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("workspace_directory_request_invalid"))?
            .extend([
                "admin",
                "directory",
                "v1",
                "customer",
                &self.customer_id,
                "orgunits",
            ]);
        url.query_pairs_mut()
            .append_pair("type", "allIncludingParent")
            .append_pair(
                "fields",
                "organizationUnits(orgUnitId,name,orgUnitPath,parentOrgUnitId,parentOrgUnitPath)",
            );
        let body = self.get(url, MAX_RESPONSE_BYTES)?;
        let response_bytes = body.len();
        Ok(ProviderPage {
            units: parse_org_unit_response(&body)?,
            response_bytes,
            hierarchy_captured_at: self.now,
        })
    }
}

/// Offline provider fixture built from Google Directory's real wire shapes and
/// parsed by the same DTOs as the live adapter.
pub struct SimulatedDirectoryPort {
    customer_id: String,
    actor: String,
    user_response: serde_json::Value,
    hierarchy_response: serde_json::Value,
    hierarchy_captured_at: i64,
}

impl SimulatedDirectoryPort {
    pub fn new(
        database: &std::path::Path,
        scope: &str,
        customer_id: &str,
        actor: &str,
        _now: i64,
    ) -> Result<Self> {
        let (user_response, hierarchy_response, hierarchy_captured_at) =
            crate::integrations::simulated::workspace_directory_responses(database, scope, actor)?;
        Ok(Self {
            customer_id: customer_id.into(),
            actor: actor.into(),
            user_response,
            hierarchy_response,
            hierarchy_captured_at,
        })
    }
}

impl DirectoryReadPort for SimulatedDirectoryPort {
    fn user_org_unit_path(&mut self, actor: &str) -> Result<String> {
        ensure!(actor == self.actor, "workspace_directory_actor_mismatch");
        let bytes = serde_json::to_vec(&self.user_response)?;
        parse_user_path(&bytes, &self.customer_id)
    }

    fn list_org_units(&mut self) -> Result<ProviderPage> {
        let bytes = serde_json::to_vec(&self.hierarchy_response)?;
        let response_bytes = bytes.len();
        Ok(ProviderPage {
            units: parse_org_unit_response(&bytes)?,
            response_bytes,
            hierarchy_captured_at: self.hierarchy_captured_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iam_response_cannot_change_the_selected_authentication_flow() -> Result<()> {
        let direct = IamToken {
            access_token: Some("fixture-access-token".into()),
            signed_jwt: None,
            key_id: None,
        };
        assert!(validate_iam_token_shape(&direct, false).is_ok());
        assert!(validate_iam_token_shape(&direct, true).is_err());
        let delegated = IamToken {
            access_token: None,
            signed_jwt: Some("header.claims.signature".into()),
            key_id: Some("fixture-key".into()),
        };
        assert!(validate_iam_token_shape(&delegated, true).is_ok());
        assert!(validate_iam_token_shape(&delegated, false).is_err());
        for token in [
            IamToken {
                access_token: direct.access_token.clone(),
                signed_jwt: delegated.signed_jwt.clone(),
                key_id: delegated.key_id.clone(),
            },
            IamToken {
                access_token: None,
                signed_jwt: None,
                key_id: None,
            },
            IamToken {
                access_token: None,
                signed_jwt: delegated.signed_jwt.clone(),
                key_id: None,
            },
            IamToken {
                access_token: None,
                signed_jwt: delegated.signed_jwt.clone(),
                key_id: Some(String::new()),
            },
        ] {
            assert!(validate_iam_token_shape(&token, true).is_err());
            assert!(validate_iam_token_shape(&token, false).is_err());
        }
        Ok(())
    }

    fn http_request(stream: &mut std::net::TcpStream) -> Result<String> {
        use std::io::Read;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut chunk)?;
            bytes.push(chunk[0]);
            ensure!(bytes.len() <= 32 * 1024, "fixture request too large");
        }
        let header_end = bytes.len();
        let headers = String::from_utf8_lossy(&bytes);
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        bytes.resize(header_end + length, 0);
        stream.read_exact(&mut bytes[header_end..])?;
        Ok(String::from_utf8(bytes)?)
    }

    fn fixture_response(
        stream: &mut std::net::TcpStream,
        body: &str,
        metadata: bool,
    ) -> Result<()> {
        use std::io::Write;
        let flavor = if metadata {
            "Metadata-Flavor: Google\r\n"
        } else {
            ""
        };
        write!(
            stream,
            "HTTP/1.1 200 OK\r\n{flavor}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        stream.flush()?;
        Ok(())
    }

    fn fixture() -> Vec<OrgUnit> {
        vec![
            OrgUnit {
                id: "root".into(),
                name: "Root".into(),
                path: "/".into(),
                parent_id: None,
                parent_path: None,
            },
            OrgUnit {
                id: "eng".into(),
                name: "Engineering".into(),
                path: "/Engineering".into(),
                parent_id: Some("root".into()),
                parent_path: Some("/".into()),
            },
        ]
    }

    #[test]
    fn full_capture_rejects_incomplete_conflicting_and_cyclic_provider_hierarchy() -> Result<()> {
        assert_eq!(validate_complete(fixture(), "/Engineering")?.len(), 2);
        assert!(validate_complete(fixture(), "/Unknown").is_err());
        let mut conflict = fixture();
        conflict[1].parent_path = Some("/Other".into());
        assert!(validate_complete(conflict, "/Engineering").is_err());
        let mut cycle = fixture();
        cycle[0].parent_id = Some("eng".into());
        cycle[0].parent_path = Some("/Engineering".into());
        assert!(validate_complete(cycle, "/Engineering").is_err());
        let mut duplicate = fixture();
        duplicate[1].id = "root".into();
        assert!(validate_complete(duplicate, "/Engineering").is_err());
        Ok(())
    }

    #[test]
    fn pages_are_count_and_byte_bounded_with_forward_only_offsets() -> Result<()> {
        let mut units = fixture();
        for index in 0..70 {
            units.push(OrgUnit {
                id: format!("id-{index:03}"),
                name: "Unit".into(),
                path: format!("/Unit-{index:03}"),
                parent_id: Some("root".into()),
                parent_path: Some("/".into()),
            });
        }
        let first = page(&units, 0)?;
        assert_eq!(first.items.len(), MAX_PAGE_ITEMS);
        assert_eq!(first.next, 32);
        assert!(!first.done);
        let last = page(&units, 72)?;
        assert_eq!(last.items.len(), 0);
        assert!(last.done);
        assert!(page(&units, 73).is_err());
        Ok(())
    }

    struct FixturePort {
        pages: Vec<ProviderPage>,
        fail_after: Option<usize>,
        calls: usize,
    }

    impl DirectoryReadPort for FixturePort {
        fn user_org_unit_path(&mut self, actor: &str) -> Result<String> {
            ensure!(actor == "alice@example.test", "wrong_actor");
            self.calls += 1;
            Ok("/Engineering".into())
        }

        fn list_org_units(&mut self) -> Result<ProviderPage> {
            if self.fail_after.is_some() {
                anyhow::bail!("provider response is not surfaced")
            }
            self.calls += 1;
            self.pages
                .first()
                .cloned()
                .context("unexpected_fixture_page")
        }
    }

    fn capture_input(actor: &str) -> CaptureInput {
        CaptureInput {
            customer_id: "customer-1".into(),
            connection_id: "directory-connection/1".into(),
            actor: actor.into(),
            captured_at: 100,
        }
    }

    #[test]
    fn complete_pipeline_publishes_only_after_all_pages_and_binds_identity() -> Result<()> {
        let mut port = FixturePort {
            pages: vec![ProviderPage {
                units: fixture(),
                response_bytes: 256,
                hierarchy_captured_at: 100,
            }],
            fail_after: None,
            calls: 0,
        };
        let capture = collect_complete(capture_input("alice@example.test"), &mut port)?;
        assert_eq!(capture.metadata.org_unit_count, 2);
        assert_eq!(capture.metadata.user_path, "/Engineering");
        assert_eq!(capture.expires_at, 100 + SOURCE_TTL_SECONDS);
        assert_eq!(capture.units, validate_complete(fixture(), "/Engineering")?);
        assert_eq!(port.calls, 2);

        let mut failed = FixturePort {
            pages: port.pages.clone(),
            fail_after: Some(1),
            calls: 0,
        };
        assert_eq!(
            collect_complete(capture_input("alice@example.test"), &mut failed)
                .unwrap_err()
                .to_string(),
            "workspace_directory_hierarchy_lookup_failed"
        );
        let unpublished = Connection::open_in_memory()?;
        let capture_rows: i64 = unpublished.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='workspace_directory_captures'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            capture_rows, 0,
            "failed provider read created a partial capture"
        );
        assert!(collect_complete(capture_input("bob@example.test"), &mut port).is_err());
        Ok(())
    }

    #[test]
    fn published_capture_is_atomic_immutable_and_isolated_by_actor_customer_and_connection()
    -> Result<()> {
        let mut port = FixturePort {
            pages: vec![ProviderPage {
                units: fixture(),
                response_bytes: 256,
                hierarchy_captured_at: 100,
            }],
            fail_after: None,
            calls: 0,
        };
        let capture = collect_complete(capture_input("alice@example.test"), &mut port)?;
        let mut db = Connection::open_in_memory()?;
        publish(&mut db, &capture)?;
        assert_eq!(
            cached_hierarchy(&db, "customer-1", "directory-connection/1", 101)?,
            Some((capture.units.clone(), 100))
        );
        assert_eq!(
            cached_hierarchy(
                &db,
                "customer-1",
                "directory-connection/1",
                100 + SOURCE_TTL_SECONDS
            )?,
            None
        );
        assert!(publish(&mut db, &capture).is_ok());
        assert!(
            db.execute(
                "UPDATE workspace_directory_captures SET actor='bob@example.test' WHERE id=?1",
                [&capture.metadata.id],
            )
            .is_err()
        );
        let first = page_for_grant(
            &db,
            &capture.metadata.id,
            "customer-1",
            "directory-connection/1",
            "alice@example.test",
            101,
            0,
        )?;
        assert_eq!(first.items, capture.units);
        assert!(first.done);
        for (customer, connection_id, actor, now) in [
            (
                "customer-2",
                "directory-connection/1",
                "alice@example.test",
                101,
            ),
            (
                "customer-1",
                "directory-connection/2",
                "alice@example.test",
                101,
            ),
            (
                "customer-1",
                "directory-connection/1",
                "bob@example.test",
                101,
            ),
            (
                "customer-1",
                "directory-connection/1",
                "alice@example.test",
                100 + SOURCE_TTL_SECONDS,
            ),
        ] {
            assert!(
                page_for_grant(
                    &db,
                    &capture.metadata.id,
                    customer,
                    connection_id,
                    actor,
                    now,
                    0,
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn direct_and_delegated_http_adapters_use_fixed_google_routes_and_real_response_shapes()
    -> Result<()> {
        use std::{net::TcpListener, thread};
        for (delegated, cached) in [(false, false), (true, false), (false, true)] {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            let origin = format!("http://{}", listener.local_addr()?);
            let server = thread::spawn(move || -> Result<()> {
                let count = if delegated {
                    5
                } else if cached {
                    3
                } else {
                    4
                };
                for _ in 0..count {
                    let (mut stream, _) = listener.accept()?;
                    let request = http_request(&mut stream)?;
                    let (body, metadata) = if request.starts_with("GET /computeMetadata/") {
                        ensure!(
                            request
                                .to_ascii_lowercase()
                                .contains("metadata-flavor: google"),
                            "metadata flavor missing"
                        );
                        (r#"{"access_token":"metadata-token","token_type":"Bearer","expires_in":3600}"#.to_owned(), true)
                    } else if request.contains(":generateAccessToken ") {
                        ensure!(
                            !delegated && request.contains("Bearer metadata-token"),
                            "direct IAM request invalid"
                        );
                        let body = request
                            .split_once("\r\n\r\n")
                            .context("request body missing")?
                            .1;
                        let input: serde_json::Value = serde_json::from_str(body)?;
                        ensure!(
                            input["scope"]
                                == serde_json::json!([USER_READ_SCOPE, ORG_UNIT_READ_SCOPE])
                                && input["lifetime"] == "3600s",
                            "direct scopes invalid"
                        );
                        (r#"{"accessToken":"directory-token","expireTime":"2030-01-01T00:00:00Z"}"#.to_owned(), false)
                    } else if request.contains(":signJwt ") {
                        ensure!(
                            delegated && request.contains("Bearer metadata-token"),
                            "delegated IAM request invalid"
                        );
                        let body = request
                            .split_once("\r\n\r\n")
                            .context("request body missing")?
                            .1;
                        let input: serde_json::Value = serde_json::from_str(body)?;
                        let claims_text =
                            input["payload"].as_str().context("JWT claims missing")?;
                        let claims: serde_json::Value = serde_json::from_str(claims_text)?;
                        ensure!(
                            claims["iss"] == "directory-reader@company.iam.gserviceaccount.com"
                                && claims["sub"] == "admin@example.test"
                                && claims["aud"] == GOOGLE_TOKEN_ENDPOINT
                                && claims["iat"] == 100
                                && claims["exp"] == 400
                                && claims["scope"]
                                    == format!("{USER_READ_SCOPE} {ORG_UNIT_READ_SCOPE}"),
                            "delegated claims invalid"
                        );
                        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(br#"{"alg":"RS256","kid":"fixture-key"}"#);
                        let payload =
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_text);
                        let signature =
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 64]);
                        let signed_jwt = format!("{header}.{payload}.{signature}");
                        (
                            serde_json::json!({"keyId":"fixture-key","signedJwt":signed_jwt})
                                .to_string(),
                            false,
                        )
                    } else if request.starts_with("POST /token ") {
                        ensure!(delegated && request.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"), "OAuth exchange invalid");
                        (r#"{"access_token":"directory-token","token_type":"Bearer","expires_in":3600}"#.to_owned(), false)
                    } else if request.contains("/users/alice%40example.test?")
                        || request.contains("/users/alice@example.test?")
                    {
                        ensure!(
                            request.contains("projection=full")
                                && request.contains("viewType=admin_view")
                                && request.contains("fields=customerId%2CorgUnitPath")
                                && request.contains("Bearer directory-token"),
                            "user request projection invalid"
                        );
                        (r#"{"customerId":"customer-1","orgUnitPath":"/Engineering","primaryEmail":"alias@example.test","kind":"admin#directory#user"}"#.to_owned(), false)
                    } else if request.contains("/customer/customer-1/orgunits?") {
                        let target = request
                            .lines()
                            .next()
                            .and_then(|line| line.split_whitespace().nth(1))
                            .context("hierarchy request target missing")?;
                        let parsed = reqwest::Url::parse(&format!("http://fixture{target}"))?;
                        let query: Vec<_> = parsed
                            .query_pairs()
                            .map(|(k, v)| (k.into_owned(), v.into_owned()))
                            .collect();
                        ensure!(
                            parsed.path() == "/admin/directory/v1/customer/customer-1/orgunits"
                                && query == vec![
                                    ("type".into(), "allIncludingParent".into()),
                                    ("fields".into(), "organizationUnits(orgUnitId,name,orgUnitPath,parentOrgUnitId,parentOrgUnitPath)".into()),
                                ]
                                && request.contains("Bearer directory-token"),
                            "hierarchy request route or query invalid"
                        );
                        (r#"{"kind":"admin#directory#orgUnits","organizationUnits":[{"orgUnitId":"root","name":"Root","orgUnitPath":"/","parentOrgUnitId":null,"parentOrgUnitPath":null},{"orgUnitId":"eng","name":"Engineering","orgUnitPath":"/Engineering","parentOrgUnitId":"root","parentOrgUnitPath":"/"}]}"#.to_owned(), false)
                    } else {
                        anyhow::bail!(
                            "unexpected fixture request path: {}",
                            request.lines().next().unwrap_or("missing request line")
                        )
                    };
                    fixture_response(&mut stream, &body, metadata)?;
                }
                Ok(())
            });
            let plan = if delegated {
                AuthenticationPlan::DomainWideDelegation {
                    service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
                    delegated_admin: "admin@example.test".into(),
                }
            } else {
                AuthenticationPlan::DirectServiceAccount {
                    service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
                }
            };
            let mut port = NativeDirectoryPort::transport_fixture(
                plan,
                "customer-1",
                100,
                cached.then(|| (fixture(), 100)),
                [origin.as_str(); 4],
            )?;
            let capture = collect_complete(capture_input("alice@example.test"), &mut port);
            server.join().expect("fixture server panicked")?;
            let capture = capture?;
            assert_eq!(capture.metadata.user_path, "/Engineering");
            assert_eq!(capture.units.len(), 2);
        }
        Ok(())
    }

    #[test]
    fn auth_plans_pin_scopes_and_fixed_origins_without_mounted_secret_refs() -> Result<()> {
        use day2_capabilities::integrations::{LiveConnection, WorkspaceDirectoryAuth};
        let direct = LiveConnection::WorkspaceDirectory {
            service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
            auth: WorkspaceDirectoryAuth::DirectServiceAccount,
        };
        direct.validate()?;
        assert!(direct.credential_ref().is_none());
        let plan = AuthenticationPlan::from_connection(&direct)?;
        assert_eq!(plan.scopes(), [USER_READ_SCOPE, ORG_UNIT_READ_SCOPE]);
        assert_eq!(
            plan.fixed_origins(),
            [DIRECTORY_ORIGIN, IAM_ORIGIN, OAUTH_ORIGIN]
        );
        let delegated = LiveConnection::WorkspaceDirectory {
            service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
            auth: WorkspaceDirectoryAuth::DomainWideDelegation {
                delegated_admin: "admin@example.test".into(),
            },
        };
        assert!(AuthenticationPlan::from_connection(&delegated).is_ok());
        assert!(
            LiveConnection::WorkspaceDirectory {
                service_account: "evil@example.test".into(),
                auth: WorkspaceDirectoryAuth::DirectServiceAccount,
            }
            .validate()
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn hierarchy_parser_accepts_the_reviewed_four_megabyte_response_ceiling() -> Result<()> {
        let organization_units: Vec<_> = (0..2_000)
            .map(|index| {
                serde_json::json!({
                    "orgUnitId": format!("unit-{index}"),
                    "name": "x".repeat(512),
                    "orgUnitPath": format!("/Unit-{index}"),
                    "parentOrgUnitId": "root",
                    "parentOrgUnitPath": "/",
                })
            })
            .collect();
        let bytes =
            serde_json::to_vec(&serde_json::json!({"organizationUnits": organization_units}))?;
        assert!(bytes.len() > 1_048_576 && bytes.len() <= MAX_RESPONSE_BYTES);
        assert_eq!(parse_org_unit_response(&bytes)?.len(), 2_000);
        Ok(())
    }

    #[test]
    fn immutable_store_has_an_explicit_fail_closed_capacity() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE workspace_directory_capacity_fixture(value TEXT)")?;
        assert_eq!(
            ensure_store_within_bound(&db, 1).unwrap_err().to_string(),
            "workspace_directory_store_full"
        );
        assert!(ensure_store_within_bound(&db, MAX_STORE_BYTES).is_ok());
        Ok(())
    }

    #[test]
    fn provider_responses_are_strict_and_bounded() -> Result<()> {
        let response = br#"{"organizationUnits":[{"orgUnitId":"root","name":"Root","orgUnitPath":"/","parentOrgUnitId":null,"parentOrgUnitPath":null}],"kind":"admin#directory#orgUnits"}"#;
        let units = parse_org_unit_response(response)?;
        assert_eq!(validate_complete(units, "/")?.len(), 1);
        assert!(parse_org_unit_response(br#"{}"#).is_err());
        assert!(
            parse_org_unit_response(br#"{"organizationUnits":[],"nextPageToken":"unexpected"}"#)
                .is_err()
        );
        assert!(
            parse_user_path(
                br#"{"customerId":"customer-1","orgUnitPath":"/../../"}"#,
                "customer-1"
            )
            .is_err()
        );
        assert!(
            parse_user_path(br#"{"customerId":"other","orgUnitPath":"/"}"#, "customer-1").is_err()
        );
        Ok(())
    }
}

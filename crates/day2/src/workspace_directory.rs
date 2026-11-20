//! Workspace Directory reads: a fresh, complete organizational-unit hierarchy
//! delivered to the reading invocation, the current actor's user path, and a
//! named person's user path for an operation granted that read.
//!
//! Provider parsing and capture integrity live here; Home owns all path policy,
//! ancestry decisions, persistence and retention of what it keeps.
use anyhow::{Context, Result, ensure};
#[cfg(test)]
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ORG_UNITS: usize = 10_000;
pub const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROVIDER_CALLS: u64 = 5;
pub const MAX_CAPTURE_REQUEST_BYTES: u64 = 32 * 1024;
// Five responses in the delegated flow, including the one-byte oversize probe
// on the final response before a rejected capture stops reading.
pub const MAX_CAPTURE_RESPONSE_BYTES: u64 = (MAX_RESPONSE_BYTES + 4 * 16 * 1024 + 1) as u64;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_USER_RESPONSE_BYTES: usize = 16 * 1024;
// Whole read reservation: metadata + identity/IAM/OAuth exchanges and the
// directory response. Delegated auth is the largest path (four bounded
// responses); reserve one extra byte for the oversize probe on the last read.
pub const MAX_USER_LOOKUP_RESPONSE_BYTES: u64 = (4 * MAX_USER_RESPONSE_BYTES + 1) as u64;
pub const MAX_USER_LOOKUP_REQUEST_BYTES: u64 = MAX_CAPTURE_REQUEST_BYTES;
pub const USER_READ_SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly";
pub const ORG_UNIT_READ_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly";
const DIRECTORY_ORIGIN: &str = "https://admin.googleapis.com";
#[cfg(test)]
use crate::google_auth::GOOGLE_TOKEN_ENDPOINT;
use crate::google_auth::{IAM_ORIGIN, OAUTH_ORIGIN};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureMode {
    Hierarchy,
    UserPath,
}

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

    pub fn scopes(&self, mode: CaptureMode) -> Vec<&'static str> {
        match mode {
            CaptureMode::Hierarchy => vec![ORG_UNIT_READ_SCOPE],
            CaptureMode::UserPath => vec![USER_READ_SCOPE],
        }
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserPath {
    pub customer_id: String,
    pub actor: String,
    pub user_path: String,
    pub captured_at: i64,
}

/// Another person's user path. `NotFound` covers a person the Directory does
/// not know, one in another customer and a suspended account, without saying
/// which.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NamedUserPath {
    Found(UserPath),
    NotFound,
}

/// The application names this user, so the name is checked before it reaches
/// a provider URL: one primary-email address, nothing that could select
/// another route or user.
pub fn validate_named_actor(actor: &str) -> Result<()> {
    bounded(actor, 320, "workspace_directory_named_user_invalid")?;
    let (local, domain) = actor
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("workspace_directory_named_user_invalid"))?;
    ensure!(
        !local.is_empty()
            && !domain.is_empty()
            && !domain.contains('@')
            && actor
                .chars()
                .all(|c| c.is_ascii_graphic() && !matches!(c, '/' | '?' | '#' | '%' | '\\')),
        "workspace_directory_named_user_invalid"
    );
    Ok(())
}

/// Read one named user's path. Only the provider's own answer that it knows no
/// such user in this customer becomes `NotFound`; every other failure stays a
/// failure, so an outage never reads as a departure.
pub fn collect_named_user_path(
    input: CaptureInput,
    port: &mut dyn DirectoryReadPort,
) -> Result<NamedUserPath> {
    validate_capture_input(&input)?;
    validate_named_actor(&input.actor)?;
    let found = port
        .named_user_org_unit_path(&input.actor)
        .map_err(|_| anyhow::anyhow!("workspace_directory_user_lookup_failed"))?;
    if let Some(user_path) = &found {
        validate_path(user_path)?;
    }
    Ok(match found {
        None => NamedUserPath::NotFound,
        Some(user_path) => NamedUserPath::Found(UserPath {
            customer_id: input.customer_id,
            actor: input.actor,
            user_path,
            captured_at: input.captured_at,
        }),
    })
}

pub fn collect_user_path(
    input: CaptureInput,
    port: &mut dyn DirectoryReadPort,
) -> Result<UserPath> {
    validate_capture_input(&input)?;
    let user_path = port
        .user_org_unit_path(&input.actor)
        .map_err(|_| anyhow::anyhow!("workspace_directory_user_lookup_failed"))?;
    validate_path(&user_path)?;
    Ok(UserPath {
        customer_id: input.customer_id,
        actor: input.actor,
        user_path,
        captured_at: input.captured_at,
    })
}

/// Explicit ports for the reviewed provider calls. Implementations own HTTP,
/// identity tokens and OAuth; this pipeline owns ordering, bounds and all-or-none
/// publication. No provider response or token is returned to the caller.
pub trait DirectoryReadPort {
    fn user_org_unit_path(&mut self, actor: &str) -> Result<String>;
    /// `None` when the Directory knows no such user, the user is in another
    /// customer, or the account is suspended.
    fn named_user_org_unit_path(&mut self, actor: &str) -> Result<Option<String>>;
    fn list_org_units(&mut self) -> Result<ProviderPage>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderPage {
    pub units: Vec<OrgUnit>,
    pub response_bytes: usize,
}

/// Read and validate the complete hierarchy through `port`. The identity is
/// checked before any provider read, and nothing partial is ever returned.
pub fn collect_hierarchy(
    input: &CaptureInput,
    port: &mut dyn DirectoryReadPort,
) -> Result<Vec<OrgUnit>> {
    validate_capture_input(input)?;
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
    validate_hierarchy(result.units)
}

fn validate_capture_input(input: &CaptureInput) -> Result<()> {
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
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrgUnit {
    pub id: String,
    pub name: String,
    pub path: String,
    #[serde(with = "optional_text")]
    pub parent_id: Option<String>,
    #[serde(with = "optional_text")]
    pub parent_path: Option<String>,
}

// The public Roc union uses tagged values, while Google's DTO uses null/string.
// Keep that translation at the app-facing record boundary, including storage.
mod optional_text {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    enum Text<T> {
        None,
        Some(T),
    }

    pub fn serialize<S: Serializer>(
        value: &Option<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value.as_deref() {
            None => Text::<&str>::None,
            Some(value) => Text::Some(value),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        Ok(match Text::<String>::deserialize(deserializer)? {
            Text::None => None,
            Text::Some(value) => Some(value),
        })
    }
}

/// What `workspace_directory.hierarchy.v2` returns. The hierarchy itself
/// travels in `page_count` pages that only this invocation can read; there is
/// no expiry because nothing outlives the invocation. `id` is the content
/// identity of the hierarchy read through this connection, so an application
/// can compare it with what it last persisted and skip an unchanged sync.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HierarchyDelivery {
    pub id: String,
    pub customer_id: String,
    pub org_unit_count: u64,
    pub page_count: u64,
    pub captured_at: i64,
}

/// One delivered page: at most one `Tx.create_many` batch of units, in the
/// capture's stable order (sorted by organizational-unit ID).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryPage {
    pub items: Vec<OrgUnit>,
    pub page: u64,
    pub done: bool,
}

/// The grant authority a delivery is bound to and every page read compares.
pub fn delivery_authority(customer_id: &str, connection_id: &str, actor: &str) -> Result<String> {
    Ok(serde_json::to_string(&(
        "workspace_directory.hierarchy.v2",
        customer_id,
        connection_id,
        actor,
    ))?)
}

pub const DELIVERY_KIND: &str = "workspace_directory.hierarchy";

/// Collect a complete hierarchy directly from the provider port and split it
/// into staged delivery pages. Every delivery is a provider read; the host keeps
/// no copy beyond the reading invocation, and the application owns any reuse.
pub fn deliver_hierarchy(
    input: CaptureInput,
    port: &mut dyn DirectoryReadPort,
) -> Result<(HierarchyDelivery, crate::capture_delivery::Staged)> {
    let authority = delivery_authority(&input.customer_id, &input.connection_id, &input.actor)?;
    let units = collect_hierarchy(&input, port)?;
    let id = crate::digest(&serde_json::to_vec(&(
        "workspace-directory-hierarchy-v2",
        &input.customer_id,
        &input.connection_id,
        &units,
    ))?);
    let (pages, starts) = delivery_pages(&units)?;
    let delivery = HierarchyDelivery {
        id: id.clone(),
        customer_id: input.customer_id,
        org_unit_count: u64::try_from(units.len())?,
        page_count: u64::try_from(pages.len())?,
        captured_at: input.captured_at,
    };
    Ok((
        delivery,
        crate::capture_delivery::Staged {
            id,
            kind: DELIVERY_KIND,
            authority,
            item_count: u64::try_from(units.len())?,
            pages,
            starts,
        },
    ))
}

/// Greedy split under both the item and the journaled-byte bound. Each unit's
/// escaped size is measured once; each finished page is then checked exactly.
/// Returns each page's encoded result and the index of its first item.
pub fn delivery_pages(units: &[OrgUnit]) -> Result<(Vec<String>, Vec<u64>)> {
    use crate::capture_delivery::{
        MAX_PAGE_ITEMS, MAX_PAGE_JOURNAL_BYTES, MAX_PAGES, journal_bytes,
    };
    ensure!(
        !units.is_empty() && units.len() <= MAX_ORG_UNITS,
        "workspace_directory_org_unit_count_invalid"
    );
    // `{"items":[`, `],"page":N,"done":false}` and the string's quotes, escaped.
    const ENVELOPE: usize = 96;
    let mut groups: Vec<Vec<OrgUnit>> = Vec::new();
    let mut current: Vec<OrgUnit> = Vec::new();
    let mut current_bytes = ENVELOPE;
    for unit in units {
        let size = journal_bytes(&serde_json::to_string(unit)?)? - 2;
        ensure!(
            ENVELOPE + size <= MAX_PAGE_JOURNAL_BYTES,
            "workspace_directory_record_too_large"
        );
        let separator = usize::from(!current.is_empty());
        if current.len() == MAX_PAGE_ITEMS
            || current_bytes + separator + size > MAX_PAGE_JOURNAL_BYTES
        {
            groups.push(std::mem::take(&mut current));
            current_bytes = ENVELOPE;
        }
        current_bytes += usize::from(!current.is_empty()) + size;
        current.push(unit.clone());
    }
    groups.push(current);
    ensure!(
        groups.len() <= MAX_PAGES,
        "workspace_directory_delivery_exceeds_invocation"
    );
    let last = groups.len() - 1;
    let mut starts = Vec::with_capacity(groups.len());
    let mut start = 0u64;
    for group in &groups {
        starts.push(start);
        start += u64::try_from(group.len())?;
    }
    let pages = groups
        .into_iter()
        .enumerate()
        .map(|(index, items)| {
            let encoded = serde_json::to_string(&DeliveryPage {
                items,
                page: u64::try_from(index)?,
                done: index == last,
            })?;
            ensure!(
                journal_bytes(&encoded)? <= MAX_PAGE_JOURNAL_BYTES,
                "workspace_directory_page_too_large"
            );
            Ok(encoded)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((pages, starts))
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
    /// Requested by every user lookup; only the named read requires it.
    suspended: Option<bool>,
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

fn decode_user(bytes: &[u8]) -> Result<DirectoryUser> {
    ensure!(
        bytes.len() <= MAX_USER_RESPONSE_BYTES,
        "workspace_directory_response_too_large"
    );
    crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("workspace_directory_user_response_invalid"))
}

pub fn parse_user_path(bytes: &[u8], expected_customer: &str) -> Result<String> {
    let user = decode_user(bytes)?;
    ensure!(
        !user.customer_id.is_empty() && user.customer_id == expected_customer,
        "workspace_directory_customer_mismatch"
    );
    validate_path(&user.org_unit_path)?;
    Ok(user.org_unit_path)
}

/// A named user's path in `expected_customer`, or `None` for a user of another
/// customer or a suspended account. A malformed record, including one without
/// its suspension state, is an error whatever it would have answered.
pub fn parse_named_user_path(bytes: &[u8], expected_customer: &str) -> Result<Option<String>> {
    let user = decode_user(bytes)?;
    let suspended = user
        .suspended
        .ok_or_else(|| anyhow::anyhow!("workspace_directory_user_response_invalid"))?;
    ensure!(
        !user.customer_id.is_empty(),
        "workspace_directory_user_response_invalid"
    );
    validate_path(&user.org_unit_path)?;
    Ok((user.customer_id == expected_customer && !suspended).then_some(user.org_unit_path))
}

pub fn validate_hierarchy(units: Vec<OrgUnit>) -> Result<Vec<OrgUnit>> {
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

/// Native, production-fixed provider adapter. All URLs and methods are built
/// here; no app field or resource can select an origin, path, or HTTP method.
pub struct NativeDirectoryPort {
    client: reqwest::blocking::Client,
    directory_origin: reqwest::Url,
    customer_id: String,
    access_token: crate::google_auth::AccessToken,
}

impl NativeDirectoryPort {
    pub fn new(plan: AuthenticationPlan, customer_id: &str, mode: CaptureMode) -> Result<Self> {
        let timing = crate::request_timing::span("provider_client");
        let client = crate::google_auth::native_client(false)
            .map_err(|_| anyhow::anyhow!("workspace_directory_transport_unavailable"))?;
        drop(timing);
        let access_token = acquire_access_token(
            &client,
            &plan,
            crate::oauth::effects::wall_time()?,
            &crate::google_auth::Origins::production()?,
            mode,
        )?;
        Ok(Self {
            client,
            directory_origin: reqwest::Url::parse(&format!("{DIRECTORY_ORIGIN}/"))?,
            customer_id: customer_id.into(),
            access_token,
        })
    }

    #[cfg(test)]
    fn transport_fixture(
        plan: AuthenticationPlan,
        customer_id: &str,
        now: i64,
        mode: CaptureMode,
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
            &crate::google_auth::Origins::fixture(metadata_origin, iam_origin, oauth_endpoint),
            mode,
        )?;
        Ok(Self {
            client,
            directory_origin,
            customer_id: customer_id.into(),
            access_token,
        })
    }

    fn get(&self, url: reqwest::Url, max: usize, endpoint: &'static str) -> Result<Vec<u8>> {
        self.fetch(url, max, endpoint, false)?
            .ok_or_else(|| anyhow::anyhow!("workspace_directory_provider_refused"))
    }

    /// `None` only for a 404 when `absent_ok`, before any of its body is read.
    fn fetch(
        &self,
        url: reqwest::Url,
        max: usize,
        endpoint: &'static str,
        absent_ok: bool,
    ) -> Result<Option<Vec<u8>>> {
        let mut timing = crate::request_timing::provider("workspace_directory", endpoint);
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            self.access_token.bearer()
        ))
        .map_err(|_| anyhow::anyhow!("workspace_directory_authentication_failed"))?;
        authorization.set_sensitive(true);
        let response = self
            .client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .map_err(|_| anyhow::anyhow!("workspace_directory_provider_unavailable"))?;
        timing.status(response.status().as_u16());
        // A refused status is classified before any of its body is read.
        if absent_ok && response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(
            response.status().is_success(),
            "workspace_directory_provider_refused"
        );
        let reply = crate::google_auth::read_native(response, max).map_err(|unreached| {
            anyhow::anyhow!(if unreached.too_large {
                "workspace_directory_response_too_large"
            } else {
                "workspace_directory_provider_unavailable"
            })
        })?;
        ensure!(
            reply.body.len() <= max,
            "workspace_directory_response_too_large"
        );
        Ok(Some(reply.body))
    }

    /// One user record, or `None` when the Directory answers that it has no
    /// such user.
    fn user_record(&mut self, actor: &str) -> Result<Option<Vec<u8>>> {
        let mut url = self.directory_origin.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("workspace_directory_request_invalid"))?
            .extend(["admin", "directory", "v1", "users", actor]);
        url.query_pairs_mut()
            .append_pair("projection", "full")
            .append_pair("viewType", "admin_view")
            .append_pair("fields", "customerId,orgUnitPath,suspended");
        self.fetch(url, MAX_USER_RESPONSE_BYTES, "directory_user", true)
    }
}

/// Token acquisition through the shared keyless flow, over this adapter's own
/// fixed-origin client. Failures keep this provider's two stable codes.
fn acquire_access_token(
    client: &reqwest::blocking::Client,
    plan: &AuthenticationPlan,
    now: i64,
    origins: &crate::google_auth::Origins,
    mode: CaptureMode,
) -> Result<crate::google_auth::AccessToken> {
    struct Wire<'a> {
        client: &'a reqwest::blocking::Client,
        origins: &'a crate::google_auth::Origins,
    }
    impl crate::google_auth::TokenWire for Wire<'_> {
        fn exchange(
            &mut self,
            exchange: &crate::google_auth::Exchange<'_>,
            max_bytes: usize,
        ) -> std::result::Result<crate::google_auth::Reply, crate::google_auth::Unreached> {
            crate::google_auth::send_native(
                self.client,
                self.origins,
                "workspace_directory",
                exchange,
                max_bytes,
            )
        }
    }
    let (service_account, identity) = match plan {
        AuthenticationPlan::DirectServiceAccount { service_account } => (
            service_account.as_str(),
            crate::google_auth::Identity::ServiceAccount,
        ),
        AuthenticationPlan::DomainWideDelegation {
            service_account,
            delegated_admin,
        } => (
            service_account.as_str(),
            crate::google_auth::Identity::Delegated(delegated_admin),
        ),
    };
    let scopes = plan.scopes(mode);
    crate::google_auth::acquire(
        &mut Wire { client, origins },
        &crate::google_auth::TokenRequest {
            service_account,
            identity,
            scopes: &scopes,
        },
        now,
    )
    .map_err(|failure| {
        anyhow::anyhow!(match failure {
            crate::google_auth::Failure::WorkloadIdentityUnavailable => {
                "workspace_directory_workload_identity_unavailable"
            }
            _ => "workspace_directory_authentication_failed",
        })
    })
}

impl DirectoryReadPort for NativeDirectoryPort {
    fn user_org_unit_path(&mut self, actor: &str) -> Result<String> {
        let body = self
            .user_record(actor)?
            .ok_or_else(|| anyhow::anyhow!("workspace_directory_provider_refused"))?;
        parse_user_path(&body, &self.customer_id)
    }

    fn named_user_org_unit_path(&mut self, actor: &str) -> Result<Option<String>> {
        match self.user_record(actor)? {
            None => Ok(None),
            Some(body) => parse_named_user_path(&body, &self.customer_id),
        }
    }

    fn list_org_units(&mut self) -> Result<ProviderPage> {
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
        let body = self.get(url, MAX_RESPONSE_BYTES, "directory_orgunits")?;
        let response_bytes = body.len();
        Ok(ProviderPage {
            units: parse_org_unit_response(&body)?,
            response_bytes,
        })
    }
}

/// Offline Google wire shapes parsed by the same DTOs as the live adapter.
pub struct SimulatedDirectoryPort {
    database: std::path::PathBuf,
    scope: String,
    customer_id: String,
    actor: String,
}

impl SimulatedDirectoryPort {
    /// The world answers only for the user this port was opened for.
    fn user_record(&self, actor: &str) -> Result<Option<Vec<u8>>> {
        ensure!(actor == self.actor, "workspace_directory_actor_mismatch");
        crate::integrations::simulated::workspace_directory_read(
            &self.database,
            &self.scope,
            &self.customer_id,
            crate::integrations::simulated::DirectoryRead::User(actor),
        )
    }

    pub fn new(
        database: &std::path::Path,
        scope: &str,
        customer_id: &str,
        actor: &str,
    ) -> Result<Self> {
        crate::integrations::simulated::workspace_directory_check(database, scope, customer_id)?;
        Ok(Self {
            database: database.into(),
            scope: scope.into(),
            customer_id: customer_id.into(),
            actor: actor.into(),
        })
    }
}

impl DirectoryReadPort for SimulatedDirectoryPort {
    fn user_org_unit_path(&mut self, actor: &str) -> Result<String> {
        let bytes = self
            .user_record(actor)?
            .context("simulated_directory_user_unconfigured")?;
        parse_user_path(&bytes, &self.customer_id)
    }

    fn named_user_org_unit_path(&mut self, actor: &str) -> Result<Option<String>> {
        match self.user_record(actor)? {
            None => Ok(None),
            Some(bytes) => parse_named_user_path(&bytes, &self.customer_id),
        }
    }

    fn list_org_units(&mut self) -> Result<ProviderPage> {
        let bytes = crate::integrations::simulated::workspace_directory_read(
            &self.database,
            &self.scope,
            &self.customer_id,
            crate::integrations::simulated::DirectoryRead::Hierarchy,
        )?
        .context("workspace_directory_provider_refused")?;
        let response_bytes = bytes.len();
        Ok(ProviderPage {
            units: parse_org_unit_response(&bytes)?,
            response_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn hierarchy_validation_rejects_incomplete_conflicting_and_cyclic_provider_data() -> Result<()>
    {
        assert_eq!(validate_hierarchy(fixture())?.len(), 2);
        let mut conflict = fixture();
        conflict[1].parent_path = Some("/Other".into());
        assert!(validate_hierarchy(conflict).is_err());
        let mut cycle = fixture();
        cycle[0].parent_id = Some("eng".into());
        cycle[0].parent_path = Some("/Engineering".into());
        assert!(validate_hierarchy(cycle).is_err());
        let mut duplicate = fixture();
        duplicate[1].id = "root".into();
        assert!(validate_hierarchy(duplicate).is_err());
        let mut orphan = fixture();
        orphan[1].parent_id = Some("missing".into());
        assert!(validate_hierarchy(orphan).is_err());
        assert!(validate_hierarchy(Vec::new()).is_err());
        Ok(())
    }

    struct FixturePort {
        units: Vec<OrgUnit>,
        fail: bool,
        calls: usize,
    }

    impl DirectoryReadPort for FixturePort {
        fn user_org_unit_path(&mut self, _actor: &str) -> Result<String> {
            anyhow::bail!("a hierarchy read never looks up a user")
        }

        fn named_user_org_unit_path(&mut self, _actor: &str) -> Result<Option<String>> {
            anyhow::bail!("a hierarchy read never looks up a user")
        }

        fn list_org_units(&mut self) -> Result<ProviderPage> {
            self.calls += 1;
            if self.fail {
                anyhow::bail!("provider response is not surfaced")
            }
            Ok(ProviderPage {
                units: self.units.clone(),
                response_bytes: 256,
            })
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
    fn capture_identity_is_validated_before_any_provider_read() -> Result<()> {
        let mut missing_actor = capture_input("");
        missing_actor.customer_id.clear();
        let mut negative_time = capture_input("alice@example.test");
        negative_time.captured_at = -1;
        let mut long_connection = capture_input("alice@example.test");
        long_connection.connection_id = "x".repeat(129);
        for input in [missing_actor, negative_time, long_connection] {
            let mut port = FixturePort {
                units: fixture(),
                fail: false,
                calls: 0,
            };
            assert_eq!(
                deliver_hierarchy(input, &mut port).unwrap_err().to_string(),
                "workspace_directory_capture_identity_invalid"
            );
            assert_eq!(port.calls, 0);
        }
        Ok(())
    }

    #[test]
    fn a_delivery_is_content_identified_and_never_surfaces_provider_errors() -> Result<()> {
        let deliver = |input: CaptureInput, units: Vec<OrgUnit>| {
            let mut port = FixturePort {
                units,
                fail: false,
                calls: 0,
            };
            deliver_hierarchy(input, &mut port)
        };
        let (delivery, staged) = deliver(capture_input("alice@example.test"), fixture())?;
        assert_eq!(delivery.org_unit_count, 2);
        assert_eq!(delivery.page_count, 1);
        assert_eq!(delivery.captured_at, 100);
        assert_eq!(staged.starts, vec![0]);
        // The identity is the hierarchy read through this connection: not the
        // reader or the time, but any change of content or connection.
        let later = CaptureInput {
            captured_at: 900,
            ..capture_input("bob@example.test")
        };
        assert_eq!(deliver(later, fixture())?.0.id, delivery.id);
        let mut renamed = fixture();
        renamed[1].name = "Platform".into();
        assert_ne!(
            deliver(capture_input("alice@example.test"), renamed)?.0.id,
            delivery.id
        );
        let other_connection = CaptureInput {
            connection_id: "directory-connection/2".into(),
            ..capture_input("alice@example.test")
        };
        assert_ne!(deliver(other_connection, fixture())?.0.id, delivery.id);
        // The authority binds the reader too, even where the identity does not.
        assert_ne!(
            delivery_authority("customer-1", "directory-connection/1", "bob@example.test")?,
            staged.authority
        );
        let mut failing = FixturePort {
            units: fixture(),
            fail: true,
            calls: 0,
        };
        assert_eq!(
            deliver_hierarchy(capture_input("alice@example.test"), &mut failing)
                .unwrap_err()
                .to_string(),
            "workspace_directory_hierarchy_lookup_failed"
        );
        Ok(())
    }

    #[test]
    fn direct_http_adapter_uses_fixed_google_routes_and_real_response_shapes() -> Result<()> {
        use std::{net::TcpListener, thread};
        for (delegated, user_only) in [(false, false), (false, true), (true, true)] {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            let origin = format!("http://{}", listener.local_addr()?);
            let server = thread::spawn(move || -> Result<()> {
                let count = if delegated { 4 } else { 3 };
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
                        let scopes = if user_only {
                            serde_json::json!([USER_READ_SCOPE])
                        } else {
                            serde_json::json!([ORG_UNIT_READ_SCOPE])
                        };
                        ensure!(
                            input["scope"] == scopes && input["lifetime"] == "3600s",
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
                                && claims["scope"] == USER_READ_SCOPE,
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
                        ensure!(user_only, "a hierarchy read looked up a user");
                        ensure!(
                            request.contains("projection=full")
                                && request.contains("viewType=admin_view")
                                && request.contains("fields=customerId%2CorgUnitPath%2Csuspended")
                                && request.contains("Bearer directory-token"),
                            "user request projection invalid"
                        );
                        (r#"{"customerId":"customer-1","orgUnitPath":"/Engineering","primaryEmail":"alias@example.test","kind":"admin#directory#user"}"#.to_owned(), false)
                    } else if request.contains("/customer/customer-1/orgunits?") {
                        ensure!(!user_only, "user-only lookup attempted a hierarchy read");
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
            let mode = if user_only {
                CaptureMode::UserPath
            } else {
                CaptureMode::Hierarchy
            };
            let mut port = NativeDirectoryPort::transport_fixture(
                plan,
                "customer-1",
                100,
                mode,
                [origin.as_str(); 4],
            )?;
            if user_only {
                let observed = collect_user_path(capture_input("alice@example.test"), &mut port);
                server.join().expect("fixture server panicked")?;
                let observed = observed?;
                assert_eq!(observed.actor, "alice@example.test");
                assert_eq!(observed.customer_id, "customer-1");
                assert_eq!(observed.user_path, "/Engineering");
                assert_eq!(observed.captured_at, 100);
            } else {
                let delivered = deliver_hierarchy(capture_input("alice@example.test"), &mut port);
                server.join().expect("fixture server panicked")?;
                let (delivery, staged) = delivered?;
                assert_eq!(delivery.org_unit_count, 2);
                assert_eq!(staged.pages.len(), 1);
            }
        }
        Ok(())
    }

    #[test]
    fn delegated_hierarchy_transport_requests_only_org_unit_scope_and_never_users() -> Result<()> {
        use std::{net::TcpListener, thread};
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let origin = format!("http://{}", listener.local_addr()?);
        let server = thread::spawn(move || -> Result<()> {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept()?;
                let request = http_request(&mut stream)?;
                let (body, metadata) = if request.starts_with("GET /computeMetadata/") {
                    (
                        r#"{"access_token":"metadata-token","token_type":"Bearer"}"#.to_owned(),
                        true,
                    )
                } else if request.contains(":signJwt ") {
                    let input: serde_json::Value = serde_json::from_str(
                        request
                            .split_once("\r\n\r\n")
                            .context("IAM body missing")?
                            .1,
                    )?;
                    let claims_text = input["payload"].as_str().context("claims missing")?;
                    let claims: serde_json::Value = serde_json::from_str(claims_text)?;
                    ensure!(
                        claims["scope"] == ORG_UNIT_READ_SCOPE,
                        "hierarchy requested user scope"
                    );
                    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(br#"{"alg":"RS256","kid":"fixture-key"}"#);
                    let payload =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_text);
                    let signature =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 64]);
                    (serde_json::json!({"keyId":"fixture-key","signedJwt":format!("{header}.{payload}.{signature}")}).to_string(), false)
                } else if request.starts_with("POST /token ") {
                    (r#"{"access_token":"directory-token","token_type":"Bearer","expires_in":3600}"#.to_owned(), false)
                } else if request.contains("/customer/customer-1/orgunits?") {
                    ensure!(
                        request.contains("Bearer directory-token"),
                        "hierarchy token missing"
                    );
                    (r#"{"organizationUnits":[{"orgUnitId":"root","name":"Root","orgUnitPath":"/","parentOrgUnitId":null,"parentOrgUnitPath":null}]}"#.to_owned(), false)
                } else {
                    anyhow::bail!(
                        "unexpected request, including forbidden users lookup: {}",
                        request.lines().next().unwrap_or("missing")
                    )
                };
                fixture_response(&mut stream, &body, metadata)?;
            }
            Ok(())
        });
        let plan = AuthenticationPlan::DomainWideDelegation {
            service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
            delegated_admin: "admin@example.test".into(),
        };
        let mut port = NativeDirectoryPort::transport_fixture(
            plan,
            "customer-1",
            100,
            CaptureMode::Hierarchy,
            [origin.as_str(); 4],
        )?;
        let units = collect_hierarchy(&capture_input("alice@example.test"), &mut port)?;
        server.join().expect("fixture server panicked")?;
        assert_eq!(units.len(), 1);
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
        assert_eq!(plan.scopes(CaptureMode::Hierarchy), [ORG_UNIT_READ_SCOPE]);
        assert_eq!(plan.scopes(CaptureMode::UserPath), [USER_READ_SCOPE]);
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
    fn user_path_is_a_single_user_read_and_never_requires_hierarchy() -> Result<()> {
        struct UserOnly {
            path: Result<String>,
            lookups: usize,
            hierarchies: usize,
        }

        impl DirectoryReadPort for UserOnly {
            fn user_org_unit_path(&mut self, _actor: &str) -> Result<String> {
                self.lookups += 1;
                match &self.path {
                    Ok(path) => Ok(path.clone()),
                    Err(_) => anyhow::bail!("provider details must not escape"),
                }
            }

            fn named_user_org_unit_path(&mut self, _actor: &str) -> Result<Option<String>> {
                anyhow::bail!("the current actor's read never names a user")
            }

            fn list_org_units(&mut self) -> Result<ProviderPage> {
                self.hierarchies += 1;
                anyhow::bail!("hierarchy must not be fetched")
            }
        }

        let input = CaptureInput {
            customer_id: "customer-1".into(),
            connection_id: "directory@3".into(),
            actor: "person@example.test".into(),
            captured_at: 100,
        };
        let mut port = UserOnly {
            path: Ok("/".into()),
            lookups: 0,
            hierarchies: 0,
        };
        let observed = collect_user_path(input.clone(), &mut port)?;
        assert_eq!(observed.user_path, "/");
        assert_eq!((port.lookups, port.hierarchies), (1, 0));

        let mut port = UserOnly {
            path: Err(anyhow::anyhow!("secret provider response")),
            lookups: 0,
            hierarchies: 0,
        };
        let error = collect_user_path(input, &mut port).unwrap_err().to_string();
        assert_eq!(error, "workspace_directory_user_lookup_failed");
        assert_eq!((port.lookups, port.hierarchies), (1, 0));
        Ok(())
    }

    #[test]
    fn user_path_reserves_whole_authentication_envelope_and_user_only_scope() {
        assert_eq!(MAX_USER_LOOKUP_REQUEST_BYTES, MAX_CAPTURE_REQUEST_BYTES);
        assert_eq!(
            MAX_USER_LOOKUP_RESPONSE_BYTES,
            (4 * MAX_USER_RESPONSE_BYTES + 1) as u64
        );
        let direct = AuthenticationPlan::DirectServiceAccount {
            service_account: "svc@example.test".into(),
        };
        let delegated = AuthenticationPlan::DomainWideDelegation {
            service_account: "svc@example.test".into(),
            delegated_admin: "admin@example.test".into(),
        };
        assert_eq!(direct.scopes(CaptureMode::UserPath), [USER_READ_SCOPE]);
        assert_eq!(delegated.scopes(CaptureMode::UserPath), [USER_READ_SCOPE]);
    }

    #[test]
    fn provider_responses_are_strict_and_bounded() -> Result<()> {
        let response = br#"{"organizationUnits":[{"orgUnitId":"root","name":"Root","orgUnitPath":"/","parentOrgUnitId":null,"parentOrgUnitPath":null}],"kind":"admin#directory#orgUnits"}"#;
        let units = parse_org_unit_response(response)?;
        assert_eq!(validate_hierarchy(units)?.len(), 1);
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

    #[test]
    fn a_named_read_answers_not_found_only_for_the_providers_own_answer() -> Result<()> {
        // Another customer and a suspended account read as NotFound; a malformed
        // record or path is still a failure.
        assert_eq!(
            parse_named_user_path(
                br#"{"customerId":"customer-1","orgUnitPath":"/Engineering","suspended":false}"#,
                "customer-1"
            )?,
            Some("/Engineering".into())
        );
        assert_eq!(
            parse_named_user_path(
                br#"{"customerId":"customer-1","orgUnitPath":"/Engineering","suspended":true}"#,
                "customer-1"
            )?,
            None
        );
        assert_eq!(
            parse_named_user_path(
                br#"{"customerId":"other","orgUnitPath":"/","suspended":false}"#,
                "customer-1"
            )?,
            None
        );
        for malformed in [
            &br#"{"customerId":"","orgUnitPath":"/","suspended":false}"#[..],
            br#"{"customerId":"customer-1","orgUnitPath":"/../x","suspended":false}"#,
            br#"{"customerId":"other","orgUnitPath":"/../x","suspended":true}"#,
            br#"{"customerId":"customer-1","orgUnitPath":"/Engineering"}"#,
            br#"{"customerId":"customer-1","suspended":false}"#,
            br#"not json"#,
        ] {
            assert!(parse_named_user_path(malformed, "customer-1").is_err());
        }
        for invalid in [
            "",
            "plain",
            "@example.test",
            "alice@",
            "a@b@example.test",
            "alice@example.test/x",
            "alice@example.test?x",
            "alice@example.test#x",
            "alice%40@example.test",
            "alice\\x@example.test",
            " alice@example.test",
            "alice @example.test",
            "álice@example.test",
        ] {
            assert!(validate_named_actor(invalid).is_err(), "{invalid:?}");
        }
        validate_named_actor("first.last+tag@example.test")?;
        assert!(validate_named_actor(&format!("{}@example.test", "a".repeat(320))).is_err());

        struct Named(Result<Option<String>>);
        impl DirectoryReadPort for Named {
            fn user_org_unit_path(&mut self, _actor: &str) -> Result<String> {
                anyhow::bail!("a named read never reads the current actor")
            }

            fn named_user_org_unit_path(&mut self, _actor: &str) -> Result<Option<String>> {
                match &self.0 {
                    Ok(path) => Ok(path.clone()),
                    Err(_) => anyhow::bail!("provider details must not escape"),
                }
            }

            fn list_org_units(&mut self) -> Result<ProviderPage> {
                anyhow::bail!("hierarchy must not be fetched")
            }
        }
        let input = capture_input("bob@example.test");
        assert_eq!(
            collect_named_user_path(input.clone(), &mut Named(Ok(None)))?,
            NamedUserPath::NotFound
        );
        assert_eq!(
            collect_named_user_path(input.clone(), &mut Named(Ok(Some("/Sales".into()))))?,
            NamedUserPath::Found(UserPath {
                customer_id: input.customer_id.clone(),
                actor: "bob@example.test".into(),
                user_path: "/Sales".into(),
                captured_at: input.captured_at,
            })
        );
        assert_eq!(
            collect_named_user_path(input, &mut Named(Err(anyhow::anyhow!("secret"))))
                .unwrap_err()
                .to_string(),
            "workspace_directory_user_lookup_failed"
        );
        assert_eq!(
            collect_named_user_path(capture_input("not-an-address"), &mut Named(Ok(None)))
                .unwrap_err()
                .to_string(),
            "workspace_directory_named_user_invalid"
        );
        Ok(())
    }

    #[test]
    fn native_named_read_maps_only_404_to_not_found() -> Result<()> {
        use std::{net::TcpListener, thread};
        // 404 is the Directory's own "no such user" for the named read only; the
        // current actor's read still fails on it, and 403 and 500 fail both.
        for status in [
            "200 OK",
            "404 Not Found",
            "403 Forbidden",
            "500 Internal Server Error",
        ] {
            for named in [true, false] {
                let listener = TcpListener::bind(("127.0.0.1", 0))?;
                let origin = format!("http://{}", listener.local_addr()?);
                let server = thread::spawn(move || -> Result<()> {
                    use std::io::Write;
                    for _ in 0..3 {
                        let (mut stream, _) = listener.accept()?;
                        let request = http_request(&mut stream)?;
                        if request.starts_with("GET /computeMetadata/") {
                            fixture_response(
                                &mut stream,
                                r#"{"access_token":"metadata-token","token_type":"Bearer","expires_in":3600}"#,
                                true,
                            )?;
                        } else if request.contains(":generateAccessToken ") {
                            fixture_response(
                                &mut stream,
                                r#"{"accessToken":"directory-token","expireTime":"2030-01-01T00:00:00Z"}"#,
                                false,
                            )?;
                        } else if request.contains("/users/departed%40example.test?")
                            || request.contains("/users/departed@example.test?")
                        {
                            ensure!(
                                request.contains("fields=customerId%2CorgUnitPath%2Csuspended"),
                                "user request projection invalid"
                            );
                            let body = if status == "200 OK" {
                                r#"{"customerId":"customer-1","orgUnitPath":"/Sales","suspended":false}"#
                            } else {
                                r#"{"error":{"code":404,"message":"Resource Not Found: userKey"}}"#
                            };
                            write!(
                                stream,
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            )?;
                            stream.flush()?;
                        } else {
                            anyhow::bail!(
                                "unexpected request: {}",
                                request.lines().next().unwrap_or("missing")
                            )
                        }
                    }
                    Ok(())
                });
                let mut port = NativeDirectoryPort::transport_fixture(
                    AuthenticationPlan::DirectServiceAccount {
                        service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
                    },
                    "customer-1",
                    100,
                    CaptureMode::UserPath,
                    [origin.as_str(); 4],
                )?;
                let input = capture_input("departed@example.test");
                let observed = if named {
                    collect_named_user_path(input, &mut port)
                } else {
                    collect_user_path(input, &mut port).map(NamedUserPath::Found)
                };
                server.join().expect("fixture server panicked")?;
                match (status, named) {
                    ("200 OK", _) => match observed? {
                        NamedUserPath::Found(found) => assert_eq!(found.user_path, "/Sales"),
                        NamedUserPath::NotFound => panic!("{status} named={named}"),
                    },
                    ("404 Not Found", true) => {
                        assert_eq!(observed?, NamedUserPath::NotFound)
                    }
                    _ => assert_eq!(
                        observed.unwrap_err().to_string(),
                        "workspace_directory_user_lookup_failed",
                        "{status} named={named}"
                    ),
                }
            }
        }
        Ok(())
    }

    #[test]
    fn provider_timing_names_each_exchange_without_tokens_accounts_or_payloads() -> Result<()> {
        use std::{net::TcpListener, thread};
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let origin = format!("http://{}", listener.local_addr()?);
        let server = thread::spawn(move || -> Result<()> {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept()?;
                let request = http_request(&mut stream)?;
                let (body, metadata) = if request.starts_with("GET /computeMetadata/") {
                    (
                        r#"{"access_token":"metadata-secret-token","token_type":"Bearer"}"#
                            .to_owned(),
                        true,
                    )
                } else if request.contains(":generateAccessToken ") {
                    (
                        r#"{"accessToken":"directory-secret-token","expireTime":"2030-01-01T00:00:00Z"}"#
                            .to_owned(),
                        false,
                    )
                } else if request.contains("/users/") {
                    (
                        r#"{"customerId":"customer-1","orgUnitPath":"/Secret Engineering"}"#
                            .to_owned(),
                        false,
                    )
                } else {
                    anyhow::bail!(
                        "unexpected request: {}",
                        request.lines().next().unwrap_or("missing")
                    )
                };
                fixture_response(&mut stream, &body, metadata)?;
            }
            Ok(())
        });
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = crate::request_timing::Recorder::request(
            crate::request_timing::Output::Capture(captured.clone()),
            crate::request_timing::now(),
        );
        let observed = {
            let _entered = recorder.enter();
            let mut port = NativeDirectoryPort::transport_fixture(
                AuthenticationPlan::DirectServiceAccount {
                    service_account: "directory-reader@company.iam.gserviceaccount.com".into(),
                },
                "customer-1",
                100,
                CaptureMode::UserPath,
                [origin.as_str(); 4],
            )?;
            collect_user_path(capture_input("alice@example.test"), &mut port)
        };
        server.join().expect("fixture server panicked")?;
        assert_eq!(observed?.user_path, "/Secret Engineering");
        drop(recorder);
        let raw = captured.lock().unwrap().clone();
        assert_eq!(raw.len(), 1);
        let line: serde_json::Value = serde_json::from_str(&raw[0])?;
        let calls: Vec<_> = line["phases"]
            .as_array()
            .context("phases")?
            .iter()
            .filter(|phase| phase["phase"] == "provider")
            .map(|phase| {
                assert!(phase["ms"].as_f64().is_some_and(|ms| ms >= 0.0));
                (
                    phase["capability"].as_str().unwrap_or_default().to_owned(),
                    phase["endpoint"].as_str().unwrap_or_default().to_owned(),
                    phase["status"].as_u64().unwrap_or_default(),
                )
            })
            .collect();
        let expected =
            |endpoint: &str| ("workspace_directory".to_owned(), endpoint.to_owned(), 200);
        assert_eq!(
            calls,
            [
                expected("metadata_token"),
                expected("iam_token"),
                expected("directory_user")
            ]
        );
        assert_eq!(line["totals"]["provider_calls"], 3);
        for secret in [
            "metadata-secret-token",
            "directory-secret-token",
            "alice",
            "example.test",
            "Secret Engineering",
            "customer-1",
            "directory-reader",
            "127.0.0.1",
        ] {
            assert!(!raw[0].contains(secret), "{secret} leaked: {}", raw[0]);
        }
        Ok(())
    }
}

//! Actual process loss around fixed-family issuance and private delivery commits.
//! Only closed observations leave the fixture; private rows never implement Debug
//! or serialization. This is disposable Runtime/SQLite evidence, not live custody.
#![cfg(unix)]

use super::{Model, Step, World, effects};
use crate::store::{Fault, Runtime, SqlDecision};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::{
    Digest,
    credentials::{GrantMode, LineageRef, ManagedProfile, Namespace},
};
use ring::rand::SecureRandom as _;
use rusqlite::{Connection, types::Value as SqlValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::AsyncReadExt as _;

#[path = "delivery_crash_reopen_tests.rs"]
mod delivery;

const ACTOR: &str = "alice@example.com";
const INVOCATION: &str = "credential-crash-issuance";
const NOW: i64 = 1_000;
const CHILD: &str =
    "managed_credentials::simulation::crash_reopen::credential_crash_child";
const CHILD_CONFIG: &str = "DAY2_CREDENTIAL_CRASH_CHILD";
const WAIT: Duration = Duration::from_secs(60);
const PRIVATE_TABLES: &[&str] = &[
    "day2_credential_browser",
    "day2_credential_confirmations",
    "day2_credential_deliveries",
    "day2_credential_lineages",
    "day2_credential_material",
    "day2_credential_origins",
    "day2_credential_receipts",
    "day2_credential_reveals",
    "day2_credential_revocations",
    "day2_credential_schema_version",
    "day2_credential_versions",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Profile {
    Client,
    Personal,
}

impl Profile {
    fn tag(self) -> u8 {
        match self {
            Self::Client => 1,
            Self::Personal => 2,
        }
    }
    fn registration(self) -> &'static str {
        match self {
            Self::Client => "clients",
            Self::Personal => "personal",
        }
    }
    fn family(self) -> &'static str {
        match self {
            Self::Client => "client_keys",
            Self::Personal => "personal_keys",
        }
    }
    fn operation(self) -> &'static str {
        match self {
            Self::Client => "credential_metadata.create_client",
            Self::Personal => "credential_metadata.create_personal",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Client => "Crash client",
            Self::Personal => "Crash personal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Cut {
    BeforeCommit,
    AfterCommit,
}

impl Cut {
    fn tag(self) -> u8 {
        match self {
            Self::BeforeCommit => 1,
            Self::AfterCommit => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    profile: Profile,
    cut: Cut,
    seed: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "operation", content = "case", rename_all = "snake_case", deny_unknown_fields)]
enum ChildCase {
    Issue(Case),
    Delivery(delivery::Case),
}

impl ChildCase {
    fn profile(self) -> Profile {
        match self {
            Self::Issue(case) => case.profile,
            Self::Delivery(case) => case.profile,
        }
    }
    fn seed(self) -> u64 {
        match self {
            Self::Issue(case) => case.seed,
            Self::Delivery(case) => case.seed,
        }
    }
    fn require_marker(self, bytes: &[u8; 16], completion: bool) -> Result<()> {
        match self {
            Self::Issue(case) => require_marker(bytes, case, completion),
            Self::Delivery(case) => delivery::require_marker(bytes, case, completion),
        }
    }
    fn completion(self) -> [u8; 16] {
        match self {
            Self::Issue(case) => marker(case.profile, None, 2, 0),
            Self::Delivery(case) => delivery::marker(case, None, 2),
        }
    }
}

// Intentionally separate from replayable ID entropy. Different material on a
// later preparation cannot hide replacement behind a rewound synthetic stream.
struct Ports {
    ids: Arc<World>,
    secret_requests: AtomicUsize,
}

impl Ports {
    fn new(seed: u64) -> Arc<Self> {
        Arc::new(Self {
            ids: World::new(seed),
            secret_requests: AtomicUsize::new(0),
        })
    }
}

impl effects::Hooks for Ports {
    fn domain(&self) -> u64 {
        effects::Hooks::domain(self.ids.as_ref())
    }
    fn wall_time(&self) -> Result<i64> {
        effects::Hooks::wall_time(self.ids.as_ref())
    }
    fn monotonic(&self) -> Duration {
        effects::Hooks::monotonic(self.ids.as_ref())
    }
    fn fill_id(&self, bytes: &mut [u8]) -> Result<()> {
        effects::Hooks::fill_id(self.ids.as_ref(), bytes)
    }
    fn fill_secret(&self, bytes: &mut [u8]) -> Result<()> {
        self.secret_requests.fetch_add(1, Ordering::SeqCst);
        ring::rand::SystemRandom::new()
            .fill(bytes)
            .map_err(|_| anyhow::anyhow!("fixture private entropy unavailable"))
    }
}

fn host_seed(seed: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    for chunk in bytes.as_chunks_mut::<8>().0 {
        *chunk = seed.to_le_bytes();
    }
    bytes
}

fn load_runtime(instance: &Path, seed: u64) -> Result<Runtime> {
    let runtime = Runtime::load(instance, "app")?;
    let simulation = crate::simulation::Simulation::new(runtime, host_seed(seed), NOW * 1000)?;
    Ok(simulation
        .runtime()
        .clone()
        .with_credential_authority(Arc::new(super::HttpAuthority)))
}

struct Fixture {
    directory: tempfile::TempDir,
    instance: PathBuf,
    artifact: String,
}

impl Fixture {
    fn new(case: Case) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let artifact = PathBuf::from(
            std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
                .context("credential crash fixture artifact required")?,
        );
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let instance = directory.path().join("instance.json");
        let data = crate::development::verification_instance_data(&artifact, None, ACTOR)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&instance)?;
        file.write_all(&serde_json::to_vec(&data)?)?;
        file.sync_all()?;
        let ports = Ports::new(case.seed);
        let artifact = effects::scope(ports, || -> Result<String> {
            let runtime = load_runtime(&instance, case.seed)?;
            ensure!(!runtime.db().exists(), "crash fixture must be fresh");
            runtime.initialize()?;
            crate::managed_credentials::verification::confirm(
                &runtime,
                case.profile.operation(),
                ACTOR,
                INVOCATION,
                &input(case.profile),
                NOW,
            )?;
            runtime.accept(
                case.profile.operation(),
                ACTOR,
                INVOCATION,
                &input(case.profile),
                NOW,
            )?;
            Ok(runtime.artifact().id().into())
        })?;
        Ok(Self {
            directory,
            instance,
            artifact,
        })
    }
}

fn input(profile: Profile) -> Value {
    json!({"label":profile.label()})
}

struct Expected {
    profile: Profile,
    namespace: Namespace,
    family_contract: Digest,
    principal: String,
}

fn expected(runtime: &Runtime, profile: Profile) -> Result<Expected> {
    let family = runtime
        .artifact()
        .contract()
        .credential_manifest
        .iter()
        .find(|f| f.id.as_str() == profile.family())
        .context("fixed fixture family missing")?;
    ensure!(
        family.grant == GrantMode::Fixed
            && family.lifetime_seconds == 3600
            && matches!(
                (profile, &family.profile),
                (Profile::Client, ManagedProfile::Client)
                    | (Profile::Personal, ManagedProfile::Personal)
            ),
        "fixed fixture profile changed"
    );
    let active = runtime.sql_read(crate::authority_state::current)?;
    let namespace = active
        .document
        .credentials
        .get(profile.family())
        .context("fixture family not activated")?
        .binding
        .namespace
        .clone();
    let principal = match profile {
        Profile::Client => format!(
            "client/{}/{}",
            profile.family(),
            Digest::of(&("credential-client-v1", &namespace, INVOCATION))?
                .as_str()
                .trim_start_matches("sha256:")
        ),
        Profile::Personal => format!(
            "verification/{}",
            Digest::new(ACTOR.as_bytes())
                .as_str()
                .trim_start_matches("sha256:")
        ),
    };
    Ok(Expected {
        profile,
        namespace,
        family_contract: family.contract.clone(),
        principal,
    })
}

// Never Debug/Serialize: these include opaque verifier/ciphertext cells solely
// for complete before/after equality, not for evidence or diagnostics.
#[derive(PartialEq)]
struct PrivateImage(BTreeMap<String, Vec<Vec<SqlValue>>>);

fn private_image(db: &Connection) -> Result<PrivateImage> {
    let mut names = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name GLOB 'day2_credential_*' ORDER BY name")?;
    let actual = names
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        actual.iter().map(String::as_str).collect::<BTreeSet<_>>()
            == PRIVATE_TABLES.iter().copied().collect(),
        "credential private snapshot inventory changed"
    );
    let mut image = BTreeMap::new();
    for &table in PRIVATE_TABLES
        .iter()
        .chain(["entries", "key_receipts", "use_receipts"].iter())
    {
        let count: i64 =
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
        ensure!((0..=4).contains(&count), "credential snapshot row bound");
        let mut query = db.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
        let columns = query.column_count();
        let mut rows = query.query([])?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            let cells = (0..columns)
                .map(|i| row.get::<_, SqlValue>(i))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(
                cells.iter().all(|v| match v {
                    SqlValue::Text(s) => s.len() <= 65536,
                    SqlValue::Blob(b) => b.len() <= 8192,
                    _ => true,
                }),
                "credential snapshot cell bound"
            );
            values.push(cells);
        }
        ensure!(
            values.len() as i64 == count,
            "credential snapshot incomplete"
        );
        image.insert(table.into(), values);
    }
    Ok(PrivateImage(image))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    product_rows: u64,
    product_receipts: u64,
    lineages: u64,
    versions: u64,
    material: u64,
    deliveries: u64,
    receipts: u64,
    revision: u64,
    committed: bool,
    active: bool,
    available: bool,
}

struct Snapshot {
    projection: Projection,
    private: PrivateImage,
    public: Option<Value>,
}

struct LineageRow {
    id: String,
    head: String,
    revision: i64,
    state: String,
    namespace: String,
    family: String,
    contract: String,
    principal: String,
    creator: String,
    recipient: String,
    session: String,
}

fn count(db: &Connection, table: &str) -> Result<u64> {
    let count: i64 = db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
    ensure!(
        (0..=4).contains(&count),
        "credential product snapshot row bound"
    );
    Ok(u64::try_from(count)?)
}

fn capture(db: &Connection, e: &Expected) -> Result<Snapshot> {
    let snapshot = capture_lifecycle(db, e)?;
    ensure!(
        snapshot.private.0["day2_credential_reveals"].is_empty(),
        "issuance changed an unrelated lifecycle table"
    );
    Ok(snapshot)
}

fn capture_lifecycle(db: &Connection, e: &Expected) -> Result<Snapshot> {
    let private = private_image(db)?;
    let n = |name: &str| private.0[name].len() as u64;
    let mut projection = Projection {
        product_rows: count(db, "entries")?,
        product_receipts: count(db, "key_receipts")?,
        lineages: n("day2_credential_lineages"),
        versions: n("day2_credential_versions"),
        material: n("day2_credential_material"),
        deliveries: n("day2_credential_deliveries"),
        receipts: n("day2_credential_receipts"),
        revision: 0,
        committed: false,
        active: false,
        available: false,
    };
    ensure!(
        count(db, "use_receipts")? == 0
            && n("day2_credential_revocations") == 0,
        "issuance changed an unrelated lifecycle table"
    );
    let (status, outcome): (String, Option<String>) = db.query_row(
        "SELECT status,outcome FROM day2_invocations WHERE id=?1",
        [INVOCATION],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let public = outcome
        .as_ref()
        .map(|raw| crate::json::decode::<Value>(raw.as_bytes()))
        .transpose()?;
    if projection.lineages == 0 {
        ensure!(
            status == "pending" && public.is_none(),
            "uncommitted credential has a public receipt"
        );
    } else {
        ensure!(projection.lineages == 1, "issuance created extra lineage");
        let LineageRow { id:lineage, head, revision, state, namespace, family, contract, principal, creator, recipient, session } = db.query_row(
            "SELECT id,head,revision,state,namespace_json,family,family_contract,principal,creator,recipient,session FROM day2_credential_lineages", [], |r| Ok(LineageRow { id:r.get(0)?,head:r.get(1)?,revision:r.get(2)?,state:r.get(3)?,namespace:r.get(4)?,family:r.get(5)?,contract:r.get(6)?,principal:r.get(7)?,creator:r.get(8)?,recipient:r.get(9)?,session:r.get(10)? }))?;
        ensure!(
            crate::json::decode::<Namespace>(namespace.as_bytes())? == e.namespace
                && family == e.profile.family()
                && contract == e.family_contract.as_str()
                && principal == e.principal
                && creator == ACTOR
                && recipient == ACTOR
                && session == format!("verification-{INVOCATION}"),
            "credential scope/profile identity differs"
        );
        let (version, owner, predecessor): (String, String, Option<String>) = db.query_row(
            "SELECT id,lineage,predecessor FROM day2_credential_versions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            version == head && owner == lineage && predecessor.is_none(),
            "credential version relation differs"
        );
        let (material_version, identity, material_revision, envelope_revision, encryption_version): (String,String,i64,i64,String) = db.query_row(
            "SELECT version,identity_json,material_revision,envelope_revision,encryption_key_version FROM day2_credential_material", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        let identity: super::super::crypto::MaterialIdentity =
            crate::json::decode(identity.as_bytes())?;
        ensure!(
            material_version == head
                && material_revision == 1
                && envelope_revision == 1
                && encryption_version == "encryption-v1"
                && identity.namespace == e.namespace
                && identity.family == e.profile.family()
                && identity.lineage == lineage
                && identity.version == head
                && identity.recipient == ACTOR
                && identity.security_epoch == 7
                && identity.material_revision == 1,
            "credential material binding differs"
        );
        let (version, delivery): (String, String) = db.query_row(
            "SELECT version,state FROM day2_credential_deliveries",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(version == head, "credential delivery version differs");
        let (invocation, receipt_lineage, receipt_head): (String, String, String) = db.query_row(
            "SELECT invocation,lineage,version FROM day2_credential_receipts",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            invocation == INVOCATION && receipt_lineage == lineage && receipt_head == head,
            "credential private receipt differs"
        );
        let public = public
            .as_ref()
            .context("committed credential public receipt absent")?;
        ensure!(
            status == "success"
                && public.as_object().is_some_and(|o| o
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
                    == BTreeSet::from(["status", "result", "error"]))
                && public["status"] == "success"
                && public["error"] == "",
            "credential public outcome shape differs"
        );
        let result = public["result"]
            .as_object()
            .context("credential public result shape")?;
        ensure!(
            result.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["lineage", "version", "label", "expires_at"])
                && result["version"] == head
                && result["label"] == e.profile.label()
                && result["expires_at"] == NOW + 3600,
            "credential public metadata differs"
        );
        let public_lineage = result["lineage"]
            .as_str()
            .context("credential public reference")?;
        let encoded = public_lineage
            .strip_prefix(&format!("cr1_{}_", e.profile.registration()))
            .context("credential public family reference differs")?;
        let decoded: LineageRef = crate::json::decode(&URL_SAFE_NO_PAD.decode(encoded)?)?;
        ensure!(
            decoded.id == lineage
                && decoded.namespace == e.namespace
                && decoded.family.as_str() == e.profile.family(),
            "credential public/private lineage differs"
        );
        let entry: String = db.query_row("SELECT note FROM entries", [], |r| r.get(0))?;
        let (product_family, product_lineage, product_head, product_revision): (
            String,
            String,
            String,
            Vec<u8>,
        ) = db.query_row(
            "SELECT family,lineage,head,revision FROM key_receipts",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        ensure!(
            entry == public_lineage
                && product_family == e.profile.registration()
                && product_lineage == public_lineage
                && product_head == head
                // Product U64 fields use the ordinary exact big-endian BLOB
                // codec; the private lineage revision remains an INTEGER.
                && product_revision == 1_u64.to_be_bytes(),
            "credential product registration differs"
        );
        projection.revision = u64::try_from(revision)?;
        projection.committed = true;
        projection.active = state == "active";
        projection.available = delivery == "available";
    }
    Ok(Snapshot {
        projection,
        private,
        public,
    })
}

fn check(model: &Model, p: &Projection) -> Result<()> {
    let n = u64::from(model.issued);
    ensure!(
        p.product_rows == n
            && p.product_receipts == n
            && p.lineages == n
            && p.versions == model.versions
            && p.material == n
            && p.deliveries == n
            && p.receipts == n
            && p.revision == model.revision
            && p.committed == model.issued
            && p.active == (model.issued && !model.revoked)
            && p.available == (model.issued && !model.closed),
        "credential crash independent oracle divergence"
    );
    Ok(())
}

struct Frame {
    id: String,
    database: PathBuf,
    artifact: String,
    pid: u32,
    thread: std::thread::ThreadId,
    expected: Expected,
    cut: Cut,
    before: Option<PrivateImage>,
    exit_instead: bool,
}
thread_local! { static FRAME: RefCell<Option<Frame>> = const { RefCell::new(None) }; }

/// Called at only the two cfg(test) transaction-coordinator sites. The unarmed
/// branch reads TLS only: no I/O, clocks, authority calls or database opening.
pub(crate) fn checkpoint(
    runtime: &Runtime,
    id: &str,
    cut: Cut,
    staged: Option<&Connection>,
) -> Result<()> {
    FRAME.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(frame) = slot.as_mut() else {
            return Ok(());
        };
        ensure!(
            frame.id == id
                && frame.database == runtime.db()
                && frame.artifact == runtime.artifact().id()
                && frame.pid == std::process::id()
                && frame.thread == std::thread::current().id(),
            "credential crash checkpoint owner differs"
        );
        let snapshot = match cut {
            Cut::BeforeCommit => capture(
                staged.context("staged checkpoint requires original transaction")?,
                &frame.expected,
            )?,
            Cut::AfterCommit => {
                ensure!(
                    staged.is_none() && frame.before.is_some(),
                    "committed checkpoint lacks staged predecessor"
                );
                runtime.sql_read(|db| capture(db, &frame.expected))?
            }
        };
        let mut model = Model {
            now: NOW,
            ..Model::default()
        };
        model.apply(Step::Issue);
        check(&model, &snapshot.projection)?;
        match cut {
            Cut::BeforeCommit => frame.before = Some(snapshot.private),
            Cut::AfterCommit => ensure!(
                frame.before.as_ref() == Some(&snapshot.private),
                "coordinator committed different private state"
            ),
        }
        if frame.cut == cut {
            std::io::stderr().write_all(&marker(frame.expected.profile, Some(cut), 1, 0))?;
            std::io::stderr().flush()?;
            if frame.exit_instead {
                std::process::exit(0);
            }
            let mut release = [0];
            std::io::stdin().read_exact(&mut release)?;
            anyhow::bail!("credential crash checkpoint was released without process loss");
        }
        Ok(())
    })
}

fn marker(profile: Profile, cut: Option<Cut>, kind: u8, phase: u8) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(b"D2CRASH1");
    bytes[8] = profile.tag();
    bytes[9] = cut.map_or(0, Cut::tag);
    bytes[10] = kind;
    bytes[11] = phase;
    bytes
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Behavior {
    Pause,
    Complete,
    SkipCheckpoint,
    ExitAtCheckpoint,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildInput {
    format: u32,
    instance: PathBuf,
    case: ChildCase,
    behavior: Behavior,
}

fn require_marker(bytes: &[u8; 16], case: Case, completion: bool) -> Result<()> {
    if bytes[..8] == *b"D2CRASH1"
        && bytes[10] == 3
        && (1..=6).contains(&bytes[11])
        && bytes[12..] == [0; 4]
    {
        anyhow::bail!("credential child refused at closed phase {}", bytes[11]);
    }
    ensure!(
        bytes[..8] == *b"D2CRASH1"
            && bytes[8] == case.profile.tag()
            && bytes[9] == if completion { 0 } else { case.cut.tag() }
            && bytes[10] == if completion { 2 } else { 1 }
            && bytes[11..] == [0; 5],
        "credential child cut protocol differs"
    );
    Ok(())
}

// The helper is not a coverage control. Without an explicit parent-created
// configuration it performs no work; only the parent campaign claims cases.
#[test]
fn credential_crash_child() -> Result<()> {
    let Some(path) = std::env::var_os(CHILD_CONFIG) else {
        return Ok(());
    };
    let mut phase = 1;
    let result = (|| -> Result<()> {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4096, "credential child configuration bound");
        let config: ChildInput = crate::json::decode(&bytes)?;
        ensure!(config.format == 2, "credential child configuration version");
        let ports = Ports::new(config.case.seed().wrapping_add(0x1000));
        effects::scope(ports, || -> Result<()> {
            phase = 2;
            let runtime = load_runtime(&config.instance, config.case.seed())?;
            phase = 3;
            let expectation = expected(&runtime, config.case.profile())?;
            phase = 4;
            match config.case {
                ChildCase::Issue(case) => {
            let armed = matches!(
                config.behavior,
                Behavior::Pause | Behavior::ExitAtCheckpoint
            );
            if armed {
                FRAME.with(|slot| {
                    ensure!(
                        slot.borrow().is_none(),
                        "credential child checkpoint already armed"
                    );
                    *slot.borrow_mut() = Some(Frame {
                        id: INVOCATION.into(),
                        database: runtime.db().to_owned(),
                        artifact: runtime.artifact().id().into(),
                        pid: std::process::id(),
                        thread: std::thread::current().id(),
                        expected: expectation,
                        cut: case.cut,
                        before: None,
                        exit_instead: matches!(config.behavior, Behavior::ExitAtCheckpoint),
                    });
                    Ok::<_, anyhow::Error>(())
                })?;
            }
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    FRAME.with(|slot| *slot.borrow_mut() = None);
                }
            }
            let _reset = Reset;
            let outcome = runtime.execute(INVOCATION, Fault::None)?;
            ensure!(
                outcome.status == "success",
                "credential child command failed"
            );
            ensure!(!armed, "credential requested checkpoint was never reached");
                }
                ChildCase::Delivery(case) => {
                    delivery::execute(&runtime, case, config.behavior, &expectation)?;
                }
            }
            phase = 6;
            std::io::stderr().write_all(&config.case.completion())?;
            std::io::stderr().flush()?;
            Ok(())
        })
    })();
    if result.is_err() {
        // No downstream error formatting: an adapter regression could place
        // material in an error. Parent sees only an invalid closed failure frame.
        let _ = std::io::stderr().write_all(&marker(Profile::Client, None, 3, phase));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildStatus {
    code: Option<i32>,
    signal: Option<i32>,
    kill_requested: bool,
    eof: bool,
}

fn require_killed(status: &ChildStatus) -> Result<()> {
    ensure!(
        status.kill_requested && status.code.is_none() && status.signal == Some(9) && status.eof,
        "credential child actual kill/EOF missing"
    );
    Ok(())
}

async fn cleanup(child: &mut tokio::process::Child) -> Result<()> {
    let requested = child.start_kill();
    let waited = tokio::time::timeout(WAIT, child.wait()).await;
    ensure!(
        matches!(waited, Ok(Ok(_))),
        "credential child cleanup completion unknown"
    );
    // start_kill may report that an already-exited child is absent; known wait
    // completion is still retained. An unknown wait is never a successful case.
    let _ = requested;
    Ok(())
}

async fn child(
    fixture: &Fixture,
    case: ChildCase,
    behavior: Behavior,
    kill: bool,
) -> Result<ChildStatus> {
    use std::os::unix::{fs::OpenOptionsExt, process::ExitStatusExt};
    let config = fixture.directory.path().join("child.json");
    let body = serde_json::to_vec(&ChildInput {
        format: 2,
        instance: fixture.instance.clone(),
        case,
        behavior,
    })?;
    ensure!(body.len() <= 4096, "credential child configuration bound");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&config)?;
    file.write_all(&body)?;
    file.sync_all()?;
    drop(file);
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args(["--exact", CHILD, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(CHILD_CONFIG, &config)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| anyhow::anyhow!("credential child spawn refused"))?;
    let result = async {
        let mut stderr = child
            .stderr
            .take()
            .context("credential child control pipe")?;
        let mut bytes = [0; 16];
        tokio::time::timeout(WAIT, stderr.read_exact(&mut bytes))
            .await
            .map_err(|_| anyhow::anyhow!("credential child checkpoint deadline"))?
            .map_err(|_| anyhow::anyhow!("credential child checkpoint unavailable"))?;
        case.require_marker(&bytes, matches!(behavior, Behavior::Complete))?;
        if kill {
            child
                .start_kill()
                .map_err(|_| anyhow::anyhow!("credential child kill request refused"))?;
        }
        let status = tokio::time::timeout(WAIT, child.wait())
            .await
            .map_err(|_| anyhow::anyhow!("credential child wait deadline"))?
            .map_err(|_| anyhow::anyhow!("credential child wait failed"))?;
        let mut extra = [0; 1];
        let tail = tokio::time::timeout(WAIT, stderr.read(&mut extra))
            .await
            .map_err(|_| anyhow::anyhow!("credential child pipe EOF deadline"))?
            .map_err(|_| anyhow::anyhow!("credential child pipe EOF failed"))?;
        ensure!(
            tail == 0,
            "credential child emitted unexpected control bytes"
        );
        let result = ChildStatus {
            code: status.code(),
            signal: status.signal(),
            kill_requested: kill,
            eof: true,
        };
        if kill {
            require_killed(&result)?;
        } else {
            ensure!(status.success(), "credential baseline child failed");
        }
        Ok::<_, anyhow::Error>(result)
    }
    .await;
    if result.is_err() {
        cleanup(&mut child).await?;
    }
    fs::remove_file(config)?;
    result
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    case: Case,
    child: ChildStatus,
    reopened: Projection,
    recovered: Projection,
    repeated: Projection,
    recovery_needed_material: bool,
}

async fn history(case: Case) -> Result<Observation> {
    let fixture =
        Fixture::new(case).map_err(|_| anyhow::anyhow!("credential crash fixture setup failed"))?;
    let status = child(&fixture, ChildCase::Issue(case), Behavior::Pause, true).await?;
    let ports = Ports::new(case.seed.wrapping_add(0x2000));
    effects::scope(ports.clone(), || -> Result<Observation> {
        let runtime = load_runtime(&fixture.instance, case.seed)?;
        ensure!(
            runtime.artifact().id() == fixture.artifact,
            "credential reopen artifact differs"
        );
        let e = expected(&runtime, case.profile)?;
        let before = runtime.sql_read(|db| capture(db, &e))?;
        let mut oracle = Model {
            now: NOW,
            ..Model::default()
        };
        if case.cut == Cut::AfterCommit {
            oracle.apply(Step::Issue);
        }
        check(&oracle, &before.projection)?;
        let first_entropy = ports.secret_requests.load(Ordering::SeqCst);
        runtime.accept(
            case.profile.operation(),
            ACTOR,
            INVOCATION,
            &input(case.profile),
            NOW,
        )?;
        let recovered = runtime.execute(INVOCATION, Fault::None)?;
        oracle.apply(Step::Issue);
        let after = runtime.sql_read(|db| capture(db, &e))?;
        check(&oracle, &after.projection)?;
        ensure!(
            serde_json::to_value(&recovered)?
                == after
                    .public
                    .clone()
                    .context("credential recovered receipt absent")?,
            "credential recovery public result differs"
        );
        let entropy = ports.secret_requests.load(Ordering::SeqCst) - first_entropy;
        ensure!(
            (entropy > 0) == (case.cut == Cut::BeforeCommit),
            "credential recovery prepared unexpected new material"
        );
        if case.cut == Cut::AfterCommit {
            ensure!(
                before.private == after.private && before.public == after.public,
                "committed recovery replaced credential state"
            );
        }
        let repeated = runtime.execute(INVOCATION, Fault::None)?;
        let again = runtime.sql_read(|db| capture(db, &e))?;
        check(&oracle, &again.projection)?;
        ensure!(
            repeated == recovered
                && after.private == again.private
                && after.public == again.public
                && ports.secret_requests.load(Ordering::SeqCst) == first_entropy + entropy,
            "duplicate recovery issued extra material or product state"
        );
        let changed = json!({"label":"Different confirmed label"});
        ensure!(
            runtime
                .accept(case.profile.operation(), ACTOR, INVOCATION, &changed, NOW)
                .is_err(),
            "changed duplicate issuance accepted"
        );
        let final_state = runtime.sql_read(|db| capture(db, &e))?;
        ensure!(
            final_state.private == again.private && final_state.public == again.public,
            "changed duplicate modified credential state"
        );
        Ok(Observation {
            case,
            child: status,
            reopened: before.projection,
            recovered: after.projection,
            repeated: again.projection,
            recovery_needed_material: entropy > 0,
        })
    })
}

fn implementation() -> Digest {
    Digest::of(&(
        "credential-runtime-crash-v1",
        include_str!("crash_reopen_tests.rs"),
        include_str!("delivery_crash_reopen_tests.rs"),
        include_str!("simulation.rs"),
        include_str!("store.rs"),
        include_str!("issuance.rs"),
        include_str!("../store.rs"),
        include_str!("../../../../toolchain.json"),
    ))
    .expect("fixed source tuple serializes")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    format: u32,
    implementation: Digest,
    artifact: String,
    case: ChildCase,
}

fn decode_replay(bytes: &[u8], artifact: &str) -> Result<ChildCase> {
    ensure!(bytes.len() <= 4096, "credential crash replay bound");
    let replay: Replay = crate::json::decode(bytes)?;
    ensure!(
        replay.format == 2
            && replay.implementation == implementation()
            && replay.artifact == artifact,
        "credential crash replay source/artifact differs"
    );
    Ok(replay.case)
}

async fn checked(case: Case, artifact: &str) -> Result<Observation> {
    let result = async {
        let first = history(case).await?;
        ensure!(
            history(case).await? == first,
            "credential crash history replay differs"
        );
        Ok::<_, anyhow::Error>(first)
    }
    .await;
    match result {
        Ok(observed) => Ok(observed),
        Err(_) => {
            retain_failure(ChildCase::Issue(case), artifact)?;
            anyhow::bail!(
                "credential crash/reopen case diverged; redacted source-bound case retained"
            );
        }
    }
}

fn retain_failure(case: ChildCase, artifact: &str) -> Result<()> {
    // No downstream error, private snapshots, identifiers or entropy.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/credential-crash-reopen");
    fs::create_dir_all(&root)?;
    let directory = tempfile::Builder::new()
        .prefix("failure-")
        .tempdir_in(root)?
        .keep();
    fs::write(directory.join("failure.json"), serde_json::to_vec(&Replay {
        format: 2,
        implementation: implementation(),
        artifact: artifact.into(),
        case,
    })?)?;
    Ok(())
}

fn artifact_id() -> Result<String> {
    let path = PathBuf::from(
        std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
            .context("credential crash fixture artifact required")?,
    );
    Ok(crate::artifact::LoadedArtifact::load(&path)?.id().into())
}

#[tokio::test]
async fn fixed_client_and_personal_issuance_survive_real_process_loss_and_reopen() -> Result<()> {
    let artifact = artifact_id()?;
    let mut observed = Vec::new();
    for profile in [Profile::Client, Profile::Personal] {
        let baseline_case = Case {
            profile,
            cut: Cut::BeforeCommit,
            seed: 11,
        };
        let fixture = Fixture::new(baseline_case)?;
        child(&fixture, ChildCase::Issue(baseline_case), Behavior::Complete, false).await?;
        let ports = Ports::new(12);
        effects::scope(ports, || -> Result<()> {
            let runtime = load_runtime(&fixture.instance, 11)?;
            let e = expected(&runtime, profile)?;
            let state = runtime.sql_read(|db| capture(db, &e))?;
            let mut model = Model {
                now: NOW,
                ..Model::default()
            };
            model.apply(Step::Issue);
            check(&model, &state.projection)?;
            // A valid native fixture must pass first; then the same reader
            // must refuse another validly encoded product revision.
            runtime.sql_decide(|tx| {
                ensure!(
                    tx.execute(
                        "UPDATE key_receipts SET revision=?1",
                        [2_u64.to_be_bytes().to_vec()],
                    )? == 1,
                    "credential product revision control missed its row"
                );
                let failure = capture(tx, &e)
                    .err()
                    .context("credential reader accepted wrong product revision")?;
                ensure!(
                    failure.to_string() == "credential product registration differs",
                    "credential product revision refused at wrong boundary"
                );
                Ok(SqlDecision::Rollback(()))
            })?;
            let restored = runtime.sql_read(|db| capture(db, &e))?;
            ensure!(
                restored.private == state.private && restored.public == state.public,
                "credential product revision control escaped rollback"
            );
            Ok(())
        })?;
        for cut in [Cut::BeforeCommit, Cut::AfterCommit] {
            for seed in [1, 19, 401] {
                observed.push(checked(Case { profile, cut, seed }, &artifact).await?);
            }
        }
    }
    let declared: BTreeSet<_> = [Profile::Client, Profile::Personal]
        .into_iter()
        .flat_map(|profile| {
            [Cut::BeforeCommit, Cut::AfterCommit]
                .into_iter()
                .flat_map(move |cut| {
                    [1, 19, 401]
                        .into_iter()
                        .map(move |seed| Case { profile, cut, seed })
                })
        })
        .collect();
    ensure!(
        observed.len() == 12
            && observed.iter().map(|o| o.case).collect::<BTreeSet<_>>() == declared
            && observed
                .iter()
                .all(|o| o.child.signal == Some(9) && o.child.eof),
        "credential declared crash cases did not run"
    );
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/credential-crash-reopen");
    fs::create_dir_all(&root)?;
    let directory = tempfile::Builder::new()
        .prefix("campaign-")
        .tempdir_in(root)?
        .keep();
    fs::write(
        directory.join("receipt.json"),
        serde_json::to_vec_pretty(
            &json!({"format":1,"status":"passed","scope":"disposable_runtime_fixed_issuance_not_live_custody","implementation":implementation(),"artifact":artifact,"each_history_replayed":true,"observations":observed}),
        )?,
    )?;
    Ok(())
}

#[tokio::test]
async fn real_child_cut_and_death_guards_refuse_normal_exit_and_missing_checkpoint() -> Result<()> {
    let case = Case {
        profile: Profile::Client,
        cut: Cut::BeforeCommit,
        seed: 31,
    };
    let baseline = Fixture::new(case)?;
    child(&baseline, ChildCase::Issue(case), Behavior::Pause, true).await?;
    let skipped = Fixture::new(case)?;
    ensure!(
        child(&skipped, ChildCase::Issue(case), Behavior::SkipCheckpoint, true)
            .await
            .is_err(),
        "missing checkpoint passed actual guard"
    );
    let graceful = Fixture::new(case)?;
    let status = child(&graceful, ChildCase::Issue(case), Behavior::ExitAtCheckpoint, false).await?;
    ensure!(
        require_killed(&status).is_err(),
        "normal child exit counted as crash"
    );
    Ok(())
}

#[test]
fn independent_oracle_and_cut_protocol_refuse_substitutes() -> Result<()> {
    let model = Model {
        now: NOW,
        ..Model::default()
    };
    let empty = Projection {
        product_rows: 0,
        product_receipts: 0,
        lineages: 0,
        versions: 0,
        material: 0,
        deliveries: 0,
        receipts: 0,
        revision: 0,
        committed: false,
        active: false,
        available: false,
    };
    check(&model, &empty)?;
    let mut issued = Model {
        now: NOW,
        ..Model::default()
    };
    issued.apply(Step::Issue);
    let good = Projection {
        product_rows: 1,
        product_receipts: 1,
        lineages: 1,
        versions: 1,
        material: 1,
        deliveries: 1,
        receipts: 1,
        revision: 1,
        committed: true,
        active: true,
        available: true,
    };
    check(&issued, &good)?;
    for mutant in 0..5 {
        let mut bad = good.clone();
        match mutant {
            0 => bad.product_rows = 0,
            1 => bad.versions = 2,
            2 => bad.receipts = 0,
            3 => bad.committed = false,
            _ => bad.available = false,
        };
        ensure!(
            check(&issued, &bad).is_err(),
            "independent credential oracle accepted mutant"
        );
    }
    let case = Case {
        profile: Profile::Client,
        cut: Cut::BeforeCommit,
        seed: 1,
    };
    let good = marker(case.profile, Some(case.cut), 1, 0);
    require_marker(&good, case, false)?;
    for index in [0, 8, 9, 10, 11, 15] {
        let mut bad = good;
        bad[index] ^= 0x7f;
        ensure!(
            require_marker(&bad, case, false).is_err(),
            "credential protocol accepted mutated marker"
        );
    }
    Ok(())
}

#[tokio::test]
async fn replay_saved_credential_process_loss() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_CREDENTIAL_CRASH_REPLAY") else {
        return Ok(());
    };
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    let artifact = artifact_id()?;
    match decode_replay(&bytes, &artifact)? {
        ChildCase::Issue(case) => { checked(case, &artifact).await?; }
        ChildCase::Delivery(case) => { delivery::checked(case, &artifact).await?; }
    }
    Ok(())
}

#[test]
fn credential_crash_replay_refuses_unknown_fields_source_and_size() -> Result<()> {
    let artifact = "sha256:fixture-artifact";
    let case = Case {
        profile: Profile::Client,
        cut: Cut::BeforeCommit,
        seed: 3,
    };
    let mut value = serde_json::to_value(Replay {
        format: 2,
        implementation: implementation(),
        artifact: artifact.into(),
        case: ChildCase::Issue(case),
    })?;
    ensure!(
        matches!(decode_replay(&serde_json::to_vec(&value)?, artifact)?, ChildCase::Issue(found) if found == case),
        "valid crash replay refused"
    );
    value["artifact"] = json!("foreign");
    assert!(decode_replay(&serde_json::to_vec(&value)?, artifact).is_err());
    value["artifact"] = json!(artifact);
    value["implementation"] = json!(Digest::new(b"different implementation"));
    assert!(decode_replay(&serde_json::to_vec(&value)?, artifact).is_err());
    value["implementation"] = json!(implementation());
    value["private_rows"] = json!([]);
    assert!(decode_replay(&serde_json::to_vec(&value)?, artifact).is_err());
    assert!(decode_replay(&[b' '; 4097], artifact).is_err());
    Ok(())
}

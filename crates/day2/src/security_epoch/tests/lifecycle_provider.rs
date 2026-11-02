//! Access to the existing conditional SQLite fixture, never a native adapter.
use super::*;

pub(in crate::security_epoch) fn open(path: &Path) -> Provider {
    Provider::open(path)
}

pub(in crate::security_epoch) fn transaction_closed(provider: &Provider) -> bool {
    provider.db.is_autocommit()
}

/// Independent historical DATA, not a replacement writer/continuation owner.
/// The refused writer port is untouched; this connection cannot create or
/// mutate even the fixture schema, and a missing file refuses.
pub(in crate::security_epoch) fn observe_read_only(
    path: &Path,
    selected: &EpochStore,
    request: &Request,
) -> Result<Snapshot> {
    let mut reader = Provider {
        db: Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?,
        fault: Fault::None,
        tick: Duration::from_secs(100),
        samples: VecDeque::new(),
        read_override: None,
        calls: Vec::new(),
        refused: false,
    };
    Ok(observe_selected(&mut reader, selected, request)?.into_data())
}

pub(in crate::security_epoch) fn observe_selected(
    provider: &mut Provider,
    selected: &EpochStore,
    request: &Request,
) -> Result<firestore::EpochObservation> {
    let active = match request {
        Request::CompleteInitialFirstActivation { operation, .. } => Some(operation),
        _ => None,
    };
    firestore::read(
        provider,
        &Names::new(selected, request.bootstrap(), active)?,
    )
}

pub(in crate::security_epoch) fn snapshot(provider: &Provider) -> Value {
    let mut statement = provider
        .db
        .prepare("SELECT name,fields,version FROM documents ORDER BY name")
        .unwrap();
    let documents = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })
        .unwrap()
        .map(|row| {
            let (name, fields, version) = row.unwrap();
            json!({"name":name,"fields":serde_json::from_str::<Value>(&fields).unwrap(),"version":version})
        })
        .collect::<Vec<_>>();
    json!({"documents":documents,"sends":provider.sends(),"calls":provider.calls})
}

/// External fixture corruption/restoration, never an admitted writer action.
/// Each edit has its own real SQLite transaction and changes neither send log.
pub(in crate::security_epoch) fn replace_document(
    provider: &mut Provider,
    name: &str,
    document: Option<&Value>,
) -> Result<()> {
    let transaction = provider.db.transaction()?;
    if let Some(document) = document {
        transaction.execute(
            "INSERT INTO documents(name,fields,version) VALUES(?1,?2,?3) ON CONFLICT(name) DO UPDATE SET fields=excluded.fields,version=excluded.version",
            params![name, serde_json::to_string(&document["fields"])?, document["version"].as_i64().context("fixture version")?],
        )?;
    } else {
        transaction.execute("DELETE FROM documents WHERE name=?1", [name])?;
    }
    transaction.commit()?;
    Ok(())
}

pub(in crate::security_epoch) fn lose_before(provider: &mut Provider, enabled: bool) {
    provider.fault = if enabled {
        Fault::LoseBefore
    } else {
        Fault::None
    };
}

pub(in crate::security_epoch) fn reopen(provider: &mut Provider, path: &Path) {
    let mut replacement = Provider::open(path);
    replacement.calls = std::mem::take(&mut provider.calls);
    replacement.tick = provider.tick;
    replacement.samples = std::mem::take(&mut provider.samples);
    replacement.fault = provider.fault;
    *provider = replacement;
}

pub(in crate::security_epoch) fn rewrite_selected_root(
    provider: &mut Provider,
    selected: &EpochStore,
    request: &Request,
) {
    let name = Names::new(selected, request.bootstrap(), None)
        .unwrap()
        .root;
    provider
        .db
        .execute(
            "UPDATE documents SET version=version+1 WHERE name=?1",
            [name],
        )
        .unwrap();
}

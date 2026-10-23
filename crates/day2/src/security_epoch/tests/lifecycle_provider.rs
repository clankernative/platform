//! Access to the existing conditional SQLite fixture, never a native adapter.
use super::*;

pub(in crate::security_epoch) fn open(path: &Path) -> Provider {
    Provider::open(path)
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

pub(in crate::security_epoch) fn rewrite_root(provider: &mut Provider, request: &Request) {
    let name = Names::new(&selection(), request.bootstrap(), None)
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

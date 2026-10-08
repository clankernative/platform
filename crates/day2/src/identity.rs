//! Public TypeIDs, binary UUID storage, and permanent per-app model identities.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
pub const REGISTRY_FILE: &str = "model-identities.json";

pub fn valid_prefix(prefix: &str) -> bool {
    (3..=63).contains(&prefix.len())
        && prefix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_lowercase)
        && prefix.as_bytes().last().is_some_and(u8::is_ascii_lowercase)
        && prefix.bytes().all(|b| b.is_ascii_lowercase())
}

pub fn encode(bytes: [u8; 16]) -> String {
    let mut value = u128::from_be_bytes(bytes);
    let mut encoded = [b'0'; 26];
    for byte in encoded.iter_mut().rev() {
        *byte = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(encoded.to_vec()).expect("ASCII alphabet")
}

pub fn decode(raw: &str) -> Result<[u8; 16]> {
    ensure!(
        raw.len() == 26 && raw.as_bytes()[0] <= b'7',
        "invalid_uuid_encoding"
    );
    let mut value = 0_u128;
    for byte in raw.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .context("invalid_uuid_encoding")?;
        value = (value << 5) | digit as u128;
    }
    let bytes = value.to_be_bytes();
    ensure!(
        bytes[6] >> 4 == 7 && bytes[8] >> 6 == 2,
        "invalid_uuid_version"
    );
    Ok(bytes)
}

pub fn parse(raw: &str) -> Result<(&str, [u8; 16])> {
    let (prefix, suffix) = raw.rsplit_once('_').context("invalid_reference")?;
    ensure!(valid_prefix(prefix), "invalid_id_prefix");
    Ok((prefix, decode(suffix)?))
}

pub fn valid_for(raw: &str, prefix: &str) -> bool {
    parse(raw).is_ok_and(|(actual, _)| actual == prefix)
}

pub fn parse_public_or_legacy(raw: &str) -> Result<Id> {
    if let Ok(value) = raw.parse::<i64>() {
        ensure!(value > 0 && value.to_string() == raw, "invalid_reference");
        return Ok(Id::Legacy(value));
    }
    let id = Id::from_text(raw)?;
    ensure!(id.valid(), "invalid_reference");
    Ok(id)
}

/// Replay-stable UUIDv7. The host persists a fresh random seed at admission.
pub fn generate(seed: &[u8; 32], millis: u64, model: &str, ordinal: u64) -> Result<[u8; 16]> {
    ensure!(millis < (1 << 48), "invalid_uuid_clock");
    let hash = Sha256::digest(serde_json::to_vec(&(
        "day2.uuid7.v1",
        seed,
        model,
        ordinal,
    ))?);
    let mut bytes: [u8; 16] = hash[..16].try_into()?;
    bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    bytes[6] = (bytes[6] & 15) | 0x70;
    bytes[8] = (bytes[8] & 63) | 0x80;
    Ok(bytes)
}

pub fn example(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        encode(generate(&[0; 32], 1_700_000_000_000, prefix, 0).expect("example clock"))
    )
}

pub fn json_schema(prefix: &str) -> Value {
    json!({"type":"string", "title":format!("{prefix} ID"),
        "pattern":format!("^{prefix}_[0-7][0-9a-hjkmnp-tv-z]{{9}}[ef][0-9a-hjkmnp-tv-z]{{2}}[89abrstv][0-9a-hjkmnp-tv-z]{{12}}$"),
        "minLength":prefix.len()+27,"maxLength":prefix.len()+27,
        "x-day2-id-prefix":prefix,"x-day2-id-format":"typeid-uuidv7",
        "description":format!("Stable {prefix}_ identifier. Its suffix encodes a UUIDv7."),
        "examples":[example(prefix)]})
}

/// Legacy numeric wire values remain readable for old artifacts and audit replay.
/// Text is inline so identities retain value semantics throughout transaction plans.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Id {
    Legacy(i64),
    Text { bytes: [u8; 90], len: u8 },
}

impl Default for Id {
    fn default() -> Self {
        Self::Text {
            bytes: [0; 90],
            len: 0,
        }
    }
}

impl Id {
    pub fn from_text(raw: &str) -> Result<Self> {
        ensure!(raw.len() <= 90 && raw.is_ascii(), "invalid_reference");
        if !raw.is_empty() {
            parse(raw)?;
        }
        let mut bytes = [0; 90];
        bytes[..raw.len()].copy_from_slice(raw.as_bytes());
        Ok(Self::Text {
            bytes,
            len: raw.len() as u8,
        })
    }
    pub fn from_uuid(prefix: &str, bytes: [u8; 16]) -> Result<Self> {
        Self::from_text(&format!("{prefix}_{}", encode(bytes)))
    }
    pub fn valid(self) -> bool {
        match self {
            Self::Legacy(value) => value > 0,
            Self::Text { len, .. } => len > 0,
        }
    }
    pub fn empty(self) -> bool {
        self == Self::default() || self == Self::Legacy(0)
    }
    pub fn bytes_for(self, prefix: &str) -> Result<[u8; 16]> {
        let raw = self.to_string();
        let (actual, bytes) = parse(&raw)?;
        ensure!(actual == prefix, "wrong_id_prefix");
        Ok(bytes)
    }
    pub fn sql(self, identity: Option<&ModelIdentity>) -> Result<rusqlite::types::Value> {
        match identity {
            Some(identity) => Ok(rusqlite::types::Value::Blob(
                self.bytes_for(&identity.prefix)?.to_vec(),
            )),
            None => match self {
                Self::Legacy(value) if value >= 0 => Ok(rusqlite::types::Value::Integer(value)),
                _ => bail!("legacy_integer_id_required"),
            },
        }
    }
}

impl From<i64> for Id {
    fn from(value: i64) -> Self {
        Self::Legacy(value)
    }
}
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy(value) => write!(f, "{value}"),
            Self::Text { bytes, len } => f.write_str(
                std::str::from_utf8(&bytes[..usize::from(*len)]).map_err(|_| fmt::Error)?,
            ),
        }
    }
}
impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Legacy(value) => serializer.serialize_i64(*value),
            _ => serializer.serialize_str(&self.to_string()),
        }
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        if let Some(number) = value.as_i64() {
            return Ok(Self::Legacy(number));
        }
        Self::from_text(
            value
                .as_str()
                .ok_or_else(|| serde::de::Error::custom("invalid_reference"))?,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    pub key: String,
    pub prefix: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub identity: ModelIdentity,
    pub table: String,
    pub roc_type: String,
    pub retired: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub format: u32,
    pub models: Vec<Registration>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            format: 1,
            models: vec![],
        }
    }
}

impl Registry {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 1 && self.models.len() <= 4096,
            "invalid_model_registry"
        );
        let (mut prefixes, mut keys, mut tables) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for model in &self.models {
            crate::schema::identifier(&model.table)?;
            crate::schema::roc_type_name(&model.roc_type)?;
            ensure!(
                valid_prefix(&model.identity.prefix) && prefixes.insert(&model.identity.prefix),
                "duplicate_or_invalid_id_prefix"
            );
            ensure!(
                model.identity.key.len() == 32
                    && model
                        .identity
                        .key
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    && keys.insert(&model.identity.key),
                "duplicate_or_invalid_model_identity"
            );
            ensure!(
                model.retired || tables.insert(&model.table),
                "duplicate_model_registration"
            );
        }
        Ok(())
    }

    pub fn synchronize(
        &mut self,
        models: &BTreeMap<String, crate::schema::Record>,
        entropy: &dyn crate::host_inputs::Entropy,
    ) -> Result<()> {
        let mut next = self.clone();
        next.synchronize_in(models, entropy)?;
        *self = next;
        Ok(())
    }

    fn synchronize_in(
        &mut self,
        models: &BTreeMap<String, crate::schema::Record>,
        entropy: &dyn crate::host_inputs::Entropy,
    ) -> Result<()> {
        self.validate()?;
        for registered in &mut self.models {
            if !registered.retired && !models.contains_key(&registered.table) {
                registered.retired = true;
            }
        }
        for (table, record) in models {
            let roc_type = record.roc_type.as_ref().context("nominal_model_required")?;
            if let Some(existing) = self.models.iter().find(|m| !m.retired && &m.table == table) {
                ensure!(
                    &existing.roc_type == roc_type,
                    "model_type_rename_requires_registry_rename"
                );
                continue;
            }
            let stem: String = table.chars().filter(char::is_ascii_lowercase).collect();
            let stem = if stem.len() < 3 {
                format!("{stem}id")
            } else {
                stem
            };
            let mut prefix = None;
            for length in 3..=stem.len() {
                let candidate = &stem[..length];
                if self.models.iter().all(|m| m.identity.prefix != candidate) {
                    prefix = Some(candidate.to_string());
                    break;
                }
            }
            let prefix = match prefix {
                Some(prefix) => prefix,
                None => {
                    let mut candidate = format!("{stem}id");
                    while self.models.iter().any(|m| m.identity.prefix == candidate) {
                        candidate.push('x');
                    }
                    ensure!(valid_prefix(&candidate), "id_prefix_namespace_exhausted");
                    candidate
                }
            };
            let mut key = [0_u8; 16];
            entropy.fill(&mut key).context("model identity entropy")?;
            self.models.push(Registration {
                identity: ModelIdentity {
                    key: key.iter().map(|b| format!("{b:02x}")).collect(),
                    prefix,
                },
                table: table.clone(),
                roc_type: roc_type.clone(),
                retired: false,
            });
        }
        self.validate()
    }

    pub fn register_model(
        &mut self,
        table: &str,
        roc_type: &str,
        entropy: &dyn crate::host_inputs::Entropy,
    ) -> Result<()> {
        crate::schema::identifier(table)?;
        crate::schema::roc_type_name(roc_type)?;
        ensure!(
            !self
                .models
                .iter()
                .any(|model| !model.retired && model.table == table),
            "model_already_registered"
        );
        let mut models: BTreeMap<_, _> = self
            .models
            .iter()
            .filter(|model| !model.retired)
            .map(|model| {
                (
                    model.table.clone(),
                    crate::schema::Record {
                        roc_type: Some(model.roc_type.clone()),
                        identity: None,
                        fields: BTreeMap::new(),
                    },
                )
            })
            .collect();
        models.insert(
            table.into(),
            crate::schema::Record {
                roc_type: Some(roc_type.into()),
                identity: None,
                fields: BTreeMap::new(),
            },
        );
        self.synchronize(&models, entropy)
    }

    pub fn identity(&self, table: &str, roc_type: &str) -> Result<&ModelIdentity> {
        self.models
            .iter()
            .find(|m| !m.retired && m.table == table && m.roc_type == roc_type)
            .map(|m| &m.identity)
            .context("model_identity_not_registered")
    }

    pub fn check_successor(&self, next: &Self) -> Result<()> {
        next.validate()?;
        for old in &self.models {
            let new = next
                .models
                .iter()
                .find(|m| m.identity.key == old.identity.key)
                .context("model_identity_history_removed")?;
            ensure!(
                new.identity.prefix == old.identity.prefix && (!old.retired || new.retired),
                "model_prefix_is_immutable"
            );
        }
        Ok(())
    }

    pub fn rename(&mut self, old: &str, table: &str, roc_type: &str) -> Result<()> {
        let mut next = self.clone();
        let model = next
            .models
            .iter_mut()
            .find(|m| !m.retired && m.table == old)
            .context("unknown_model")?;
        model.table = table.into();
        model.roc_type = roc_type.into();
        next.validate()?;
        *self = next;
        Ok(())
    }
}

/// Explicit authoring may persist assignments; every ordinary build passes readonly.
pub fn prepare(app: &Path, schema: &crate::schema::Schema, readonly: bool) -> Result<Registry> {
    let path = app.join(REGISTRY_FILE);
    // Lock and read the same inode. The final comparison also rejects a writer
    // that opened an older inode before an atomic replacement.
    let mut registry_lock = None;
    let original = if path.exists() {
        ensure!(
            fs::symlink_metadata(&path)?.file_type().is_file(),
            "model_registry_must_be_regular_file"
        );
        let mut file = fs::File::open(&path)?;
        file.try_lock()
            .context("concurrent_model_registry_change")?;
        let mut bytes = Vec::new();
        use std::io::Read;
        file.by_ref().take(128_001).read_to_end(&mut bytes)?;
        registry_lock = Some(file);
        ensure!(bytes.len() <= 128_000, "model_registry_budget");
        Some(bytes)
    } else {
        None
    };
    let mut registry: Registry = original
        .as_deref()
        .map(serde_json::from_slice)
        .transpose()?
        .unwrap_or_default();
    let previous = registry.clone();
    registry.synchronize(&schema.models, &crate::host_inputs::SecureEntropy)?;
    if original.is_none() || previous != registry {
        ensure!(!readonly, "commit_model_identities_before_build");
        let bytes = serde_json::to_vec_pretty(&registry)?;
        let mut temporary = tempfile::NamedTempFile::new_in(app)?;
        use std::io::Write;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        if let Some(original) = original {
            ensure!(
                fs::read(&path)? == original,
                "concurrent_model_registry_change"
            );
            temporary.persist(&path)?;
        } else {
            temporary.persist_noclobber(&path)?;
        }
    }
    drop(registry_lock);
    Ok(registry)
}

pub fn rename_registered(app: &Path, old: &str, table: &str, roc_type: &str) -> Result<()> {
    edit_registry(app, false, |registry| registry.rename(old, table, roc_type))
}

/// Explicit authoring, separate from ordinary read-only builds. History survives
/// retirement and future reuse of a table name receives a new identity.
pub fn register_model(
    app: &Path,
    table: &str,
    roc_type: &str,
    entropy: &dyn crate::host_inputs::Entropy,
) -> Result<()> {
    edit_registry(app, true, |registry| {
        registry.register_model(table, roc_type, entropy)
    })
}

pub fn retire_model(app: &Path, table: &str) -> Result<()> {
    edit_registry(app, false, |registry| {
        registry
            .models
            .iter_mut()
            .find(|model| !model.retired && model.table == table)
            .context("unknown_model")?
            .retired = true;
        registry.validate()
    })
}

fn edit_registry(
    app: &Path,
    create: bool,
    edit: impl FnOnce(&mut Registry) -> Result<()>,
) -> Result<()> {
    use std::io::{Read, Write};
    let path = app.join(REGISTRY_FILE);
    if create && !path.exists() {
        let mut registry = Registry::default();
        edit(&mut registry)?;
        registry.validate()?;
        let mut temporary = tempfile::NamedTempFile::new_in(app)?;
        temporary.write_all(&serde_json::to_vec_pretty(&registry)?)?;
        temporary.as_file().sync_all()?;
        temporary.persist_noclobber(&path)?;
        return Ok(());
    }
    ensure!(
        fs::symlink_metadata(&path)?.file_type().is_file(),
        "model_registry_must_be_regular_file"
    );
    let mut file = fs::File::open(&path)?;
    file.try_lock()
        .context("concurrent_model_registry_change")?;
    let mut original = Vec::new();
    Read::by_ref(&mut file)
        .take(128_001)
        .read_to_end(&mut original)?;
    ensure!(original.len() <= 128_000, "model_registry_budget");
    let mut registry: Registry = serde_json::from_slice(&original)?;
    registry.validate()?;
    edit(&mut registry)?;
    registry.validate()?;
    let mut temporary = tempfile::NamedTempFile::new_in(app)?;
    temporary.write_all(&serde_json::to_vec_pretty(&registry)?)?;
    temporary.as_file().sync_all()?;
    ensure!(
        fs::read(&path)? == original,
        "concurrent_model_registry_change"
    );
    temporary.persist(&path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Record, Schema};

    #[test]
    fn explicit_authoring_preserves_retired_identity_history() -> Result<()> {
        let directory = tempfile::tempdir()?;
        register_model(
            directory.path(),
            "reports",
            "Models.Report",
            &crate::host_inputs::SecureEntropy,
        )?;
        let read = || -> Result<Registry> {
            Ok(serde_json::from_slice(&fs::read(
                directory.path().join(REGISTRY_FILE),
            )?)?)
        };
        let original = read()?;
        assert!(
            register_model(
                directory.path(),
                "reports",
                "Models.Report",
                &crate::host_inputs::SecureEntropy
            )
            .is_err()
        );
        rename_registered(directory.path(), "reports", "documents", "Models.Document")?;
        let renamed = read()?;
        assert_eq!(original.models[0].identity, renamed.models[0].identity);
        retire_model(directory.path(), "documents")?;
        register_model(
            directory.path(),
            "documents",
            "Models.NewDocument",
            &crate::host_inputs::SecureEntropy,
        )?;
        let next = read()?;
        assert!(next.models[0].retired);
        assert_ne!(next.models[0].identity, next.models[1].identity);
        original.check_successor(&next)?;
        Ok(())
    }

    #[test]
    fn uuid7_matches_typeid_golden_vector_and_rejects_noncanonical_values() -> Result<()> {
        let bytes = [
            0x01, 0x89, 0x0a, 0x5d, 0xac, 0x96, 0x77, 0x4b, 0xbc, 0xce, 0xb3, 0x02, 0x09, 0x9a,
            0x80, 0x57,
        ];
        let suffix = "01h455vb4pex5vsknk084sn02q";
        assert_eq!(encode(bytes), suffix);
        assert_eq!(decode(suffix)?, bytes);
        let id = Id::from_uuid("ord", bytes)?;
        assert_eq!(id.to_string(), format!("ord_{suffix}"));
        assert_eq!(id.bytes_for("ord")?, bytes);
        assert!(id.bytes_for("cus").is_err());
        for invalid in [
            "",
            "ord_1",
            "ORD_01h455vb4pex5vsknk084sn02q",
            "ord_81h455vb4pex5vsknk084sn02q",
            "ord_01H455vb4pex5vsknk084sn02q",
            "ord_01h455vb4pex5vsknk084sn02i",
            "ord_00000000000000000000000000",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
        for version in [0, 4, 6, 8] {
            let mut wrong = bytes;
            wrong[6] = (wrong[6] & 15) | (version << 4);
            assert!(decode(&encode(wrong)).is_err());
        }
        let mut wrong = bytes;
        wrong[8] &= 63;
        assert!(decode(&encode(wrong)).is_err());
        assert_eq!(serde_json::to_value(id)?, json!(format!("ord_{suffix}")));
        assert_eq!(serde_json::from_value::<Id>(json!(id.to_string()))?, id);
        Ok(())
    }

    #[test]
    fn uuid_generation_is_stable_for_replay_and_distinct_across_creates() -> Result<()> {
        let value = generate(&[1; 32], 1234567890, "orders", 0)?;
        assert_eq!(generate(&[1; 32], 1234567890, "orders", 0)?, value);
        for other in [
            generate(&[2; 32], 1234567890, "orders", 0)?,
            generate(&[1; 32], 1234567890, "customers", 0)?,
            generate(&[1; 32], 1234567890, "orders", 1)?,
        ] {
            assert_ne!(value, other);
        }
        assert_eq!(&value[..6], &1234567890_u64.to_be_bytes()[2..]);
        assert_eq!(decode(&encode(value))?, value);
        assert!(generate(&[1; 32], 1 << 48, "orders", 0).is_err());
        Ok(())
    }

    fn models(names: &[(&str, &str)]) -> BTreeMap<String, Record> {
        names
            .iter()
            .map(|(table, name)| {
                (
                    table.to_string(),
                    Record {
                        roc_type: Some(format!("Models.{name}")),
                        identity: None,
                        fields: BTreeMap::new(),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn prefixes_survive_growth_rename_and_retirement() -> Result<()> {
        let entropy = crate::host_inputs::simulation::SeededEntropy::new(130);
        let mut registry = Registry::default();
        registry.synchronize(
            &models(&[("customers", "Customer"), ("ordinals", "Ordinal")]),
            &entropy,
        )?;
        assert_eq!(
            registry.identity("customers", "Models.Customer")?.prefix,
            "cus"
        );
        let ordinal = registry.identity("ordinals", "Models.Ordinal")?.clone();
        assert_eq!(ordinal.prefix, "ord");
        let initial = registry.clone();
        registry.synchronize(
            &models(&[
                ("customers", "Customer"),
                ("ordinals", "Ordinal"),
                ("orders", "Order"),
            ]),
            &entropy,
        )?;
        assert_eq!(registry.identity("orders", "Models.Order")?.prefix, "orde");
        assert_eq!(registry.identity("ordinals", "Models.Ordinal")?, &ordinal);
        initial.check_successor(&registry)?;
        registry.rename("ordinals", "positions", "Models.Position")?;
        assert_eq!(registry.identity("positions", "Models.Position")?, &ordinal);
        initial.check_successor(&registry)?;
        registry.synchronize(
            &models(&[("customers", "Customer"), ("orders", "Order")]),
            &entropy,
        )?;
        assert!(
            registry
                .models
                .iter()
                .any(|m| m.identity == ordinal && m.retired)
        );
        let retired = registry.clone();
        registry.synchronize(
            &models(&[
                ("customers", "Customer"),
                ("orders", "Order"),
                ("ordinals", "Ordinal"),
            ]),
            &entropy,
        )?;
        assert_eq!(
            registry.identity("ordinals", "Models.Ordinal")?.prefix,
            "ordi"
        );
        retired.check_successor(&registry)?;
        let mut invalid = registry.clone();
        invalid.models.retain(|m| m.identity != ordinal);
        assert!(retired.check_successor(&invalid).is_err());
        let mut invalid = registry.clone();
        invalid.models[0].identity.prefix = "changed".into();
        assert!(registry.check_successor(&invalid).is_err());
        let mut invalid = registry.clone();
        invalid.models[0].identity.prefix = invalid.models[1].identity.prefix.clone();
        assert!(invalid.validate().is_err());
        Ok(())
    }

    #[test]
    fn explicit_entropy_replays_authoring_and_failure_does_not_publish_partial_state() -> Result<()>
    {
        struct Unavailable;
        impl crate::host_inputs::Entropy for Unavailable {
            fn fill(&self, _: &mut [u8]) -> Result<()> {
                bail!("scripted entropy failure")
            }
        }
        let author = || -> Result<Registry> {
            let entropy = crate::host_inputs::simulation::SeededEntropy::new(130);
            let mut registry = Registry::default();
            registry.register_model("orders", "Models.Order", &entropy)?;
            registry.register_model("ordinals", "Models.Ordinal", &entropy)?;
            assert!(
                registry
                    .register_model("orders", "Models.Order", &entropy)
                    .is_err()
            );
            registry.rename("orders", "purchases", "Models.Purchase")?;
            registry.synchronize(&models(&[("ordinals", "Ordinal")]), &entropy)?;
            registry.register_model("orders", "Models.NewOrder", &entropy)?;
            Ok(registry)
        };
        let registry = author()?;
        assert_eq!(registry, author()?);
        // Independent namespace/history expectations, not another call to the decision logic.
        assert_eq!(
            registry
                .models
                .iter()
                .map(|m| (m.table.as_str(), m.identity.prefix.as_str(), m.retired))
                .collect::<Vec<_>>(),
            vec![
                ("purchases", "ord", true),
                ("ordinals", "ordi", false),
                ("orders", "orde", false)
            ]
        );
        let mut unchanged = registry.clone();
        assert!(
            unchanged
                .synchronize(&models(&[("customers", "Customer")]), &Unavailable)
                .is_err()
        );
        assert_eq!(unchanged, registry);
        Ok(())
    }

    #[test]
    fn registry_is_persisted_and_isolated_builds_cannot_assign_ids() -> Result<()> {
        let app = tempfile::tempdir()?;
        let schema = Schema {
            domains: BTreeMap::new(),
            models: models(&[("orders", "Order")]),
            inputs: BTreeMap::new(),
            foreign_keys: vec![],
            rollups: Vec::new(),
            indexes: vec![],
        };
        assert!(prepare(app.path(), &schema, true).is_err());
        let registry = prepare(app.path(), &schema, false)?;
        let bytes = fs::read(app.path().join(REGISTRY_FILE))?;
        assert_eq!(prepare(app.path(), &schema, true)?, registry);
        assert_eq!(fs::read(app.path().join(REGISTRY_FILE))?, bytes);
        rename_registered(app.path(), "orders", "purchases", "Models.Purchase")?;
        let renamed = Schema {
            domains: BTreeMap::new(),
            models: models(&[("purchases", "Purchase")]),
            inputs: BTreeMap::new(),
            foreign_keys: vec![],
            rollups: Vec::new(),
            indexes: vec![],
        };
        let next = prepare(app.path(), &renamed, true)?;
        assert_eq!(
            next.identity("purchases", "Models.Purchase")?,
            registry.identity("orders", "Models.Order")?
        );
        Ok(())
    }
}

//! Reviewed-instance passkey configuration DATA. Parsing, a content digest or
//! a configured principal is not current admission, authentication or approval.
use crate::{Digest, Name};
use anyhow::{Result, ensure};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
};

const MAX_KEYS: usize = 128;
const MAX_REGISTRY_BYTES: usize = 524_288;

/// Closed public COSE EC2/P-256/ES256 key. No private parameter, alternate
/// algorithm, extension, duplicate label or nonminimal CBOR encoding is accepted.
/// Coordinate shape is DATA; actual assertion signature verification is still required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicCoseKey([u8; 65]);

impl TryFrom<Vec<u8>> for PublicCoseKey {
    type Error = anyhow::Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        ensure!(
            bytes.len() == 77 && bytes[0] == 0xa5,
            "restore_passkey_cose_profile"
        );
        let mut point = [0; 65];
        point[0] = 4;
        let mut at = 1;
        let mut seen = 0u8;
        for _ in 0..5 {
            let label = *bytes
                .get(at)
                .ok_or_else(|| anyhow::anyhow!("restore_passkey_cose_profile"))?;
            at += 1;
            let (bit, value) = match label {
                1 => (1, Some(2)),
                3 => (2, Some(0x26)),
                0x20 => (4, Some(1)),
                0x21 => (8, None),
                0x22 => (16, None),
                _ => anyhow::bail!("restore_passkey_cose_profile"),
            };
            ensure!(seen & bit == 0, "restore_passkey_cose_duplicate");
            seen |= bit;
            if let Some(value) = value {
                ensure!(
                    bytes.get(at) == Some(&value),
                    "restore_passkey_cose_profile"
                );
                at += 1;
            } else {
                ensure!(
                    bytes.get(at..at + 2) == Some(&[0x58, 0x20][..]),
                    "restore_passkey_cose_coordinate"
                );
                at += 2;
                let coordinate = bytes
                    .get(at..at + 32)
                    .ok_or_else(|| anyhow::anyhow!("restore_passkey_cose_coordinate"))?;
                let start = if label == 0x21 { 1 } else { 33 };
                point[start..start + 32].copy_from_slice(coordinate);
                at += 32;
            }
        }
        ensure!(
            seen == 31 && at == bytes.len(),
            "restore_passkey_cose_profile"
        );
        Ok(Self(point))
    }
}

impl PublicCoseKey {
    pub fn uncompressed_p256(&self) -> &[u8; 65] {
        &self.0
    }

    pub fn cose_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20];
        bytes.extend_from_slice(&self.0[1..33]);
        bytes.extend_from_slice(&[0x22, 0x58, 0x20]);
        bytes.extend_from_slice(&self.0[33..]);
        bytes
    }
}

impl Serialize for PublicCoseKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.cose_bytes().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for PublicCoseKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = bounded_bytes::<D, 77>(deserializer)?;
        Self::try_from(bytes).map_err(|_| de::Error::custom("restore_passkey_cose_profile"))
    }
}

fn bounded_bytes<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    struct Bytes<const N: usize>;
    impl<'de, const N: usize> Visitor<'de> for Bytes<N> {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bounded public credential bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > N) {
                return Err(de::Error::custom("restore_passkey_byte_bound"));
            }
            let mut bytes = Vec::new();
            while let Some(byte) = seq.next_element::<u8>()? {
                if bytes.len() == N {
                    return Err(de::Error::custom("restore_passkey_byte_bound"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer
        .deserialize_seq(Bytes::<N>)
        .map_err(|_| de::Error::custom("restore_passkey_byte_encoding"))
}
fn credential_bytes<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    bounded_bytes::<D, 1023>(d)
}
fn handle_bytes<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    bounded_bytes::<D, 64>(d)
}

fn bounded_text<'de, D: Deserializer<'de>, const N: usize>(
    d: D,
) -> std::result::Result<String, D::Error> {
    struct Text<const N: usize>;
    impl<'de, const N: usize> Visitor<'de> for Text<N> {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bounded public passkey metadata")
        }
        fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<String, E> {
            if s.len() > N {
                return Err(E::custom("restore_passkey_text_bound"));
            }
            Ok(s.to_owned())
        }
        fn visit_string<E: de::Error>(self, s: String) -> std::result::Result<String, E> {
            if s.len() > N {
                return Err(E::custom("restore_passkey_text_bound"));
            }
            Ok(s)
        }
    }
    d.deserialize_str(Text::<N>)
        .map_err(|_| de::Error::custom("restore_passkey_text_encoding"))
}
fn email_text<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    bounded_text::<D, 254>(d)
}
fn subject_text<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    bounded_text::<D, 1024>(d)
}
fn rp_text<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    bounded_text::<D, 253>(d)
}
fn origin_text<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    bounded_text::<D, 2048>(d)
}

/// Require JSON object shape while keeping the derived field/duplicate checks.
/// Parser diagnostics stay closed even for an unknown field containing private input.
struct Object<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct AsObject<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for AsObject<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("restore passkey configuration object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer
            .deserialize_map(AsObject(PhantomData))
            .map_err(|_| de::Error::custom("restore_passkey_config_object"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Object<KeyWire>")]
pub struct AdminPasskey {
    pub email: String,
    pub subject: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub cose_key: PublicCoseKey,
    pub backup_eligible: bool,
    pub rp_id: String,
    pub origin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyWire {
    #[serde(deserialize_with = "email_text")]
    email: String,
    #[serde(deserialize_with = "subject_text")]
    subject: String,
    #[serde(deserialize_with = "credential_bytes")]
    credential_id: Vec<u8>,
    #[serde(deserialize_with = "handle_bytes")]
    user_handle: Vec<u8>,
    cose_key: PublicCoseKey,
    backup_eligible: bool,
    #[serde(deserialize_with = "rp_text")]
    rp_id: String,
    #[serde(deserialize_with = "origin_text")]
    origin: String,
}
impl TryFrom<Object<KeyWire>> for AdminPasskey {
    type Error = anyhow::Error;
    fn try_from(Object(row): Object<KeyWire>) -> Result<Self> {
        let key = Self {
            email: row.email,
            subject: row.subject,
            credential_id: row.credential_id,
            user_handle: row.user_handle,
            cose_key: row.cose_key,
            backup_eligible: row.backup_eligible,
            rp_id: row.rp_id,
            origin: row.origin,
        };
        key.validate()?;
        Ok(key)
    }
}

fn dns_host(host: &str) -> bool {
    if host.len() > 253 {
        return false;
    }
    let labels = host.split('.').collect::<Vec<_>>();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && s.as_bytes()[0].is_ascii_alphanumeric()
                && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
        })
        && labels
            .last()
            .is_some_and(|s| s.bytes().any(|b| b.is_ascii_lowercase()))
}
impl AdminPasskey {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.email.len() <= 254 && self.subject.len() <= 1024 && self.origin.len() <= 2048,
            "restore_passkey_text_bound"
        );
        let parts = self.email.split('@').collect::<Vec<_>>();
        ensure!(
            !self.email.is_empty()
                && self.email.is_ascii()
                && self.email.len() <= 254
                && self.email.to_ascii_lowercase() == self.email
                && !self
                    .email
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
                && parts.len() == 2
                && parts.iter().all(|s| !s.is_empty()),
            "restore_passkey_admin_email"
        );
        ensure!(
            !self.subject.is_empty()
                && self.subject.len() <= 1024
                && !self.subject.chars().any(char::is_control),
            "restore_passkey_admin_subject"
        );
        ensure!(
            (1..=1023).contains(&self.credential_id.len())
                && (1..=64).contains(&self.user_handle.len()),
            "restore_passkey_credential_bytes"
        );
        ensure!(dns_host(&self.rp_id), "restore_passkey_rp_id");
        let base = format!("https://{}", self.rp_id);
        let remainder = self
            .origin
            .strip_prefix(&base)
            .ok_or_else(|| anyhow::anyhow!("restore_passkey_origin"))?;
        ensure!(
            remainder.is_empty()
                || remainder
                    .strip_prefix(':')
                    .is_some_and(|port| !port.is_empty()
                        && !port.starts_with('0')
                        && port.bytes().all(|b| b.is_ascii_digit())
                        && port.parse::<u16>().is_ok_and(|n| n != 0 && n != 443)),
            "restore_passkey_origin"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Object<RegistryWire>")]
pub struct Registry {
    pub version: u32,
    pub keys: BTreeMap<Name, AdminPasskey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryWire {
    version: u32,
    #[serde(deserialize_with = "unique_keys")]
    keys: BTreeMap<Name, AdminPasskey>,
}
fn unique_keys<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<Name, AdminPasskey>, D::Error> {
    struct Keys;
    impl<'de> Visitor<'de> for Keys {
        type Value = BTreeMap<Name, AdminPasskey>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bounded unique passkey labels")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            if map.size_hint().is_some_and(|n| n > MAX_KEYS) {
                return Err(de::Error::custom("restore_passkey_count"));
            }
            let mut keys = BTreeMap::new();
            while let Some(label) = map.next_key::<Name>()? {
                if keys.len() == MAX_KEYS || keys.contains_key(&label) {
                    return Err(de::Error::custom("restore_passkey_duplicate_or_count"));
                }
                keys.insert(label, map.next_value()?);
            }
            Ok(keys)
        }
    }
    d.deserialize_map(Keys)
}
impl TryFrom<Object<RegistryWire>> for Registry {
    type Error = anyhow::Error;
    fn try_from(Object(row): Object<RegistryWire>) -> Result<Self> {
        let registry = Self {
            version: row.version,
            keys: row.keys,
        };
        registry.validate()?;
        Ok(registry)
    }
}
impl Registry {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && !self.keys.is_empty() && self.keys.len() <= MAX_KEYS,
            "restore_passkey_registry_version_or_count"
        );
        let mut ids = BTreeSet::new();
        let mut emails = BTreeMap::new();
        let mut subjects = BTreeMap::new();
        for key in self.keys.values() {
            key.validate()?;
            ensure!(
                ids.insert(&key.credential_id),
                "restore_passkey_duplicate_credential"
            );
            ensure!(
                emails
                    .insert(&key.email, &key.subject)
                    .is_none_or(|old| old == &key.subject)
                    && subjects
                        .insert(&key.subject, &key.email)
                        .is_none_or(|old| old == &key.email),
                "restore_passkey_ambiguous_admin"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_REGISTRY_BYTES,
            "restore_passkey_registry_byte_bound"
        );
        Ok(())
    }

    /// Content identity only, not an authenticated/nonreusable config revision.
    /// Returning to the same bytes has the same digest; the real source must
    /// bind an actual admitted revision and keep counter/tombstone history.
    pub fn content_digest(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(&("day2-restore-passkey-registry-v1", self))
    }
}

#[cfg(test)]
mod tests;

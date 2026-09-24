//! Bounded JSON transport decoding with duplicate decoded keys rejected at every
//! level. Serde structs alone do not reject duplicate keys inside maps.
use anyhow::{Result, ensure};
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::fmt;

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Unique;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(value.into()))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(value.into()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(value.into()))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::from(value)))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(value.into()))
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    values.insert(key, map.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    decode_with_limits(bytes, 1_048_576, 20_000)
}

/// Decode persisted verification evidence, not application or worker transport.
/// Evidence has a larger fixed budget but identical key and depth validation.
pub fn decode_evidence<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    decode_with_limits(bytes, 4 * 1_048_576, 250_000)
}

fn decode_with_limits<T: DeserializeOwned>(
    bytes: &[u8],
    byte_limit: usize,
    node_limit: usize,
) -> Result<T> {
    ensure!(bytes.len() <= byte_limit, "JSON byte budget");
    let value: Unique = serde_json::from_slice(bytes)?;
    fn bounded(value: &Value, depth: usize, count: &mut usize, node_limit: usize) -> Result<()> {
        *count += 1;
        ensure!(depth <= 32 && *count <= node_limit, "JSON structure budget");
        match value {
            Value::Array(values) => {
                for value in values {
                    bounded(value, depth + 1, count, node_limit)?;
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    bounded(value, depth + 1, count, node_limit)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    bounded(&value.0, 0, &mut 0, node_limit)?;
    Ok(serde_json::from_value(value.0)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn escaped_duplicate_keys_and_deep_maps_are_rejected() {
        for decode in [
            super::decode::<serde_json::Value>,
            super::decode_evidence::<serde_json::Value>,
        ] {
            assert!(decode(br#"{"apps":{"reports":1,"\u0072eports":2}}"#).is_err());
            assert!(decode(format!("{}0{}", "[".repeat(32), "]".repeat(32)).as_bytes()).is_ok());
            assert!(decode(format!("{}0{}", "[".repeat(33), "]".repeat(33)).as_bytes()).is_err());
        }
    }

    #[test]
    fn evidence_byte_budget_does_not_relax_transport() {
        let bytes = serde_json::to_vec(&"x".repeat(1_048_576)).unwrap();
        assert_eq!(
            super::decode::<String>(&bytes).unwrap_err().to_string(),
            "JSON byte budget"
        );
        assert_eq!(
            super::decode_evidence::<String>(&bytes).unwrap().len(),
            1_048_576
        );
    }

    #[test]
    fn evidence_node_budget_does_not_relax_transport() {
        let bytes = serde_json::to_vec(&vec![0_u8; 20_000]).unwrap();
        assert_eq!(
            super::decode::<Vec<u8>>(&bytes).unwrap_err().to_string(),
            "JSON structure budget"
        );
        assert_eq!(
            super::decode_evidence::<Vec<u8>>(&bytes).unwrap().len(),
            20_000
        );
    }

    #[test]
    fn evidence_rejects_bytes_above_its_fixed_limit() {
        let bytes = serde_json::to_vec(&"x".repeat(4 * 1_048_576 - 2)).unwrap();
        assert_eq!(bytes.len(), 4 * 1_048_576);
        assert!(super::decode_evidence::<String>(&bytes).is_ok());
        let oversized = serde_json::to_vec(&"x".repeat(4 * 1_048_576 - 1)).unwrap();
        assert_eq!(
            super::decode_evidence::<String>(&oversized)
                .unwrap_err()
                .to_string(),
            "JSON byte budget"
        );
    }

    #[test]
    fn evidence_rejects_nodes_above_its_fixed_limit() {
        let bytes = serde_json::to_vec(&vec![0_u8; 249_999]).unwrap();
        assert_eq!(
            super::decode_evidence::<Vec<u8>>(&bytes).unwrap().len(),
            249_999
        );
        let oversized = serde_json::to_vec(&vec![0_u8; 250_000]).unwrap();
        assert_eq!(
            super::decode_evidence::<Vec<u8>>(&oversized)
                .unwrap_err()
                .to_string(),
            "JSON structure budget"
        );
    }
}

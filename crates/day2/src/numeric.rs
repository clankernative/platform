//! Numeric domains shared by codec admission, runtime validation, and API schemas.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Unsigned {
    U8,
    U16,
    U32,
    U64,
}

impl Unsigned {
    pub fn from_roc(name: &str) -> Option<Self> {
        match name {
            "U8" => Some(Self::U8),
            "U16" => Some(Self::U16),
            "U32" => Some(Self::U32),
            "U64" => Some(Self::U64),
            _ => None,
        }
    }

    pub fn roc_type(self) -> &'static str {
        match self {
            Self::U8 => "U8",
            Self::U16 => "U16",
            Self::U32 => "U32",
            Self::U64 => "U64",
        }
    }

    pub fn maximum(self) -> u64 {
        match self {
            Self::U8 => u8::MAX.into(),
            Self::U16 => u16::MAX.into(),
            Self::U32 => u32::MAX.into(),
            Self::U64 => u64::MAX,
        }
    }

    pub fn valid(self, value: &Value) -> bool {
        value
            .as_u64()
            .is_some_and(|number| number <= self.maximum())
    }

    pub fn schema(self) -> Value {
        json!({"type":"integer", "format":self.roc_type().replacen('U', "uint", 1),
            "minimum":0,"maximum":self.maximum(),"examples":[0]})
    }
}

pub fn valid_row_version(value: &Value) -> bool {
    value.as_i64().is_some_and(|number| number >= 1)
}

pub fn row_version_schema() -> Value {
    json!({"type":"integer","format":"uint64","minimum":1,"maximum":i64::MAX,
        "title":"RowVersion","description":"Positive 64-bit row revision, starting at 1 and bounded by SQLite's revision range.","examples":[1]})
}

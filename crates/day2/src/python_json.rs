//! Python's `json.dumps(value, sort_keys=True, ...)`, byte for byte, for the
//! documents an instance's earlier Python tooling wrote and its records still
//! hold: SDK release manifests, deployment candidate records, reuse proofs and
//! the digests computed over them.
//!
//! Keys are sorted by code point at every level (UTF-8 byte order is code point
//! order). Strings are written as `ensure_ascii` writes them. Integers are
//! decimal; a float is refused, because Python's `repr` is not reproduced here
//! and no record this encodes holds one.
use anyhow::{Result, bail};
use serde_json::Value;

/// The separators and indentation of one `json.dumps` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// The defaults: `", "` between items and `": "` after a key.
    Default,
    /// `separators=(",", ":")`.
    Compact,
    /// `indent=2`: `","` between items, `": "` after a key, each item on its
    /// own line.
    Indented,
}

/// `json.dumps(value, sort_keys=True)` in `layout`, without a final newline.
pub fn dumps(value: &Value, layout: Layout) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write(value, layout, 0, &mut out)?;
    Ok(out)
}

fn write(value: &Value, layout: Layout, depth: usize, out: &mut Vec<u8>) -> Result<()> {
    let (item, key) = match layout {
        Layout::Default => (&b", "[..], &b": "[..]),
        Layout::Compact => (&b","[..], &b":"[..]),
        Layout::Indented => (&b","[..], &b": "[..]),
    };
    let indent = |out: &mut Vec<u8>, depth: usize| {
        if layout == Layout::Indented {
            out.push(b'\n');
            out.extend(std::iter::repeat_n(b' ', depth * 2));
        }
    };
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) if number.is_i64() || number.is_u64() => {
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::Number(_) => bail!("a float has no Python-compatible encoding here"),
        Value::String(text) => string(text, out),
        Value::Array(items) if items.is_empty() => out.extend_from_slice(b"[]"),
        Value::Array(items) => {
            out.push(b'[');
            for (index, element) in items.iter().enumerate() {
                if index > 0 {
                    out.extend_from_slice(item);
                }
                indent(out, depth + 1);
                write(element, layout, depth + 1, out)?;
            }
            indent(out, depth);
            out.push(b']');
        }
        Value::Object(fields) if fields.is_empty() => out.extend_from_slice(b"{}"),
        Value::Object(fields) => {
            let mut sorted: Vec<_> = fields.iter().collect();
            sorted.sort_by(|left, right| left.0.cmp(right.0));
            out.push(b'{');
            for (index, (name, element)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.extend_from_slice(item);
                }
                indent(out, depth + 1);
                string(name, out);
                out.extend_from_slice(key);
                write(element, layout, depth + 1, out)?;
            }
            indent(out, depth);
            out.push(b'}');
        }
    }
    Ok(())
}

/// A JSON string as Python's `ensure_ascii` writes it: anything outside space
/// to `~` is escaped, and code points beyond the BMP become surrogate pairs.
pub fn string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            ' '..='~' => out.push(character as u8),
            _ => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    out.extend_from_slice(format!("\\u{unit:04x}").as_bytes());
                }
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text(value: &Value, layout: Layout) -> String {
        String::from_utf8(dumps(value, layout).unwrap()).unwrap()
    }

    #[test]
    fn strings_escape_everything_outside_printable_ascii() {
        let mut out = Vec::new();
        string("a\"\\\n\u{7f}\u{e9}\u{1f600}\u{1}", &mut out);
        assert_eq!(out, br#""a\"\\\n\u007f\u00e9\ud83d\ude00\u0001""#);
    }

    #[test]
    fn each_layout_is_pythons_with_sorted_keys() {
        let value = json!({"b": [], "a": {}, "c": [1, true, null], "é": "x"});
        assert_eq!(
            text(&value, Layout::Default),
            r#"{"a": {}, "b": [], "c": [1, true, null], "\u00e9": "x"}"#
        );
        assert_eq!(
            text(&value, Layout::Compact),
            r#"{"a":{},"b":[],"c":[1,true,null],"\u00e9":"x"}"#
        );
        assert_eq!(
            text(&value, Layout::Indented),
            "{\n  \"a\": {},\n  \"b\": [],\n  \"c\": [\n    1,\n    true,\n    null\n  ],\n  \"\\u00e9\": \"x\"\n}"
        );
        // Negative and big integers, and nesting.
        assert_eq!(
            text(
                &json!({"n": [-3, 18_446_744_073_709_551_615_u64], "z": {"y": {"x": 0}}}),
                Layout::Default
            ),
            r#"{"n": [-3, 18446744073709551615], "z": {"y": {"x": 0}}}"#
        );
    }

    #[test]
    fn floats_are_refused() {
        assert!(dumps(&json!({"a": 1.5}), Layout::Default).is_err());
        assert!(dumps(&json!([0.0]), Layout::Compact).is_err());
        // serde_json reads `-0` as the float -0.0, where Python reads the integer
        // 0: refused here, a narrowing.
        let negative_zero: Value = serde_json::from_str("-0").unwrap();
        assert!(dumps(&negative_zero, Layout::Default).is_err());
    }
}

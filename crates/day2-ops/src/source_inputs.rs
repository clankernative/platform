//! An app's source inputs: the one identity the deploy side computes from a
//! forge archive (`instance_candidate::source_inputs`) and app CI computes from
//! a source tree (`ci_check::source_inputs`), as the earlier tooling's
//! `source_identity` did: `sha256` of the compact, key-sorted JSON
//! `{"files":[[name,size,hex],...],"version":1}`, the files in the order
//! Python's `sorted(Path)` gives (by path parts, each compared by code point)
//! and each name written as Python writes a JSON string with `ensure_ascii`.
use crate::instance_source::python_json_string;

/// One file below the app root: its `/`-separated name as code points (which
/// may hold the lone surrogates tarfile decodes), size and sha256 hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    pub name: Vec<u32>,
    pub size: u64,
    pub hex: String,
}

/// The digest document for these files, in any order.
pub fn document(mut files: Vec<SourceFile>) -> Vec<u8> {
    let slash = u32::from(b'/');
    files.sort_by(|a, b| {
        a.name
            .split(|code| *code == slash)
            .cmp(b.name.split(|code| *code == slash))
    });
    let mut out = b"{\"files\":[".to_vec();
    for (index, file) in files.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.push(b'[');
        python_json_string(&file.name, &mut out);
        out.extend_from_slice(format!(",{},\"{}\"]", file.size, file.hex).as_bytes());
    }
    out.extend_from_slice(b"],\"version\":1}");
    out
}

/// `sha256:<hex>` of [`document`].
pub fn digest(files: Vec<SourceFile>) -> String {
    day2::digest(&document(files))
}

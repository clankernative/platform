#![forbid(unsafe_code)]
use std::{collections::BTreeMap, env, fs::OpenOptions, io::Write, process::Command};

fn observe(arguments: &[std::ffi::OsString]) -> std::io::Result<()> {
    let mut fields = BTreeMap::new();
    let mut features = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let value = arguments[index].to_str().unwrap_or("");
        if ["--crate-name", "--crate-type", "--target"].contains(&value) {
            if let Some(next) = arguments.get(index + 1).and_then(|v| v.to_str()) {
                fields.insert(
                    value.trim_start_matches('-').replace('-', "_"),
                    next.to_owned(),
                );
            }
        }
        let codegen = value
            .strip_prefix("-C")
            .filter(|v| !v.is_empty())
            .or_else(|| {
                (value == "-C")
                    .then(|| arguments.get(index + 1).and_then(|v| v.to_str()))
                    .flatten()
            });
        if let Some((name, value)) = codegen.and_then(|v| v.split_once('=')) {
            if [
                "opt-level",
                "codegen-units",
                "panic",
                "debuginfo",
                "debug-assertions",
                "overflow-checks",
                "extra-filename",
            ]
            .contains(&name)
            {
                fields.insert(name.replace('-', "_"), value.to_owned());
            }
        }
        if value == "--cfg" {
            if let Some(feature) = arguments
                .get(index + 1)
                .and_then(|v| v.to_str())
                .and_then(|v| v.strip_prefix("feature=\""))
                .and_then(|v| v.strip_suffix('"'))
            {
                features.push(feature.to_owned());
            }
        }
        index += 1;
    }
    // Cargo's compiler-version/target probes are forwarded but are not units.
    if !fields.contains_key("crate_name") {
        return Ok(());
    }
    let bounded = |value: &str| {
        value.len() <= 256
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.,:+-=~".contains(&b))
    };
    if !fields.values().all(|v| bounded(v))
        || features.len() > 512
        || !features.iter().all(|v| bounded(v))
    {
        return Err(std::io::Error::other("unsupported observation field"));
    }
    features.sort();
    let mut record = String::from("{\"test\":");
    record.push_str(if arguments.iter().any(|v| v == "--test") {
        "true"
    } else {
        "false"
    });
    for (name, value) in fields {
        record.push_str(&format!(",{name:?}:{value:?}"));
    }
    record.push_str(&format!(",\"features\":{features:?}}}\n"));
    let path = env::var_os("DAY2_MEASURE_COMPILER_FIELDS")
        .ok_or_else(|| std::io::Error::other("observation output missing"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    file.lock()?;
    if file.metadata()?.len().saturating_add(record.len() as u64) > 16 * 1024 * 1024 {
        return Err(std::io::Error::other("observation budget"));
    }
    file.write_all(record.as_bytes())
}

fn main() {
    let mut arguments = env::args_os().skip(1);
    let Some(compiler) = arguments.next() else {
        std::process::exit(2)
    };
    let arguments = arguments.collect::<Vec<_>>();
    if observe(&arguments).is_err() {
        eprintln!("DAY2_COMPILER_FIELDS_OBSERVATION_FAILED");
    }
    // Advisory collection never changes the actual selected compiler arguments,
    // inherited streams or environment. This is a temporary measurement tool,
    // not a platform build entry point or a claim about the original kill actor.
    let status = Command::new(compiler).args(arguments).status();
    let code = match status {
        Ok(status) => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                status.code().unwrap_or(128 + status.signal().unwrap_or(1))
            }
            #[cfg(not(unix))]
            {
                status.code().unwrap_or(1)
            }
        }
        Err(_) => {
            eprintln!("DAY2_SELECTED_COMPILER_SPAWN_FAILED");
            1
        }
    };
    std::process::exit(code);
}

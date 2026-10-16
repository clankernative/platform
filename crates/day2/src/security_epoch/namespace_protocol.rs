//! Strict kernel observation DATA. These parsers never produce runtime, Pod,
//! continuous-clock, role, image or bootstrap authority.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TaskFacts {
    pub process: u32,
    pub thread: u32,
    pub start_ticks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Offset {
    pub seconds: i64,
    pub nanoseconds: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TimeOffsets {
    pub monotonic: Offset,
    pub boottime: Offset,
}

fn decimal<T: std::str::FromStr + ToString>(word: &str) -> Result<T> {
    let value = word
        .parse::<T>()
        .map_err(|_| anyhow::anyhow!("epoch_native_proc_number"))?;
    ensure!(value.to_string() == word, "epoch_native_proc_number");
    Ok(value)
}

pub(super) fn task(stat: &[u8], status: &[u8]) -> Result<TaskFacts> {
    ensure!(
        stat.len() <= 16_384 && status.len() <= 65_536,
        "epoch_native_proc_bound"
    );
    let stat = std::str::from_utf8(stat)?;
    ensure!(
        stat.ends_with('\n') && !stat.contains('\0'),
        "epoch_native_proc_stat_shape"
    );
    let (tid, tail) = stat
        .split_once(" (")
        .context("epoch_native_proc_stat_shape")?;
    let close = tail.rfind(") ").context("epoch_native_proc_stat_shape")?;
    let values = tail[close + 2..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    // comm may contain spaces or ')' and cannot be split as a normal column.
    // Supported Linux stat fields 3..52 are complete. Field22 starttime is
    // index19 after the closing comm; a prefix or unknown shape is refused.
    ensure!(
        values.len() == 50
            && values[0].len() == 1
            && matches!(values[0], "R" | "S" | "D" | "T" | "t" | "I"),
        "epoch_native_proc_stat_shape"
    );
    for value in &values[1..] {
        decimal::<i128>(value)?;
    }
    let thread: u32 = decimal(tid)?;
    let start_ticks: u64 = decimal(values[19])?;
    ensure!(thread > 0 && start_ticks > 0, "epoch_native_proc_identity");
    let status = std::str::from_utf8(status)?;
    ensure!(
        status.ends_with('\n') && !status.contains('\0'),
        "epoch_native_proc_status_shape"
    );
    let mut fields = BTreeMap::new();
    for line in status.lines() {
        let (key, value) = line
            .split_once(':')
            .context("epoch_native_proc_status_shape")?;
        ensure!(
            !key.is_empty() && !fields.contains_key(key),
            "epoch_native_proc_duplicate_field"
        );
        fields.insert(key, value.trim());
    }
    let process: u32 = decimal(
        fields
            .get("Tgid")
            .context("epoch_native_proc_tgid_missing")?,
    )?;
    let status_thread: u32 = decimal(fields.get("Pid").context("epoch_native_proc_pid_missing")?)?;
    ensure!(
        process > 0 && status_thread == thread,
        "epoch_native_proc_identity"
    );
    Ok(TaskFacts {
        process,
        thread,
        start_ticks,
    })
}

pub(super) fn offsets(bytes: &[u8]) -> Result<TimeOffsets> {
    ensure!(bytes.len() <= 1024, "epoch_native_timens_bound");
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        text.ends_with('\n') && !text.contains('\0'),
        "epoch_native_timens_shape"
    );
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let values = line.split_ascii_whitespace().collect::<Vec<_>>();
        ensure!(
            values.len() == 3 && matches!(values[0], "monotonic" | "boottime"),
            "epoch_native_timens_shape"
        );
        let seconds: i64 = decimal(values[1])?;
        let nanoseconds: u32 = decimal(values[2])?;
        ensure!(
            nanoseconds < 1_000_000_000 && !fields.contains_key(values[0]),
            "epoch_native_timens_shape"
        );
        fields.insert(
            values[0],
            Offset {
                seconds,
                nanoseconds,
            },
        );
    }
    ensure!(fields.len() == 2, "epoch_native_timens_shape");
    Ok(TimeOffsets {
        monotonic: fields.remove("monotonic").unwrap(),
        boottime: fields.remove("boottime").unwrap(),
    })
}

pub(super) fn require_zero(offsets: &TimeOffsets) -> Result<()> {
    ensure!(
        offsets.monotonic.seconds == 0
            && offsets.monotonic.nanoseconds == 0
            && offsets.boottime.seconds == 0
            && offsets.boottime.nanoseconds == 0,
        "epoch_native_timens_offset_refused"
    );
    // Zero offsets are a supported observation, NOT evidence that this is the
    // node initial namespace. That still needs the actual trusted runtime join.
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Mapping {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub device_major: u64,
    pub device_minor: u64,
    pub inode: u64,
    pub path: Option<String>,
}

fn hexadecimal(word: &str) -> Result<u64> {
    ensure!(
        !word.is_empty()
            && word.len() <= 16
            && word
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "epoch_native_maps_number"
    );
    u64::from_str_radix(word, 16).map_err(|_| anyhow::anyhow!("epoch_native_maps_number"))
}

pub(super) fn mappings(bytes: &[u8]) -> Result<Vec<Mapping>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 1_048_576,
        "epoch_native_maps_bound"
    );
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        text.ends_with('\n') && !text.contains('\0'),
        "epoch_native_maps_shape"
    );
    let mut result = Vec::new();
    let mut previous_end = 0;
    for line in text.lines() {
        ensure!(result.len() < 4096, "epoch_native_maps_count");
        let mut rest = line;
        let mut columns = Vec::new();
        for _ in 0..5 {
            rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
            let end = rest
                .find(|c: char| c.is_ascii_whitespace())
                .unwrap_or(rest.len());
            ensure!(end > 0, "epoch_native_maps_shape");
            columns.push(&rest[..end]);
            rest = &rest[end..];
        }
        let (start, end) = columns[0]
            .split_once('-')
            .context("epoch_native_maps_shape")?;
        let start = hexadecimal(start)?;
        let end = hexadecimal(end)?;
        ensure!(
            start < end && start >= previous_end,
            "epoch_native_maps_order"
        );
        previous_end = end;
        let permissions = columns[1].as_bytes();
        ensure!(
            permissions.len() == 4
                && matches!(permissions[0], b'r' | b'-')
                && matches!(permissions[1], b'w' | b'-')
                && matches!(permissions[2], b'x' | b'-')
                && matches!(permissions[3], b'p' | b's'),
            "epoch_native_maps_permissions"
        );
        let offset = hexadecimal(columns[2])?;
        let (major, minor) = columns[3]
            .split_once(':')
            .context("epoch_native_maps_shape")?;
        let device_major = hexadecimal(major)?;
        let device_minor = hexadecimal(minor)?;
        let inode = decimal(columns[4])?;
        let path = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        ensure!(path.len() <= 4096, "epoch_native_maps_path_bound");
        result.push(Mapping {
            start,
            end,
            permissions: columns[1].to_owned(),
            offset,
            device_major,
            device_minor,
            inode,
            path: if path.is_empty() {
                None
            } else {
                Some(path.to_owned())
            },
        });
    }
    ensure!(!result.is_empty(), "epoch_native_maps_shape");
    Ok(result)
}

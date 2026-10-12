//! Candidate-only fixed stderr protocol. No scratch bytes leave this module.
use std::io::{self, Read};
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU32, Ordering};

const NO_ERRNO: i64 = i64::MIN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(super) struct Snapshot {
    pub first_request_only: bool,
    pub prefix: u8,
    pub bytes: u32,
    pub partial: u8,
    pub invalid: u8,
    pub overflow: u8,
    pub truncated: u8,
    pub eof: u8,
    pub read_failed: u8,
    pub read_errno: Option<i32>,
    pub entered: u8,
    pub unwound: u8,
}

impl std::fmt::Display for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "p:{} b:{} tail:{} bad:{} ov:{} trunc:{} eof:{} read:{} errno:{:?} enter:{} unwind:{}",
            self.prefix,
            self.bytes,
            self.partial,
            self.invalid,
            self.overflow,
            self.truncated,
            self.eof,
            self.read_failed,
            self.read_errno,
            self.entered,
            self.unwound
        )
    }
}

pub(super) struct Progress {
    prefix: AtomicU8,
    bytes: AtomicU32,
    partial: AtomicU8,
    invalid: AtomicU8,
    overflow: AtomicU8,
    truncated: AtomicU8,
    eof: AtomicU8,
    read_failed: AtomicU8,
    read_errno: AtomicI64,
    entered: AtomicU8,
    unwound: AtomicU8,
}

impl Progress {
    pub(super) fn new() -> Self {
        Self {
            prefix: AtomicU8::new(0),
            bytes: AtomicU32::new(0),
            partial: AtomicU8::new(0),
            invalid: AtomicU8::new(0),
            overflow: AtomicU8::new(0),
            truncated: AtomicU8::new(0),
            eof: AtomicU8::new(0),
            read_failed: AtomicU8::new(0),
            read_errno: AtomicI64::new(NO_ERRNO),
            entered: AtomicU8::new(0),
            unwound: AtomicU8::new(0),
        }
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        let errno = self.read_errno.load(Ordering::Acquire);
        Snapshot {
            first_request_only: true,
            prefix: self.prefix.load(Ordering::Acquire),
            bytes: self.bytes.load(Ordering::Acquire),
            partial: self.partial.load(Ordering::Acquire),
            invalid: self.invalid.load(Ordering::Acquire),
            overflow: self.overflow.load(Ordering::Acquire),
            truncated: self.truncated.load(Ordering::Acquire),
            eof: self.eof.load(Ordering::Acquire),
            read_failed: self.read_failed.load(Ordering::Acquire),
            read_errno: if errno == NO_ERRNO {
                None
            } else {
                i32::try_from(errno).ok()
            },
            entered: self.entered.load(Ordering::Acquire),
            unwound: self.unwound.load(Ordering::Acquire),
        }
    }

    pub(super) fn entered(&self) {
        self.entered.store(1, Ordering::Release);
    }

    pub(super) fn unwound(&self) {
        self.unwound.store(1, Ordering::Release);
    }

    fn publish(&self, state: &Parser) {
        self.prefix.store(state.prefix, Ordering::Release);
        self.bytes.store(state.bytes, Ordering::Release);
        self.partial.store(state.partial, Ordering::Release);
        self.invalid
            .store(u8::from(state.invalid), Ordering::Release);
        self.overflow
            .store(u8::from(state.overflow), Ordering::Release);
        self.truncated
            .store(u8::from(state.truncated), Ordering::Release);
        self.eof.store(u8::from(state.eof), Ordering::Release);
    }

    fn read_fault(&self, error: &io::Error) {
        self.read_errno.store(
            error.raw_os_error().map_or(NO_ERRNO, i64::from),
            Ordering::Release,
        );
        self.read_failed.store(1, Ordering::Release);
    }
}

struct Parser {
    record: [u8; 8],
    prefix: u8,
    bytes: u32,
    partial: u8,
    invalid: bool,
    overflow: bool,
    truncated: bool,
    eof: bool,
}

impl Parser {
    fn new() -> Self {
        Self {
            record: [0; 8],
            prefix: 0,
            bytes: 0,
            partial: 0,
            invalid: false,
            overflow: false,
            truncated: false,
            eof: false,
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.bytes = self.bytes.saturating_add(1);
            if self.bytes > 56 {
                self.overflow = true;
                self.invalid = true;
            }
            if !self.invalid {
                self.record[usize::from(self.partial)] = *byte;
            }
            self.partial += 1;
            if self.partial == 8 {
                self.partial = 0;
                if !self.invalid {
                    let expected = [
                        b'D',
                        b'2',
                        b'S',
                        b'T',
                        b'1',
                        b':',
                        b'1' + self.prefix,
                        b'\n',
                    ];
                    if self.record == expected && self.prefix < 7 {
                        self.prefix += 1;
                    } else {
                        self.invalid = true;
                    }
                }
            }
        }
    }

    fn finish(&mut self) {
        self.truncated = self.partial != 0;
        self.eof = true;
    }
}

/// The caller retains the descriptor outside this borrow through child exit.
/// Invalid data is discarded, not an excuse to close a live child's pipe.
pub(super) fn drain(reader: &mut impl Read, progress: &Progress) {
    let mut state = Parser::new();
    let mut scratch = [0_u8; 256];
    loop {
        match reader.read(&mut scratch) {
            Ok(0) => {
                state.finish();
                progress.publish(&state);
                return;
            }
            Ok(count) => {
                state.feed(&scratch[..count]);
                progress.publish(&state);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                progress.read_fault(&error);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Progress, drain};
    use std::io::{self, Cursor, Read};

    const WIRE: &[u8] = b"D2ST1:1\nD2ST1:2\nD2ST1:3\nD2ST1:4\nD2ST1:5\nD2ST1:6\nD2ST1:7\n";

    struct Chunks<'a> {
        remaining: &'a [u8],
        width: usize,
    }

    impl Read for Chunks<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let count = self.width.min(output.len()).min(self.remaining.len());
            output[..count].copy_from_slice(&self.remaining[..count]);
            self.remaining = &self.remaining[count..];
            Ok(count)
        }
    }

    #[test]
    fn exact_literal_protocol_accepts_every_fragmentation_width() {
        assert_eq!(WIRE.len(), 56);
        for width in 1..=57 {
            let progress = Progress::new();
            drain(
                &mut Chunks {
                    remaining: WIRE,
                    width,
                },
                &progress,
            );
            let final_state = progress.snapshot();
            assert_eq!(final_state.prefix, 7);
            assert_eq!(final_state.bytes, 56);
            assert_eq!(final_state.partial, 0);
            assert_eq!(final_state.invalid, 0);
            assert_eq!(final_state.truncated, 0);
            assert_eq!(final_state.eof, 1);
            assert_eq!(final_state.read_failed, 0);
        }
    }

    #[test]
    fn each_complete_ordered_prefix_is_incomplete_not_malformed() {
        for count in 0..=7 {
            let progress = Progress::new();
            drain(&mut Cursor::new(&WIRE[..count * 8]), &progress);
            let state = progress.snapshot();
            assert_eq!(usize::from(state.prefix), count);
            assert_eq!(usize::try_from(state.bytes).unwrap(), count * 8);
            assert_eq!((state.invalid, state.truncated, state.eof), (0, 0, 1));
        }
    }

    #[test]
    fn every_partial_record_tail_is_truncated_at_eof() {
        for length in 1..56 {
            if length % 8 == 0 {
                continue;
            }
            let progress = Progress::new();
            drain(&mut Cursor::new(&WIRE[..length]), &progress);
            let state = progress.snapshot();
            assert_eq!(usize::from(state.prefix), length / 8);
            assert_eq!(usize::from(state.partial), length % 8);
            assert_eq!((state.truncated, state.eof), (1, 1));
        }
    }

    #[test]
    fn unknown_duplicate_and_out_of_order_streams_never_resynchronize() {
        for wire in [
            b"D2ST1:1\nD2ST1:1\nD2ST1:2\n".as_slice(),
            b"D2ST1:1\nD2ST1:3\nD2ST1:2\n",
            b"D2ST1:0\nD2ST1:1\n",
            b"PRIVATE_TOKEN_PATH\nD2ST1:1\n",
        ] {
            let progress = Progress::new();
            let mut input = Cursor::new(wire);
            drain(&mut input, &progress);
            let state = progress.snapshot();
            assert_eq!(state.invalid, 1);
            assert!(state.prefix <= 1);
            assert_eq!(input.position(), u64::try_from(wire.len()).unwrap());
            assert_eq!(state.eof, 1);
            assert!(!serde_json::to_string(&state).unwrap().contains("PRIVATE"));
        }
    }

    #[test]
    fn complete_seven_then_garbage_is_invalid_and_still_fully_drained() {
        let wire = [WIRE, &[b'x'; 1025]].concat();
        let mut input = Cursor::new(&wire);
        let progress = Progress::new();
        drain(&mut input, &progress);
        let state = progress.snapshot();
        assert_eq!(state.prefix, 7);
        assert_eq!((state.invalid, state.overflow, state.eof), (1, 1, 1));
        assert_eq!(input.position(), u64::try_from(wire.len()).unwrap());
    }

    struct ReadFault {
        input: Cursor<&'static [u8]>,
        interrupted: bool,
    }

    impl Read for ReadFault {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.interrupted {
                self.interrupted = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.input.position() < u64::try_from(self.input.get_ref().len()).unwrap() {
                self.input.read(output)
            } else {
                Err(io::Error::from_raw_os_error(5))
            }
        }
    }

    #[test]
    fn interrupted_read_retries_but_real_read_fault_does_not_claim_eof() {
        let progress = Progress::new();
        let mut input = ReadFault {
            input: Cursor::new(WIRE),
            interrupted: true,
        };
        drain(&mut input, &progress);
        let state = progress.snapshot();
        assert_eq!(state.prefix, 7);
        assert_eq!(state.bytes, 56);
        assert_eq!(state.eof, 0);
        assert_eq!(state.read_failed, 1);
        assert_eq!(state.read_errno, Some(5));
    }

    #[test]
    fn late_invalid_or_truncated_tail_does_not_rewrite_earlier_snapshot() {
        for tail in [b"D2ST1:2\n".as_slice(), b"D2ST1:2", b"PRIVATE!"] {
            let progress = Progress::new();
            let mut parser = super::Parser::new();
            parser.feed(&WIRE[..16]);
            progress.publish(&parser);
            let before = progress.snapshot();
            parser.feed(tail);
            parser.finish();
            progress.publish(&parser);
            let after = progress.snapshot();
            assert_eq!(
                (before.prefix, before.invalid, before.truncated, before.eof),
                (2, 0, 0, 0)
            );
            assert!(after.invalid != 0 || after.truncated != 0);
            assert_eq!(after.eof, 1);
        }
    }

    #[test]
    fn late_valid_markers_belong_only_to_the_final_snapshot() {
        let progress = Progress::new();
        let mut parser = super::Parser::new();
        parser.feed(&WIRE[..8]);
        progress.publish(&parser);
        let before = progress.snapshot();
        parser.feed(&WIRE[8..]);
        parser.finish();
        progress.publish(&parser);
        let after = progress.snapshot();
        assert_eq!((before.prefix, before.eof), (1, 0));
        assert_eq!((after.prefix, after.eof, after.invalid), (7, 1, 0));
    }
}

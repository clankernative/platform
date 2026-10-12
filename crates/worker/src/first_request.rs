//! Temporary private native diagnostics, never an application effect or result.
use std::io::Write;

#[derive(Clone, Copy)]
pub(crate) enum Milestone {
    Run,
    Locked,
    Frame,
    Argument,
    Returned,
    Answer,
    Flushed,
}

impl Milestone {
    fn record(self) -> (u8, &'static [u8; 8]) {
        match self {
            Self::Run => (1, b"D2ST1:1\n"),
            Self::Locked => (2, b"D2ST1:2\n"),
            Self::Frame => (3, b"D2ST1:3\n"),
            Self::Argument => (4, b"D2ST1:4\n"),
            Self::Returned => (5, b"D2ST1:5\n"),
            Self::Answer => (6, b"D2ST1:6\n"),
            Self::Flushed => (7, b"D2ST1:7\n"),
        }
    }
}

pub(crate) struct FirstRequest {
    emitted: u8,
    finished: bool,
}

impl FirstRequest {
    pub(crate) fn new() -> Self {
        Self {
            emitted: 0,
            finished: false,
        }
    }

    pub(crate) fn emit(&mut self, point: Milestone, output: &mut impl Write) {
        let (ordinal, bytes) = point.record();
        if self.finished || ordinal != self.emitted + 1 {
            return;
        }
        // Once attempted, never replay a marker, including after a partial write.
        self.emitted = ordinal;
        let _ = output.write_all(bytes);
    }

    pub(crate) fn finish(&mut self) {
        self.finished = true;
    }
}

#[cfg(test)]
mod tests {
    use super::{FirstRequest, Milestone};
    use std::io::{self, Write};

    fn points() -> [Milestone; 7] {
        [
            Milestone::Run,
            Milestone::Locked,
            Milestone::Frame,
            Milestone::Argument,
            Milestone::Returned,
            Milestone::Answer,
            Milestone::Flushed,
        ]
    }

    #[test]
    fn literal_first_request_producer_emits_exactly_fifty_six_bytes_once() {
        let mut producer = FirstRequest::new();
        let mut output = Vec::new();
        for point in points() {
            producer.emit(point, &mut output);
        }
        assert_eq!(
            output,
            b"D2ST1:1\nD2ST1:2\nD2ST1:3\nD2ST1:4\nD2ST1:5\nD2ST1:6\nD2ST1:7\n"
        );
        assert_eq!(output.len(), 56);
        producer.finish();
        for point in points() {
            producer.emit(point, &mut output);
        }
        assert_eq!(output.len(), 56);
    }

    #[test]
    fn producer_cannot_duplicate_or_skip_to_a_later_record() {
        let mut producer = FirstRequest::new();
        let mut output = Vec::new();
        producer.emit(Milestone::Argument, &mut output);
        producer.emit(Milestone::Run, &mut output);
        producer.emit(Milestone::Run, &mut output);
        producer.emit(Milestone::Returned, &mut output);
        assert_eq!(output, b"D2ST1:1\n");
        producer.emit(Milestone::Locked, &mut output);
        assert_eq!(output, b"D2ST1:1\nD2ST1:2\n");
    }

    struct Fault {
        calls: usize,
    }

    impl Write for Fault {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            Err(io::Error::other("PRIVATE_MARKER_WRITE_ERROR"))
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("marker producer must not flush or replace the original result")
        }
    }

    #[test]
    fn producer_write_fault_is_best_effort_without_a_second_attempt() {
        let mut producer = FirstRequest::new();
        let mut output = Fault { calls: 0 };
        producer.emit(Milestone::Run, &mut output);
        producer.emit(Milestone::Run, &mut output);
        assert_eq!(output.calls, 1);
        producer.emit(Milestone::Locked, &mut output);
        assert_eq!(output.calls, 2);
        producer.finish();
        for point in points() {
            producer.emit(point, &mut output);
        }
        assert_eq!(output.calls, 2);
    }
}

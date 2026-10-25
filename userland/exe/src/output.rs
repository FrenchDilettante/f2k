//! The standard streams' writer: text formatted into UTF-16 units, buffered, handed to its sink a
//! buffer at a time (one WriteConsoleW or WriteFile per buffer, not one per piece the formatter
//! produces), a surrogate pair never split between two.

use core::fmt;

/// The units a writer buffers before handing them on.
pub const BUFFER: usize = 256;

/// A failed call's Win32 error code (its last error).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub u32);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error {}", self.0)
    }
}

/// Where a writer's units go: a console, or a file or pipe (see `sys::Stream`).
pub trait Sink {
    /// Write `units` (at most [`BUFFER`], whole characters) in full.
    fn write(&mut self, units: &[u16]) -> Result<(), Error>;
}

/// A buffered writer of text to a sink. Formatting into it (`core::fmt::Write`) fills its buffer;
/// [`Writer::flush`] hands the rest on and reports the first failure. After a failure the writer
/// drops what it is given. Dropping it flushes it, its failure unreported.
pub struct Writer<S: Sink> {
    sink: S,
    buffer: [u16; BUFFER],
    length: usize,
    failure: Option<Error>,
}

impl<S: Sink> Writer<S> {
    /// A writer to `sink`, its buffer empty.
    pub fn new(sink: S) -> Self {
        Writer {
            sink,
            buffer: [0; BUFFER],
            length: 0,
            failure: None,
        }
    }

    /// Write `args` and flush: the first failure, if any.
    pub fn print(&mut self, args: fmt::Arguments<'_>) -> Result<(), Error> {
        // A failure is kept and reported by the flush.
        let _ = fmt::Write::write_fmt(self, args);
        self.flush()
    }

    /// Hand the buffered units to the sink: the first failure since the writer was made, if any.
    pub fn flush(&mut self) -> Result<(), Error> {
        if self.length > 0 && self.failure.is_none() {
            self.failure = self.sink.write(&self.buffer[..self.length]).err();
        }
        self.length = 0;
        self.failure.map_or(Ok(()), Err)
    }
}

impl<S: Sink> fmt::Write for Writer<S> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for character in text.chars() {
            if self.length + character.len_utf16() > BUFFER {
                let _ = self.flush();
            }
            if self.failure.is_some() {
                return Err(fmt::Error);
            }
            let length = character
                .encode_utf16(&mut self.buffer[self.length..])
                .len();
            self.length += length;
        }
        Ok(())
    }
}

impl<S: Sink> Drop for Writer<S> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write;

    use super::*;

    /// A sink that keeps each write's units, failing from its `fail_at`th write on.
    #[derive(Default)]
    struct Recorder {
        writes: Vec<Vec<u16>>,
        fail_at: Option<usize>,
    }

    impl Sink for &mut Recorder {
        fn write(&mut self, units: &[u16]) -> Result<(), Error> {
            if self.fail_at.is_some_and(|at| self.writes.len() >= at) {
                return Err(Error(232));
            }
            self.writes.push(units.to_vec());
            Ok(())
        }
    }

    #[test]
    fn pieces_go_out_together() {
        let mut recorder = Recorder::default();
        let mut writer = Writer::new(&mut recorder);
        write!(writer, "C:\\{}{}", "WINNT", "\r\n").unwrap();
        assert_eq!(writer.flush(), Ok(()));
        drop(writer);
        let expected: Vec<u16> = "C:\\WINNT\r\n".encode_utf16().collect();
        assert_eq!(recorder.writes, vec![expected]);
    }

    #[test]
    fn nothing_buffered_writes_nothing() {
        let mut recorder = Recorder::default();
        assert_eq!(Writer::new(&mut recorder).flush(), Ok(()));
        assert!(recorder.writes.is_empty());
    }

    #[test]
    fn a_full_buffer_never_splits_a_surrogate_pair() {
        let mut recorder = Recorder::default();
        let text: String = "a".repeat(BUFFER - 1) + "\u{1F600}b";
        Writer::new(&mut recorder)
            .print(format_args!("{text}"))
            .unwrap();
        assert_eq!(recorder.writes.len(), 2);
        assert_eq!(recorder.writes[0].len(), BUFFER - 1);
        assert_eq!(
            recorder.writes[1],
            "\u{1F600}b".encode_utf16().collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_first_failure_is_reported_and_sticks() {
        let mut recorder = Recorder {
            fail_at: Some(1),
            ..Recorder::default()
        };
        let mut writer = Writer::new(&mut recorder);
        let text = "x".repeat(BUFFER + 1);
        assert_eq!(writer.print(format_args!("{text}")), Err(Error(232)));
        assert!(write!(writer, "more").is_err());
        assert_eq!(writer.flush(), Err(Error(232)));
        drop(writer);
        assert_eq!(recorder.writes.len(), 1);
    }

    #[test]
    fn an_error_shows_its_code() {
        assert_eq!(Error(3).to_string(), "error 3");
    }
}

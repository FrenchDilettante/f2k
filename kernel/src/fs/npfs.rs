//! The named-pipe file system's rules (NPFS, `\Device\NamedPipe`): a pipe instance's two ends, its
//! two data queues and their quotas, and what each read, write, peek, flush and close does to them,
//! as Windows 2000's driver answers them. Byte mode only: the read mode and the type are always
//! FILE_PIPE_BYTE_STREAM_*, so a read takes whatever bytes are queued, across the writes that
//! queued them.
//!
//! The module decides, the services wait and copy. A pipe's state sits under the services'
//! lock, and every call here runs under it: none waits, none touches user memory. A call that
//! cannot finish registers its caller as the queue's waiter and says so ([`ReadOutcome::Wait`],
//! [`WriteStep::Wait`], [`FlushOutcome::Wait`]); a call that lets a waiter go on names it in its
//! [`Wake`]; the service waits and wakes outside the lock, and a woken caller calls again. User
//! bytes pass through the service's own kernel buffer a chunk at a time, copied at passive level
//! with the lock dropped: a read moves queued bytes into the buffer it is given, and a write is fed
//! its caller's bytes chunk by chunk as the queue has room for them ([`WriteStep::Feed`]). Windows
//! queues the read and write IRPs themselves on the data queue and completes them from whichever
//! call satisfies them; here the waiter's own thread finishes its call once woken.
//!
//! One call at a time through an end. An end is one file object (a duplicated or inherited
//! handle shares it), opened for synchronous I/O, and the I/O manager serializes a synchronous file
//! object's calls behind its lock, so each queue has at most one write in progress, one read and
//! one flush waiting. A second waiter through the same end is refused ([`PipeError::Busy`]): it
//! cannot come through a synchronous file object.
//!
//! Quotas. Each queue has its quota: the create's InboundQuota for the inbound queue (the
//! client writes, the server reads) and its OutboundQuota for the outbound one; 0 asks for the
//! default, 4096 bytes. Each write queued is charged its bytes plus [`ENTRY_OVERHEAD`], the size
//! of the data entry Windows queues it in: the pipe fixture's capture fits 163 1-byte writes in
//! 4096 bytes and 2621 in 65536, 25 bytes each. A write whose charge fits the quota left completes
//! at once. One that does not is queued all the same, pending: its bytes count in what a peek
//! reports and a read takes them, and it completes once all its bytes are in the queue and the
//! charges of everything still queued, its own included, fit the quota (or everything has been
//! read), as MSDN puts it: "the write operation will be completed when a read operation makes more
//! system buffer space available for the pipe". The capture's 10000-byte write into a 4096-byte
//! pipe shows each part of the rule: it waits, PeekNamedPipe counts its 10000 bytes, a 1000-byte
//! read gets 1000 of them while it still waits, and it completes once more is read.
//!
//! Storage. No table bounds the entries: 2621 of them fit a 65536-byte quota. Each queue's
//! bytes live in a ring the service lends ([`Queue::new`], at least [`ring_size`] bytes, from
//! wherever it chooses), each write an entry there: a 4-byte header (its length), then its bytes,
//! as Windows keeps its data entries in pool memory charged to the quota. An entry's header takes
//! less room than it is charged, so the entries the quota admits always fit the ring, and the
//! ring's extra header's worth leaves room for a pending write to begin. A pending write's bytes
//! beyond the ring's room stay with its writer, which feeds them as reads free room.

pub use rtl::nt::FilePipePeekBuffer;

use crate::status::{
    NtStatus,
    STATUS_BUFFER_OVERFLOW,
    STATUS_INVALID_PARAMETER,
    STATUS_INVALID_PIPE_STATE,
    STATUS_PIPE_BROKEN,
    STATUS_PIPE_BUSY,
    STATUS_PIPE_CLOSING,
    STATUS_PIPE_LISTENING,
    STATUS_PIPE_NOT_AVAILABLE,
    STATUS_SUCCESS,
};

/// The quota a create's 0 asks for: what the capture's CreatePipe of size 0 holds, the same as
/// size 4096.
pub const DEFAULT_QUOTA: u32 = 4096;

/// What each queued write is charged beyond its bytes: the capture's 163 1-byte writes in 4096
/// bytes and 2621 in 65536 are 25 bytes each.
pub const ENTRY_OVERHEAD: u32 = 24;

/// The bytes an entry's header takes in the ring: its length, little-endian.
const HEADER: usize = 4;

/// FILE_PIPE_PEEK_BUFFER's fixed part, before the data: four ULONGs.
pub const PEEK_HEADER: u32 = 16;

/// A pipe instance's two ends. The server end is the one NtCreateNamedPipeFile makes (CreatePipe's
/// read end), the client end the one a create or open of the name connects (CreatePipe's write
/// end).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Server,
    Client,
}

impl End {
    /// The other end.
    pub fn peer(self) -> End {
        match self {
            End::Server => End::Client,
            End::Client => End::Server,
        }
    }

    /// The queue this end reads: the server the inbound one, the client the outbound one.
    pub fn reads(self) -> Direction {
        match self {
            End::Server => Direction::Inbound,
            End::Client => Direction::Outbound,
        }
    }

    /// The queue this end writes: the server the outbound one, the client the inbound one.
    pub fn writes(self) -> Direction {
        match self {
            End::Server => Direction::Outbound,
            End::Client => Direction::Inbound,
        }
    }
}

/// A pipe's two data queues, named from the server's side as Windows names them: inbound is what
/// the client writes for the server (all an anonymous pipe uses, its write end the client),
/// outbound what the server writes for the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    fn index(self) -> usize {
        match self {
            Direction::Inbound => 0,
            Direction::Outbound => 1,
        }
    }
}

/// A pipe's state as FILE_PIPE_PEEK_BUFFER's NamedPipeState reports it (FILE_PIPE_*_STATE,
/// ntifs.h), seen from one end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PipeState {
    /// The server end made, no client yet (FILE_PIPE_LISTENING_STATE).
    Listening = 2,
    /// Both ends open (FILE_PIPE_CONNECTED_STATE): what the capture's peeks report.
    Connected = 3,
    /// The other end closed (FILE_PIPE_CLOSING_STATE): what is queued can still be read.
    Closing = 4,
}

/// Why a call failed, each a status the service returns as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeError {
    /// The writing end is closed and nothing is left to read; a pending write the reading end's
    /// close ended; or a call through an end already closed.
    Broken,
    /// A write once the reading end is closed, even of zero bytes (the capture's 232).
    Closing,
    /// A read, write or flush on a server end no client has opened yet.
    Listening,
    /// A peek on a server end no client has opened yet.
    InvalidState,
    /// A client's open of an instance already connected.
    NotAvailable,
    /// A second call waiting through the same end, which a synchronous file object never makes.
    Busy,
    /// A peek's output buffer shorter than FILE_PIPE_PEEK_BUFFER's header (the capture's
    /// 0xC000000D for 8 bytes).
    InvalidParameter,
}

impl PipeError {
    /// The status the service returns.
    pub fn status(self) -> NtStatus {
        match self {
            PipeError::Broken => STATUS_PIPE_BROKEN,
            PipeError::Closing => STATUS_PIPE_CLOSING,
            PipeError::Listening => STATUS_PIPE_LISTENING,
            PipeError::InvalidState => STATUS_INVALID_PIPE_STATE,
            PipeError::NotAvailable => STATUS_PIPE_NOT_AVAILABLE,
            PipeError::Busy => STATUS_PIPE_BUSY,
            PipeError::InvalidParameter => STATUS_INVALID_PARAMETER,
        }
    }
}

/// A caller that may wait, named by the service (a thread, or its wait block): the module keeps it
/// while the caller waits and hands it back in a [`Wake`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Waiter(pub usize);

/// The waiters a call lets go on: the service wakes each once it has dropped the pipe's lock, and
/// each calls again. A waiter named here is no longer registered: its next call registers it anew
/// if it must wait again.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wake {
    waiters: [Option<Waiter>; 6],
}

impl Wake {
    /// Add `waiter`, once.
    fn add(&mut self, waiter: Waiter) {
        if self.waiters.contains(&Some(waiter)) {
            return;
        }
        let slot = self
            .waiters
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("a pipe has at most six waiters");
        *slot = Some(waiter);
    }

    /// Each waiter to wake.
    pub fn iter(&self) -> impl Iterator<Item = Waiter> + '_ {
        self.waiters.iter().flatten().copied()
    }

    /// Whether there is nobody to wake.
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }
}

/// A call's outcome, and whom it lets go on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct Answer<T> {
    pub outcome: T,
    pub wake: Wake,
}

impl<T> Answer<T> {
    fn new(outcome: T, wake: Wake) -> Answer<T> {
        Answer { outcome, wake }
    }

    fn alone(outcome: T) -> Answer<T> {
        Answer::new(outcome, Wake::default())
    }
}

/// What a read did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// This many bytes were moved into the buffer, from the front of the queue: the read completes
    /// with STATUS_SUCCESS and the count. Zero for a zero-length buffer while data is queued (it
    /// stays queued), and for a continuation that found nothing more.
    Moved(u32),
    /// Nothing to read yet, the writing end open: the reader is registered. Wait to be woken (or
    /// cancel with [`Pipe::cancel_read`]), then read again.
    Wait,
    /// The read fails with the error's status, nothing moved.
    Failed(PipeError),
}

/// A write in progress, as its writer names it to [`Pipe::feed`] and [`Pipe::cancel_write`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteTicket {
    direction: Direction,
    serial: u32,
}

/// Where a write stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStep {
    /// Copy the caller's bytes from `offset` into a kernel buffer, at most `room` of them (and at
    /// most a chunk), and feed them ([`Pipe::feed`]).
    Feed {
        ticket: WriteTicket,
        offset: u32,
        room: u32,
    },
    /// The write waits: for room in the queue, or for its charge to fit the quota. Wait to be
    /// woken (or cancel with [`Pipe::cancel_write`]), then ask again with an empty
    /// [`Pipe::feed`].
    Wait(WriteTicket),
    /// The write is complete: STATUS_SUCCESS, this many bytes written (all of them).
    Done(u32),
    /// The write fails with the error's status, nothing written.
    Failed(PipeError),
}

/// What a flush did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushOutcome {
    /// Nothing this end wrote is left unread: STATUS_SUCCESS.
    Done,
    /// The reader has yet to read what this end wrote: the flush is registered. Wait to be woken
    /// (or cancel with [`Pipe::cancel_flush`]), then flush again.
    Wait,
    /// The flush fails with the error's status.
    Failed(PipeError),
}

/// What a peek found: the header to write, and how many bytes it copied after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peeked {
    pub header: FilePipePeekBuffer,
    pub copied: u32,
}

impl Peeked {
    /// The peek's status for an output buffer with `data_room` bytes after the header: success
    /// when every byte a read could take fits, STATUS_BUFFER_OVERFLOW (a warning: the header and
    /// the bytes that fit are written, and the I/O status reports them) when some do not, as the
    /// capture's header-only buffer shows over 13 queued bytes.
    pub fn status(&self, data_room: u32) -> NtStatus {
        if data_room < self.header.read_data_available {
            STATUS_BUFFER_OVERFLOW
        } else {
            STATUS_SUCCESS
        }
    }
}

/// The room for data in a peek's output buffer of `out_len` bytes, after FILE_PIPE_PEEK_BUFFER's
/// header; a buffer shorter than the header is refused before anything is written.
pub fn peek_data_room(out_len: u32) -> Result<u32, PipeError> {
    out_len
        .checked_sub(PEEK_HEADER)
        .ok_or(PipeError::InvalidParameter)
}

/// The quota a create's InboundQuota or OutboundQuota gives: its own, or the default for 0.
pub fn resolve_quota(quota: u32) -> u32 {
    if quota == 0 {
        DEFAULT_QUOTA
    } else {
        quota
    }
}

/// The ring a queue of `quota` (as the create passes it, 0 for the default) needs: the quota and
/// one entry header; none when that is past the address space.
pub fn ring_size(quota: u32) -> Option<usize> {
    usize::try_from(resolve_quota(quota))
        .ok()?
        .checked_add(HEADER)
}

/// An end's life: the client's begins when it connects, each ends at its cleanup (its file
/// object's last handle closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndState {
    NotConnected,
    Open,
    Closed,
}

/// The write in progress on a queue: always its last entry, its header in the ring from the start.
#[derive(Clone, Copy, Debug)]
struct Write {
    serial: u32,
    waiter: Waiter,
    /// The write's length; its header holds it.
    len: u32,
    /// The bytes fed into the ring so far.
    fed: u32,
    /// The bytes of it read so far.
    read: u32,
    /// Whether its charge fitted the quota when it began: it never waits, and a close of the
    /// reading end completes it (Windows had buffered it and completed it at once).
    fits: bool,
    /// Whether its writer waits to be woken.
    waiting: bool,
}

/// A write another call finished (completed or failed) while its writer waited, kept until the
/// writer comes back for it.
#[derive(Clone, Copy, Debug)]
struct Finished {
    serial: u32,
    step: WriteStep,
}

/// One direction's data queue: its entries in the lent ring, its quota, its write in progress and
/// its waiters.
pub struct Queue<S> {
    ring: S,
    /// Which queue of its pipe this is, for the tickets of its writes.
    direction: Direction,
    quota: u32,
    /// The ring offset of the next byte to consume: an entry's header, or the head entry's data
    /// once its header is taken.
    start: usize,
    /// The ring bytes in use from `start`: headers and unread data.
    used: usize,
    /// The data bytes left of the head entry, once its header is taken off the ring (0: none
    /// taken).
    head_left: u32,
    /// The entries queued, each charged [`ENTRY_OVERHEAD`]: the completed ones and the write in
    /// progress.
    entries: u32,
    /// The data bytes in the ring, unread.
    buffered: u32,
    write: Option<Write>,
    finished: Option<Finished>,
    /// The read waiting for data.
    reader: Option<Waiter>,
    /// The flush waiting for the queue to drain.
    drain: Option<Waiter>,
    serial: u32,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Queue<S> {
    /// An empty queue of `quota` (as the create passes it, 0 for the default) over `ring`; the
    /// ring back when it is shorter than [`ring_size`] asks. A direction the pipe does not
    /// have (an anonymous pipe's outbound queue) can take the smallest ring, of quota 1: no call
    /// reaches it.
    pub fn new(ring: S, quota: u32) -> Result<Queue<S>, S> {
        match ring_size(quota) {
            Some(needed) if ring.as_ref().len() >= needed => Ok(Queue {
                ring,
                direction: Direction::Inbound,
                quota: resolve_quota(quota),
                start: 0,
                used: 0,
                head_left: 0,
                entries: 0,
                buffered: 0,
                write: None,
                finished: None,
                reader: None,
                drain: None,
                serial: 0,
            }),
            _ => Err(ring),
        }
    }

    /// The queue's quota (FilePipeLocalInformation's, which no service answers yet).
    #[cfg_attr(target_arch = "x86", allow(dead_code))]
    pub fn quota(&self) -> u32 {
        self.quota
    }

    /// The bytes a read could take: every queued byte, a pending write's included, whether or not
    /// they are in the ring yet (PeekNamedPipe's total, the peek's ReadDataAvailable).
    pub fn available(&self) -> u32 {
        self.buffered.saturating_add(self.unfed())
    }

    /// The quota left: the quota less every entry's charge (FilePipeLocalInformation's
    /// WriteQuotaAvailable), 0 while a pending write overdraws it.
    #[cfg_attr(target_arch = "x86", allow(dead_code))]
    pub fn quota_available(&self) -> u32 {
        u32::try_from(u64::from(self.quota).saturating_sub(self.charged())).unwrap_or(0)
    }

    fn capacity(&self) -> usize {
        self.ring.as_ref().len()
    }

    fn room(&self) -> usize {
        self.capacity() - self.used
    }

    /// The bytes of the write in progress still with its writer.
    fn unfed(&self) -> u32 {
        self.write.map_or(0, |write| write.len - write.fed)
    }

    /// What everything queued is charged: each entry's overhead and its unread bytes, a pending
    /// write's unfed ones included.
    fn charged(&self) -> u64 {
        u64::from(ENTRY_OVERHEAD) * u64::from(self.entries)
            + u64::from(self.buffered)
            + u64::from(self.unfed())
    }

    fn within_quota(&self) -> bool {
        self.charged() <= u64::from(self.quota)
    }

    /// Whether the head entry is the write in progress (the last entry, so the only one).
    fn head_is_write(&self) -> bool {
        self.write.is_some() && self.entries == 1
    }

    /// Copy the ring's bytes from `at` into `dst`, across its wrap.
    fn copy_out(&self, at: usize, dst: &mut [u8]) {
        let ring = self.ring.as_ref();
        let first = dst.len().min(ring.len() - at);
        let (head, tail) = dst.split_at_mut(first);
        head.copy_from_slice(&ring[at..at + first]);
        tail.copy_from_slice(&ring[..tail.len()]);
    }

    /// Append `bytes` after the ring's last, across its wrap.
    fn push(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() <= self.room(), "a pipe's ring overrun");
        let capacity = self.capacity();
        let at = (self.start + self.used) % capacity;
        let first = bytes.len().min(capacity - at);
        let ring = self.ring.as_mut();
        ring[at..at + first].copy_from_slice(&bytes[..first]);
        ring[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.used += bytes.len();
    }

    /// Take the ring's first bytes into `dst`.
    fn pop(&mut self, dst: &mut [u8]) {
        self.copy_out(self.start, dst);
        self.start = (self.start + dst.len()) % self.capacity();
        self.used -= dst.len();
    }

    /// The entry length in the header at `at`.
    fn header_at(&self, at: usize) -> u32 {
        let mut header = [0; HEADER];
        self.copy_out(at, &mut header);
        u32::from_le_bytes(header)
    }

    /// Visit each run of unread data in the ring, in order, as (ring offset, length), while
    /// `visit` answers true.
    fn runs(&self, mut visit: impl FnMut(usize, usize) -> bool) {
        let capacity = self.capacity();
        let mut at = self.start;
        let mut left = self.entries;
        if self.head_left > 0 {
            let present = match self.write {
                Some(write) if self.head_is_write() => write.fed - write.read,
                _ => self.head_left,
            };
            if !visit(at, present as usize) {
                return;
            }
            at = (at + present as usize) % capacity;
            left -= 1;
        }
        while left > 0 {
            let len = self.header_at(at);
            at = (at + HEADER) % capacity;
            // The last entry, the write in progress, holds what it has been fed; nothing of it is
            // read while its header is still in the ring.
            let present = match self.write {
                Some(write) if left == 1 => write.fed,
                _ => len,
            };
            if present == 0 || !visit(at, present as usize) {
                return;
            }
            at = (at + present as usize) % capacity;
            left -= 1;
        }
    }

    /// Copy the unread data from `skip` bytes in into `dst`, consuming nothing: the count copied.
    fn peek(&self, skip: u32, dst: &mut [u8]) -> u32 {
        let capacity = self.capacity();
        let mut skip = skip as usize;
        let mut copied = 0;
        self.runs(|at, len| {
            if skip >= len {
                skip -= len;
                return true;
            }
            let count = (len - skip).min(dst.len() - copied);
            self.copy_out((at + skip) % capacity, &mut dst[copied..copied + count]);
            skip = 0;
            copied += count;
            copied < dst.len()
        });
        copied as u32
    }

    /// Move unread data from the front into `dst`, across entries (byte mode reads past a write's
    /// end): the count moved. An entry read to its end leaves the queue, and its charge with it.
    fn take(&mut self, dst: &mut [u8]) -> u32 {
        let mut moved = 0;
        while moved < dst.len() && self.buffered > 0 {
            if self.head_left == 0 {
                let mut header = [0; HEADER];
                self.pop(&mut header);
                self.head_left = u32::from_le_bytes(header);
            }
            let head_is_write = self.head_is_write();
            let present = match self.write {
                Some(write) if head_is_write => write.fed - write.read,
                _ => self.head_left,
            };
            let count = (present as usize).min(dst.len() - moved);
            if count == 0 {
                break;
            }
            self.pop(&mut dst[moved..moved + count]);
            moved += count;
            self.buffered -= count as u32;
            self.head_left -= count as u32;
            if let Some(write) = self.write.as_mut().filter(|_| head_is_write) {
                write.read += count as u32;
            }
            if self.head_left == 0 {
                self.entries -= 1;
            }
        }
        moved as u32
    }

    /// After a read freed room or charge: complete the write in progress once all of it is in the
    /// ring and the charges fit the quota, or wake its writer to feed more once there is room; and
    /// wake a flush once the queue is drained.
    fn settle(&mut self, wake: &mut Wake) {
        if let Some(write) = self.write {
            if write.fed == write.len && self.within_quota() {
                self.finish(WriteStep::Done(write.len));
                if write.waiting {
                    wake.add(write.waiter);
                }
            } else if write.waiting && write.fed < write.len && self.room() > 0 {
                self.write.as_mut().expect("a write in progress").waiting = false;
                wake.add(write.waiter);
            }
        }
        if self.available() == 0 {
            if let Some(flusher) = self.drain.take() {
                wake.add(flusher);
            }
        }
    }

    /// End the write in progress for its writer to collect: its entry, if it completed, stays as
    /// any other.
    fn finish(&mut self, step: WriteStep) {
        let write = self.write.take().expect("a write in progress");
        self.finished = Some(Finished {
            serial: write.serial,
            step,
        });
    }

    /// Take the write in progress's entry off the queue, the bytes of it unread with it (only the
    /// last entry can go, and the write's is always the last).
    fn remove_write(&mut self) {
        let header_taken = self.head_is_write() && self.head_left > 0;
        let write = self.write.take().expect("a write in progress");
        if header_taken {
            // Its header is taken and part of it read: what is left of it is all the ring holds.
            let present = write.fed - write.read;
            debug_assert_eq!(self.used, present as usize);
            self.used = 0;
            self.buffered -= present;
            self.head_left = 0;
        } else {
            self.used -= HEADER + write.fed as usize;
            self.buffered -= write.fed;
        }
        self.entries -= 1;
    }

    /// Where the write in progress stands, registering its writer when it must wait.
    fn step(&mut self) -> WriteStep {
        let room = self.room();
        let within_quota = self.within_quota();
        let write = self.write.as_mut().expect("a write in progress");
        let ticket = WriteTicket {
            direction: self.direction,
            serial: write.serial,
        };
        if write.fed == write.len && within_quota {
            let len = write.len;
            self.write = None;
            return WriteStep::Done(len);
        }
        let room = room.min((write.len - write.fed) as usize);
        if room == 0 {
            write.waiting = true;
            WriteStep::Wait(ticket)
        } else {
            write.waiting = false;
            WriteStep::Feed {
                ticket,
                offset: write.fed,
                room: room as u32,
            }
        }
    }

    /// Begin a write of `len` bytes (not 0): its entry queued, its header in the ring.
    fn begin(&mut self, len: u32, waiter: Waiter) -> WriteStep {
        if self.write.is_some() {
            return WriteStep::Failed(PipeError::Busy);
        }
        // A finished write its writer never came back for (a writer ended in between) is
        // forgotten.
        self.finished = None;
        let charge = u64::from(ENTRY_OVERHEAD) + u64::from(len);
        let fits = self.charged() + charge <= u64::from(self.quota);
        // With no write in progress every entry's charge fits the quota, and an entry takes no more
        // ring than its charge: a ring of the quota and one header always has a header's room.
        self.push(&len.to_le_bytes());
        self.entries += 1;
        self.serial = self.serial.wrapping_add(1);
        self.write = Some(Write {
            serial: self.serial,
            waiter,
            len,
            fed: 0,
            read: 0,
            fits,
            waiting: false,
        });
        self.step()
    }

    /// Feed the write in progress `serial` with `bytes` (as many as fit), then where it stands.
    fn feed(&mut self, serial: u32, bytes: &[u8], wake: &mut Wake) -> WriteStep {
        match (self.write, self.finished) {
            (Some(write), _) if write.serial == serial => {
                let count = bytes
                    .len()
                    .min(self.room())
                    .min((write.len - write.fed) as usize);
                if count > 0 {
                    self.push(&bytes[..count]);
                    self.buffered += count as u32;
                    self.write.as_mut().expect("a write in progress").fed += count as u32;
                    if let Some(reader) = self.reader.take() {
                        wake.add(reader);
                    }
                }
                self.step()
            }
            (_, Some(finished)) if finished.serial == serial => {
                self.finished = None;
                finished.step
            }
            // A write the queue no longer knows: cancelled.
            _ => WriteStep::Failed(PipeError::Broken),
        }
    }

    /// Cancel the write `serial`: in progress, its entry and its unread bytes go; completed by
    /// another's call, its bytes stay.
    fn cancel_write(&mut self, serial: u32, wake: &mut Wake) {
        match (self.write, self.finished) {
            (Some(write), _) if write.serial == serial => {
                self.remove_write();
                if self.available() == 0 {
                    if let Some(flusher) = self.drain.take() {
                        wake.add(flusher);
                    }
                }
            }
            (_, Some(finished)) if finished.serial == serial => self.finished = None,
            _ => {}
        }
    }

    /// The reading end closed: what is queued can never be read, so it goes. A write that fitted
    /// completes (Windows had buffered it), a pending one fails STATUS_PIPE_BROKEN, as the
    /// capture's pending write does when the read end closes; a flush waiting on the queue is
    /// woken to find the reader gone.
    fn reader_closed(&mut self, wake: &mut Wake) {
        if let Some(write) = self.write {
            let step = if write.fits {
                WriteStep::Done(write.len)
            } else {
                WriteStep::Failed(PipeError::Broken)
            };
            self.finish(step);
            if write.waiting {
                wake.add(write.waiter);
            }
        }
        self.start = 0;
        self.used = 0;
        self.head_left = 0;
        self.entries = 0;
        self.buffered = 0;
        if let Some(reader) = self.reader.take() {
            wake.add(reader);
        }
        if let Some(flusher) = self.drain.take() {
            wake.add(flusher);
        }
    }

    /// The writing end closed: what it wrote stays to be read. Its waiting reader is woken (to the
    /// data, or STATUS_PIPE_BROKEN). A pending write of its own goes, failing STATUS_PIPE_BROKEN; a
    /// write that fitted, still being fed, is left to complete.
    fn writer_closed(&mut self, wake: &mut Wake) {
        if let Some(write) = self.write.filter(|write| !write.fits) {
            self.remove_write();
            self.finished = Some(Finished {
                serial: write.serial,
                step: WriteStep::Failed(PipeError::Broken),
            });
            if write.waiting {
                wake.add(write.waiter);
            }
        }
        if let Some(reader) = self.reader.take() {
            wake.add(reader);
        }
        if let Some(flusher) = self.drain.take() {
            wake.add(flusher);
        }
    }
}

/// One pipe instance: its two ends and its two queues. The service keeps it under its lock, calls
/// in with that lock held, and waits and copies outside it.
pub struct Pipe<S> {
    queues: [Queue<S>; 2],
    server: EndState,
    client: EndState,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Pipe<S> {
    /// A new instance, its server end open and listening: NtCreateNamedPipeFile's, with its two
    /// queues.
    pub fn new(mut inbound: Queue<S>, mut outbound: Queue<S>) -> Pipe<S> {
        inbound.direction = Direction::Inbound;
        outbound.direction = Direction::Outbound;
        Pipe {
            queues: [inbound, outbound],
            server: EndState::Open,
            client: EndState::NotConnected,
        }
    }

    /// A client's create or open of the pipe's name: it connects the listening instance. One
    /// already connected (or whose server is gone) is not available, as Windows answers an open of
    /// a busy instance.
    pub fn connect(&mut self) -> Result<(), PipeError> {
        if self.server != EndState::Open || self.client != EndState::NotConnected {
            return Err(PipeError::NotAvailable);
        }
        self.client = EndState::Open;
        Ok(())
    }

    /// The queue of `direction`.
    pub fn queue(&self, direction: Direction) -> &Queue<S> {
        &self.queues[direction.index()]
    }

    fn queue_mut(&mut self, direction: Direction) -> &mut Queue<S> {
        &mut self.queues[direction.index()]
    }

    fn end_state(&self, end: End) -> EndState {
        match end {
            End::Server => self.server,
            End::Client => self.client,
        }
    }

    fn end_state_mut(&mut self, end: End) -> &mut EndState {
        match end {
            End::Server => &mut self.server,
            End::Client => &mut self.client,
        }
    }

    /// The pipe's state seen from `end`.
    pub fn state(&self, end: End) -> PipeState {
        match self.end_state(end.peer()) {
            EndState::NotConnected => PipeState::Listening,
            EndState::Open => PipeState::Connected,
            EndState::Closed => PipeState::Closing,
        }
    }

    /// Whether both ends are gone (or the server went before any client came): the instance goes
    /// with its last reference.
    pub fn is_unused(&self) -> bool {
        self.server == EndState::Closed && self.client != EndState::Open
    }

    /// Whether a call can go through `end`: refused through an end already closed (only a call
    /// woken by its own end's close comes back to one), and on a server no client has opened yet.
    fn usable(&self, end: End) -> Result<(), PipeError> {
        if self.end_state(end) == EndState::Closed {
            Err(PipeError::Broken)
        } else if self.state(end) == PipeState::Listening {
            Err(PipeError::Listening)
        } else {
            Ok(())
        }
    }

    /// Whether the end that writes `end`'s read queue is gone.
    fn writer_gone(&self, end: End) -> bool {
        self.end_state(end.peer()) == EndState::Closed
    }

    /// A read through `end` into `dst` (a chunk of the caller's buffer). The first chunk of a read
    /// names its `waiter`: the read takes what is queued, at least a byte, or waits for some, or
    /// fails STATUS_PIPE_BROKEN once the writing end is closed and the queue drained (the capture:
    /// the data left, then 109, and a waiting read 109 when the write end closes). A zero-length
    /// read completes at once while anything is queued, and otherwise waits as any read does (the
    /// capture's zero-byte read on the empty pipe, woken by a write and moving nothing). Later
    /// chunks of the same read pass no waiter: they take what more is there, never waiting or
    /// failing.
    pub fn read(
        &mut self,
        end: End,
        dst: &mut [u8],
        waiter: Option<Waiter>,
    ) -> Answer<ReadOutcome> {
        let Some(waiter) = waiter else {
            if self.usable(end).is_err() {
                return Answer::alone(ReadOutcome::Moved(0));
            }
            let mut wake = Wake::default();
            let queue = self.queue_mut(end.reads());
            let moved = queue.take(dst);
            if moved > 0 {
                queue.settle(&mut wake);
            }
            return Answer::new(ReadOutcome::Moved(moved), wake);
        };
        if let Err(error) = self.usable(end) {
            self.cancel_read(end, waiter);
            return Answer::alone(ReadOutcome::Failed(error));
        }
        let writer_gone = self.writer_gone(end);
        let mut wake = Wake::default();
        let queue = self.queue_mut(end.reads());
        let outcome = if dst.is_empty() {
            if queue.available() > 0 {
                ReadOutcome::Moved(0)
            } else if writer_gone {
                ReadOutcome::Failed(PipeError::Broken)
            } else {
                ReadOutcome::Wait
            }
        } else {
            let moved = queue.take(dst);
            if moved > 0 {
                queue.settle(&mut wake);
                ReadOutcome::Moved(moved)
            } else if queue.available() == 0 && writer_gone {
                ReadOutcome::Failed(PipeError::Broken)
            } else {
                // Nothing queued, or a write's bytes still on their way from its writer.
                ReadOutcome::Wait
            }
        };
        let outcome = match (outcome, queue.reader) {
            (ReadOutcome::Wait, Some(other)) if other != waiter => {
                ReadOutcome::Failed(PipeError::Busy)
            }
            (ReadOutcome::Wait, _) => {
                queue.reader = Some(waiter);
                ReadOutcome::Wait
            }
            (outcome, reader) => {
                if reader == Some(waiter) {
                    queue.reader = None;
                }
                outcome
            }
        };
        Answer::new(outcome, wake)
    }

    /// A read's wait ended without its wake (its thread terminated, or an alert): the reader is
    /// forgotten and the pipe left as it was, as the capture's terminated reader leaves it.
    pub fn cancel_read(&mut self, end: End, waiter: Waiter) {
        let queue = self.queue_mut(end.reads());
        if queue.reader == Some(waiter) {
            queue.reader = None;
        }
    }

    /// A write of `len` bytes through `end`, by `waiter`. Through a pipe whose reading end is
    /// closed it fails STATUS_PIPE_CLOSING, even for zero bytes (the capture's 232); otherwise a
    /// zero-length write completes at once and queues nothing (the capture's peek after it shows
    /// nothing, and a zero-byte read still waits), and any other is queued, its first step
    /// returned.
    pub fn write(&mut self, end: End, len: u32, waiter: Waiter) -> Answer<WriteStep> {
        if let Err(error) = self.usable(end) {
            return Answer::alone(WriteStep::Failed(error));
        }
        if self.end_state(end.peer()) == EndState::Closed {
            return Answer::alone(WriteStep::Failed(PipeError::Closing));
        }
        if len == 0 {
            return Answer::alone(WriteStep::Done(0));
        }
        Answer::alone(self.queue_mut(end.writes()).begin(len, waiter))
    }

    /// Feed the write `ticket` the caller's next bytes (as [`WriteStep::Feed`] asked: from its
    /// offset, at most its room), or nothing to ask where it stands once woken. Bytes fed wake a
    /// waiting reader.
    pub fn feed(&mut self, ticket: WriteTicket, bytes: &[u8]) -> Answer<WriteStep> {
        let mut wake = Wake::default();
        let step = self
            .queue_mut(ticket.direction)
            .feed(ticket.serial, bytes, &mut wake);
        Answer::new(step, wake)
    }

    /// A write's wait ended without its wake (its thread terminated), or its copy failed: the
    /// write leaves nothing behind, its bytes not yet read included, as the capture's terminated
    /// writer leaves an empty pipe. A write another call already completed keeps its bytes queued.
    pub fn cancel_write(&mut self, ticket: WriteTicket) -> Wake {
        let mut wake = Wake::default();
        self.queue_mut(ticket.direction)
            .cancel_write(ticket.serial, &mut wake);
        wake
    }

    /// A flush through `end`: done once nothing it wrote is left unread (at once with nothing
    /// queued, as the capture's flush with nothing buffered), or once the reading end is closed
    /// (what it held is gone: the capture's flush after the read end's close succeeds); otherwise
    /// it waits for the reader to drain the queue, as MSDN's FlushFileBuffers does on a pipe.
    pub fn flush(&mut self, end: End, waiter: Waiter) -> Answer<FlushOutcome> {
        if let Err(error) = self.usable(end) {
            self.cancel_flush(end, waiter);
            return Answer::alone(FlushOutcome::Failed(error));
        }
        let reader_gone = self.end_state(end.peer()) == EndState::Closed;
        let queue = self.queue_mut(end.writes());
        let outcome = if reader_gone || queue.available() == 0 {
            if queue.drain == Some(waiter) {
                queue.drain = None;
            }
            FlushOutcome::Done
        } else {
            match queue.drain {
                Some(other) if other != waiter => FlushOutcome::Failed(PipeError::Busy),
                _ => {
                    queue.drain = Some(waiter);
                    FlushOutcome::Wait
                }
            }
        };
        Answer::alone(outcome)
    }

    /// A flush's wait ended without its wake: the flush is forgotten.
    pub fn cancel_flush(&mut self, end: End, waiter: Waiter) {
        let queue = self.queue_mut(end.writes());
        if queue.drain == Some(waiter) {
            queue.drain = None;
        }
    }

    /// FSCTL_PIPE_PEEK through `end`: the header for the queue it reads, and the unread bytes from
    /// `skip` in copied into `dst` without consuming them (the capture's read after a peek gets
    /// the same bytes). A service copying through a small buffer peeks chunk after chunk, `skip`
    /// the bytes already copied: only this end reads the queue, and its calls are serialized, so
    /// what it peeked stays put. The header counts every queued byte, a pending write's included
    /// (the capture's 10000 while the writer waits), and reports the pipe connected, or closing
    /// once the other end is closed; once that end is closed and the queue drained, the peek fails
    /// STATUS_PIPE_BROKEN (the capture's 109). FILE_READ_DATA on the handle is the service's check
    /// (the capture's write end gets 0xC0000022), as is the buffer's length
    /// ([`peek_data_room`]).
    pub fn peek(&self, end: End, skip: u32, dst: &mut [u8]) -> Result<Peeked, PipeError> {
        self.usable(end).map_err(|error| match error {
            PipeError::Listening => PipeError::InvalidState,
            error => error,
        })?;
        let queue = self.queue(end.reads());
        let available = queue.available();
        if available == 0 && self.writer_gone(end) {
            return Err(PipeError::Broken);
        }
        Ok(Peeked {
            header: FilePipePeekBuffer {
                named_pipe_state: self.state(end) as u32,
                read_data_available: available,
                number_of_messages: 0,
                message_length: 0,
            },
            copied: queue.peek(skip, dst),
        })
    }

    /// `end`'s cleanup, at its file object's last handle: the end closes, and the waiters this
    /// leaves nothing to wait for are woken. The queue it read goes (nobody can read it): a pending
    /// write into it fails STATUS_PIPE_BROKEN, and a later write STATUS_PIPE_CLOSING. The queue it
    /// wrote stays for the other end to read, then STATUS_PIPE_BROKEN.
    pub fn cleanup(&mut self, end: End) -> Wake {
        let mut wake = Wake::default();
        if self.end_state(end) != EndState::Open {
            return wake;
        }
        *self.end_state_mut(end) = EndState::Closed;
        self.queue_mut(end.reads()).reader_closed(&mut wake);
        self.queue_mut(end.writes()).writer_closed(&mut wake);
        wake
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READER: Waiter = Waiter(1);
    const WRITER: Waiter = Waiter(2);
    const FLUSHER: Waiter = Waiter(3);
    /// The service's copy chunk.
    const CHUNK: usize = 512;

    /// A pipe as CreatePipe makes it, of `quota` both ways, its client connected.
    fn pipe(quota: u32) -> Pipe<Vec<u8>> {
        let queue = |quota| {
            let size = ring_size(quota).unwrap();
            Queue::new(vec![0; size], quota).unwrap()
        };
        let mut pipe = Pipe::new(queue(quota), queue(quota));
        pipe.connect().unwrap();
        pipe
    }

    /// A write in progress as the service drives it: the caller's bytes, fed a chunk at a time.
    struct Writer {
        data: Vec<u8>,
        step: WriteStep,
        /// The waiters its first feeding woke.
        woke: Vec<Waiter>,
    }

    impl Writer {
        /// Begin writing `data` through `end`, and feed it as far as it goes.
        fn start(pipe: &mut Pipe<Vec<u8>>, end: End, data: &[u8]) -> Writer {
            let answer = pipe.write(end, data.len() as u32, WRITER);
            assert!(answer.wake.is_empty());
            let mut writer = Writer {
                data: data.to_vec(),
                step: answer.outcome,
                woke: Vec::new(),
            };
            writer.woke = writer.run(pipe);
            writer
        }

        /// Feed while the write asks for bytes: the waiters the feeding woke.
        fn run(&mut self, pipe: &mut Pipe<Vec<u8>>) -> Vec<Waiter> {
            let mut woken = Vec::new();
            while let WriteStep::Feed {
                ticket,
                offset,
                room,
            } = self.step
            {
                let from = offset as usize;
                let count = (room as usize).min(CHUNK).min(self.data.len() - from);
                let answer = pipe.feed(ticket, &self.data[from..from + count]);
                woken.extend(answer.wake.iter());
                self.step = answer.outcome;
            }
            woken
        }

        /// Woken: ask where the write stands, and feed on.
        fn resume(&mut self, pipe: &mut Pipe<Vec<u8>>) -> Vec<Waiter> {
            let WriteStep::Wait(ticket) = self.step else {
                panic!("resuming a write that does not wait: {:?}", self.step);
            };
            let answer = pipe.feed(ticket, &[]);
            let mut woken: Vec<Waiter> = answer.wake.iter().collect();
            self.step = answer.outcome;
            woken.extend(self.run(pipe));
            woken
        }

        fn ticket(&self) -> WriteTicket {
            match self.step {
                WriteStep::Wait(ticket) | WriteStep::Feed { ticket, .. } => ticket,
                step => panic!("no ticket: {step:?}"),
            }
        }

        fn waits(&self) -> bool {
            matches!(self.step, WriteStep::Wait(_))
        }
    }

    /// A whole write's outcome, for one that should not wait.
    fn put(pipe: &mut Pipe<Vec<u8>>, end: End, data: &[u8]) -> WriteStep {
        Writer::start(pipe, end, data).step
    }

    /// A read through `end` as the service makes it: the first chunk names the reader, the next
    /// ones take what more is there. The outcome, and the bytes.
    fn get(pipe: &mut Pipe<Vec<u8>>, end: End, len: usize) -> (ReadOutcome, Vec<u8>) {
        let (outcome, bytes, _) = get_waking(pipe, end, len);
        (outcome, bytes)
    }

    /// [`get`], and the waiters the read woke.
    fn get_waking(
        pipe: &mut Pipe<Vec<u8>>,
        end: End,
        len: usize,
    ) -> (ReadOutcome, Vec<u8>, Vec<Waiter>) {
        let mut buf = vec![0; len];
        let first = len.min(CHUNK);
        let answer = pipe.read(end, &mut buf[..first], Some(READER));
        let mut woke: Vec<Waiter> = answer.wake.iter().collect();
        let ReadOutcome::Moved(mut moved) = answer.outcome else {
            return (answer.outcome, Vec::new(), woke);
        };
        // On while each chunk comes back full.
        let mut full = moved as usize == first;
        while full && (moved as usize) < len {
            let from = moved as usize;
            let to = (from + CHUNK).min(len);
            let answer = pipe.read(end, &mut buf[from..to], None);
            woke.extend(answer.wake.iter());
            let ReadOutcome::Moved(more) = answer.outcome else {
                panic!("a continuation failed or waited");
            };
            moved += more;
            full = more as usize == to - from;
        }
        buf.truncate(moved as usize);
        (ReadOutcome::Moved(moved), buf, woke)
    }

    /// PeekNamedPipe's total through the server end.
    fn total(pipe: &Pipe<Vec<u8>>) -> u32 {
        pipe.peek(End::Server, 0, &mut [])
            .unwrap()
            .header
            .read_data_available
    }

    /// A peek through `end` into a buffer of `room` data bytes: the answer and the bytes copied.
    fn peek(pipe: &Pipe<Vec<u8>>, end: End, room: usize) -> Result<(Peeked, Vec<u8>), PipeError> {
        let mut buf = vec![0xCC; room];
        let peeked = pipe.peek(end, 0, &mut buf)?;
        buf.truncate(peeked.copied as usize);
        Ok((peeked, buf))
    }

    fn woken(wake: Wake) -> Vec<Waiter> {
        wake.iter().collect()
    }

    /// The capture's 10000-byte run.
    fn big() -> Vec<u8> {
        (0..10000u32).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    // --- create: the quotas -------------------------------------------------------------------

    /// 1-byte writes until one waits: how many completed, and PeekNamedPipe's total then.
    fn one_byte_writes(quota: u32) -> (u32, u32) {
        let mut pipe = pipe(quota);
        let mut done = 0;
        loop {
            let writer = Writer::start(&mut pipe, End::Client, b"q");
            if writer.waits() {
                return (done, total(&pipe));
            }
            assert_eq!(writer.step, WriteStep::Done(1));
            done += 1;
        }
    }

    #[test]
    fn quotas_as_captured() {
        // CreatePipe(nSize 0): 163, then 164; 1: 0, then 1; 4096 as 0; 65536: 2621, then 2622.
        assert_eq!(one_byte_writes(0), (163, 164));
        assert_eq!(one_byte_writes(1), (0, 1));
        assert_eq!(one_byte_writes(4096), (163, 164));
        assert_eq!(one_byte_writes(65536), (2621, 2622));
    }

    #[test]
    fn the_storage_a_quota_needs() {
        assert_eq!(ring_size(0), Some(4096 + HEADER));
        assert_eq!(ring_size(1), Some(1 + HEADER));
        assert_eq!(
            Queue::new(vec![0; 4099], 4096).err().map(|ring| ring.len()),
            Some(4099)
        );
        assert_eq!(
            Queue::new(vec![0; 4100], 0).ok().map(|queue| queue.quota()),
            Some(DEFAULT_QUOTA)
        );
    }

    #[test]
    fn a_waiting_one_byte_write_completes_once_read() {
        // The quota-1 pipe: the byte waits, counted; reading it completes the write.
        let mut pipe = pipe(1);
        let mut writer = Writer::start(&mut pipe, End::Client, b"q");
        assert!(writer.waits());
        assert_eq!(total(&pipe), 1);
        let answer = pipe.read(End::Server, &mut [0; 64], Some(READER));
        assert_eq!(answer.outcome, ReadOutcome::Moved(1));
        assert_eq!(woken(answer.wake), [WRITER]);
        writer.resume(&mut pipe);
        assert_eq!(writer.step, WriteStep::Done(1));
        assert_eq!(total(&pipe), 0);
    }

    #[test]
    fn the_quota_exactly_full() {
        // One write charged the whole quota completes; then a 1-byte write waits, and a zero-byte
        // one completes.
        let mut pipe = pipe(4096);
        assert_eq!(
            put(&mut pipe, End::Client, &[b'a'; 4072]),
            WriteStep::Done(4072)
        );
        assert_eq!(pipe.queue(Direction::Inbound).quota_available(), 0);
        assert_eq!(put(&mut pipe, End::Client, b""), WriteStep::Done(0));
        assert!(Writer::start(&mut pipe, End::Client, b"b").waits());
        // A byte more than the quota waits.
        let mut pipe = self::pipe(4096);
        assert!(Writer::start(&mut pipe, End::Client, &[b'a'; 4073]).waits());
        // Two entries filling it exactly: 24 + 2000 and 24 + 2048.
        let mut pipe = self::pipe(4096);
        assert_eq!(
            put(&mut pipe, End::Client, &[b'a'; 2000]),
            WriteStep::Done(2000)
        );
        assert_eq!(
            put(&mut pipe, End::Client, &[b'b'; 2048]),
            WriteStep::Done(2048)
        );
        assert_eq!(total(&pipe), 4048);
        let (outcome, bytes) = get(&mut pipe, End::Server, 8192);
        assert_eq!(outcome, ReadOutcome::Moved(4048));
        assert!(bytes[..2000].iter().all(|&b| b == b'a'));
        assert!(bytes[2000..].iter().all(|&b| b == b'b'));
    }

    #[test]
    fn a_partly_read_entry_is_charged_what_is_left() {
        let mut pipe = pipe(4096);
        assert_eq!(
            put(&mut pipe, End::Client, &[b'a'; 4072]),
            WriteStep::Done(4072)
        );
        assert_eq!(get(&mut pipe, End::Server, 2).0, ReadOutcome::Moved(2));
        // 24 + 4070 charged: 2 bytes are free, not a new entry's 26.
        let writer = Writer::start(&mut pipe, End::Client, b"bc");
        assert!(writer.waits());
        pipe.cancel_write(writer.ticket());
        assert_eq!(get(&mut pipe, End::Server, 24).0, ReadOutcome::Moved(24));
        assert_eq!(put(&mut pipe, End::Client, b"bc"), WriteStep::Done(2));
        assert_eq!(pipe.queue(Direction::Inbound).quota_available(), 0);
    }

    // --- io -----------------------------------------------------------------------------------

    #[test]
    fn a_write_then_a_read() {
        let mut pipe = pipe(0);
        assert_eq!(put(&mut pipe, End::Client, b"hello"), WriteStep::Done(5));
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(5), b"hello".to_vec())
        );
    }

    #[test]
    fn a_read_shorter_than_the_data() {
        let mut pipe = pipe(0);
        assert_eq!(
            put(&mut pipe, End::Client, b"0123456789"),
            WriteStep::Done(10)
        );
        assert_eq!(
            get(&mut pipe, End::Server, 4),
            (ReadOutcome::Moved(4), b"0123".to_vec())
        );
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(6), b"456789".to_vec())
        );
    }

    #[test]
    fn three_writes_one_read() {
        let mut pipe = pipe(0);
        for piece in [b"ab", b"cd", b"ef"] {
            assert_eq!(put(&mut pipe, End::Client, piece), WriteStep::Done(2));
        }
        assert_eq!(total(&pipe), 6);
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(6), b"abcdef".to_vec())
        );
    }

    #[test]
    fn zero_byte_writes_and_reads() {
        let mut pipe = pipe(0);
        // A zero-byte write completes and queues nothing.
        assert_eq!(put(&mut pipe, End::Client, b""), WriteStep::Done(0));
        assert_eq!(total(&pipe), 0);
        // A zero-byte read on the empty pipe waits; a write wakes it, and it moves nothing.
        assert_eq!(
            pipe.read(End::Server, &mut [], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        let answer = pipe.write(End::Client, 1, WRITER);
        let WriteStep::Feed { ticket, .. } = answer.outcome else {
            panic!("{:?}", answer.outcome)
        };
        let answer = pipe.feed(ticket, b"x");
        assert_eq!(answer.outcome, WriteStep::Done(1));
        assert_eq!(woken(answer.wake), [READER]);
        assert_eq!(
            pipe.read(End::Server, &mut [], Some(READER)).outcome,
            ReadOutcome::Moved(0)
        );
        assert_eq!(total(&pipe), 1);
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(1), b"x".to_vec())
        );
        // A zero-byte read with 2 bytes queued: at once, nothing taken.
        assert_eq!(put(&mut pipe, End::Client, b"yz"), WriteStep::Done(2));
        assert_eq!(
            pipe.read(End::Server, &mut [], Some(READER)).outcome,
            ReadOutcome::Moved(0)
        );
        assert_eq!(total(&pipe), 2);
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(2), b"yz".to_vec())
        );
    }

    #[test]
    fn peeks_as_captured() {
        let mut pipe = pipe(0);
        assert_eq!(
            put(&mut pipe, End::Client, b"peekdata12"),
            WriteStep::Done(10)
        );
        // No buffer: the total alone, and the buffer overflows.
        let (peeked, bytes) = peek(&pipe, End::Server, 0).unwrap();
        assert_eq!((peeked.header.read_data_available, bytes.len()), (10, 0));
        assert_eq!(peeked.status(0), STATUS_BUFFER_OVERFLOW);
        // A 4-byte buffer: its 4 bytes.
        let (peeked, bytes) = peek(&pipe, End::Server, 4).unwrap();
        assert_eq!((peeked.copied, bytes.as_slice()), (4, &b"peek"[..]));
        assert_eq!(peeked.status(4), STATUS_BUFFER_OVERFLOW);
        // A 64-byte buffer: all 10, byte mode's message counts 0.
        let (peeked, bytes) = peek(&pipe, End::Server, 64).unwrap();
        assert_eq!(bytes, b"peekdata12");
        assert_eq!(peeked.status(64), STATUS_SUCCESS);
        assert_eq!(
            peeked.header,
            FilePipePeekBuffer {
                named_pipe_state: 3,
                read_data_available: 10,
                number_of_messages: 0,
                message_length: 0,
            }
        );
        // Two writes, peeked as one.
        assert_eq!(put(&mut pipe, End::Client, b"+more"), WriteStep::Done(5));
        let (peeked, bytes) = peek(&pipe, End::Server, 64).unwrap();
        assert_eq!(peeked.header.read_data_available, 15);
        assert_eq!(bytes, b"peekdata12+more");
        // Nothing was consumed.
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(15), b"peekdata12+more".to_vec())
        );
        // The empty pipe: nothing, a success.
        let (peeked, bytes) = peek(&pipe, End::Server, 64).unwrap();
        assert_eq!((peeked.header.read_data_available, bytes.len()), (0, 0));
        assert_eq!(peeked.status(64), STATUS_SUCCESS);
        assert_eq!(peeked.status(0), STATUS_SUCCESS);
    }

    // --- peek ---------------------------------------------------------------------------------

    #[test]
    fn the_peek_buffer() {
        const RUN: [u8; 13] = [
            1, 2, b'F', b'2', b'K', 0, b'p', b'e', b'e', b'k', 0xFE, 0xFF, 0x7F,
        ];
        let mut pipe = pipe(0);
        assert_eq!(put(&mut pipe, End::Client, &RUN), WriteStep::Done(13));
        // A 64-byte output buffer: the header, then the 13 bytes; Information 16 + 13.
        let room = peek_data_room(64).unwrap();
        let mut data = vec![0xCC; room as usize];
        let peeked = pipe.peek(End::Server, 0, &mut data).unwrap();
        assert_eq!(peeked.status(room), STATUS_SUCCESS);
        assert_eq!(PEEK_HEADER + peeked.copied, 16 + 13);
        assert_eq!(
            rtl::pod::Pod::as_bytes(&peeked.header),
            [3, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(data[..13], RUN);
        assert!(data[13..].iter().all(|&b| b == 0xCC));
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(13), RUN.to_vec())
        );
        // The empty pipe: Information 16, available 0.
        let peeked = pipe.peek(End::Server, 0, &mut data).unwrap();
        assert_eq!((peeked.copied, peeked.header.read_data_available), (0, 0));
        // An 8-byte buffer is refused; one as long as the header overflows, available 13.
        assert_eq!(peek_data_room(8), Err(PipeError::InvalidParameter));
        assert_eq!(PipeError::InvalidParameter.status().0, 0xC000_000D);
        assert_eq!(put(&mut pipe, End::Client, &RUN), WriteStep::Done(13));
        let room = peek_data_room(16).unwrap();
        let peeked = pipe.peek(End::Server, 0, &mut []).unwrap();
        assert_eq!(peeked.status(room).0, 0x8000_0005);
        assert_eq!((peeked.copied, peeked.header.read_data_available), (0, 13));
    }

    #[test]
    fn a_peek_in_chunks() {
        let mut pipe = pipe(0);
        for piece in [&b"0123"[..], b"456", b"789ab"] {
            assert!(matches!(
                put(&mut pipe, End::Client, piece),
                WriteStep::Done(_)
            ));
        }
        let mut data = [0; 5];
        assert_eq!(pipe.peek(End::Server, 0, &mut data).unwrap().copied, 5);
        assert_eq!(&data, b"01234");
        assert_eq!(pipe.peek(End::Server, 5, &mut data).unwrap().copied, 5);
        assert_eq!(&data, b"56789");
        assert_eq!(pipe.peek(End::Server, 10, &mut data).unwrap().copied, 2);
        assert_eq!(&data[..2], b"ab");
        assert_eq!(pipe.peek(End::Server, 12, &mut data).unwrap().copied, 0);
        // Part of the head entry read: the peek starts after it.
        assert_eq!(get(&mut pipe, End::Server, 2).1, b"01");
        assert_eq!(pipe.peek(End::Server, 1, &mut data).unwrap().copied, 5);
        assert_eq!(&data, b"34567");
    }

    // --- ends ---------------------------------------------------------------------------------

    #[test]
    fn the_write_end_closed_with_data_left() {
        let mut pipe = pipe(0);
        assert_eq!(put(&mut pipe, End::Client, b"tail"), WriteStep::Done(4));
        assert!(pipe.cleanup(End::Client).is_empty());
        // The data is still peeked, the pipe closing, and read.
        let (peeked, bytes) = peek(&pipe, End::Server, 64).unwrap();
        assert_eq!(bytes, b"tail");
        assert_eq!(peeked.header.named_pipe_state, PipeState::Closing as u32);
        assert_eq!(peeked.header.named_pipe_state, 4);
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(4), b"tail".to_vec())
        );
        // Drained: reads and peeks fail broken (109), again and again.
        for _ in 0..2 {
            assert_eq!(
                get(&mut pipe, End::Server, 64).0,
                ReadOutcome::Failed(PipeError::Broken)
            );
        }
        assert_eq!(
            pipe.read(End::Server, &mut [], Some(READER)).outcome,
            ReadOutcome::Failed(PipeError::Broken)
        );
        assert_eq!(peek(&pipe, End::Server, 64).err(), Some(PipeError::Broken));
        assert_eq!(PipeError::Broken.status().0, 0xC000_014B);
        assert!(!pipe.is_unused());
        assert!(pipe.cleanup(End::Server).is_empty());
        assert!(pipe.is_unused());
    }

    #[test]
    fn the_write_end_closed_nothing_left() {
        let mut pipe = pipe(0);
        assert!(pipe.cleanup(End::Client).is_empty());
        assert_eq!(
            get(&mut pipe, End::Server, 64).0,
            ReadOutcome::Failed(PipeError::Broken)
        );
    }

    #[test]
    fn a_waiting_read_ended_by_the_write_end_closing() {
        let mut pipe = pipe(0);
        assert_eq!(
            pipe.read(End::Server, &mut [0; 64], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        assert_eq!(woken(pipe.cleanup(End::Client)), [READER]);
        assert_eq!(
            get(&mut pipe, End::Server, 64).0,
            ReadOutcome::Failed(PipeError::Broken)
        );
    }

    #[test]
    fn the_read_end_closed() {
        let mut pipe = pipe(0);
        assert_eq!(put(&mut pipe, End::Client, b"left"), WriteStep::Done(4));
        assert!(pipe.cleanup(End::Server).is_empty());
        // Writes fail closing (232), even of zero bytes.
        assert_eq!(
            put(&mut pipe, End::Client, b"x"),
            WriteStep::Failed(PipeError::Closing)
        );
        assert_eq!(
            put(&mut pipe, End::Client, b""),
            WriteStep::Failed(PipeError::Closing)
        );
        assert_eq!(PipeError::Closing.status().0, 0xC000_00B1);
        // A flush has nothing left to wait for.
        assert_eq!(pipe.flush(End::Client, FLUSHER).outcome, FlushOutcome::Done);
        // The unread bytes went with the reader.
        assert_eq!(pipe.queue(Direction::Inbound).available(), 0);
        assert_eq!(pipe.state(End::Client), PipeState::Closing);
        assert!(!pipe.is_unused());
        assert!(pipe.cleanup(End::Client).is_empty());
        assert!(pipe.is_unused());
    }

    #[test]
    fn a_closed_end_answers_nothing_more() {
        let mut pipe = pipe(0);
        assert!(pipe.cleanup(End::Server).is_empty());
        assert!(pipe.cleanup(End::Server).is_empty());
        assert_eq!(
            get(&mut pipe, End::Server, 64).0,
            ReadOutcome::Failed(PipeError::Broken)
        );
        assert_eq!(
            pipe.peek(End::Server, 0, &mut []).err(),
            Some(PipeError::Broken)
        );
        assert_eq!(
            pipe.read(End::Server, &mut [0; 4], None).outcome,
            ReadOutcome::Moved(0)
        );
        assert_eq!(
            pipe.flush(End::Server, FLUSHER).outcome,
            FlushOutcome::Failed(PipeError::Broken)
        );
    }

    // --- block --------------------------------------------------------------------------------

    #[test]
    fn a_waiting_read_woken_by_a_write() {
        let mut pipe = pipe(0);
        assert_eq!(
            pipe.read(End::Server, &mut [0; 64], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        let answer = pipe.write(End::Client, 4, WRITER);
        let WriteStep::Feed {
            ticket,
            offset: 0,
            room: 4,
        } = answer.outcome
        else {
            panic!("{:?}", answer.outcome)
        };
        let answer = pipe.feed(ticket, b"wake");
        assert_eq!(answer.outcome, WriteStep::Done(4));
        assert_eq!(woken(answer.wake), [READER]);
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(4), b"wake".to_vec())
        );
    }

    #[test]
    fn a_large_write_into_a_small_pipe() {
        let big = big();
        let mut pipe = pipe(4096);
        let mut writer = Writer::start(&mut pipe, End::Client, &big);
        // It waits, every byte counted.
        assert!(writer.waits());
        assert_eq!(total(&pipe), 10000);
        // A 1000-byte read gets 1000 of them, and the writer is woken to feed more...
        let mut buf = vec![0; 1000];
        let answer = pipe.read(End::Server, &mut buf, Some(READER));
        assert_eq!(answer.outcome, ReadOutcome::Moved(1000));
        assert_eq!(woken(answer.wake), [WRITER]);
        assert_eq!(buf, big[..1000]);
        assert!(writer.resume(&mut pipe).is_empty());
        // ...and still waits: 24 + 9000 is past the quota.
        assert!(writer.waits());
        assert_eq!(total(&pipe), 9000);
        // Reading on as the capture's reader does (the total, then that much) gets the rest in
        // order, and the write completes.
        let mut got = buf;
        while got.len() < big.len() {
            let want = total(&pipe) as usize;
            assert!(want > 0);
            let (outcome, bytes) = get(&mut pipe, End::Server, want);
            match outcome {
                ReadOutcome::Moved(_) => got.extend(bytes),
                ReadOutcome::Wait => pipe.cancel_read(End::Server, READER),
                ReadOutcome::Failed(error) => panic!("{error:?}"),
            }
            if writer.waits() {
                writer.resume(&mut pipe);
            }
        }
        assert_eq!(got, big);
        assert_eq!(writer.step, WriteStep::Done(10000));
        assert_eq!(total(&pipe), 0);
    }

    #[test]
    fn a_pending_write_completes_once_its_rest_fits() {
        let big = big();
        let mut pipe = pipe(4096);
        let mut writer = Writer::start(&mut pipe, End::Client, &big);
        // Read until 4073 are left: 24 + 4073 is one byte past the quota.
        let mut read = 0;
        while read < 10000 - 4073 {
            let want = (10000 - 4073 - read).min(4096);
            let (outcome, _) = get(&mut pipe, End::Server, want);
            let ReadOutcome::Moved(moved) = outcome else {
                panic!("{outcome:?}")
            };
            read += moved as usize;
            writer.resume(&mut pipe);
            assert!(writer.waits(), "completed with {} left", 10000 - read);
        }
        assert_eq!(read, 10000 - 4073);
        // One byte more read: it fits, and the read wakes the writer for its last bytes.
        let answer = pipe.read(End::Server, &mut [0; 1], Some(READER));
        assert_eq!(answer.outcome, ReadOutcome::Moved(1));
        assert_eq!(woken(answer.wake), [WRITER]);
        writer.resume(&mut pipe);
        assert_eq!(writer.step, WriteStep::Done(10000));
        assert_eq!(total(&pipe), 4072);
        assert_eq!(get(&mut pipe, End::Server, 8192).1, big[10000 - 4072..]);
    }

    #[test]
    fn a_waiting_reader_terminated() {
        let mut pipe = pipe(0);
        assert_eq!(
            pipe.read(End::Server, &mut [0; 64], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        pipe.cancel_read(End::Server, READER);
        assert_eq!(total(&pipe), 0);
        // The pipe still usable; a write wakes nobody.
        let answer = pipe.write(End::Client, 5, WRITER);
        let WriteStep::Feed { ticket, .. } = answer.outcome else {
            panic!("{:?}", answer.outcome)
        };
        let answer = pipe.feed(ticket, b"after");
        assert_eq!(answer.outcome, WriteStep::Done(5));
        assert!(answer.wake.is_empty());
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(5), b"after".to_vec())
        );
    }

    #[test]
    fn a_woken_reader_cancelled_changes_nothing() {
        let mut pipe = pipe(0);
        assert_eq!(
            pipe.read(End::Server, &mut [0; 64], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        assert_eq!(put(&mut pipe, End::Client, b"data"), WriteStep::Done(4));
        pipe.cancel_read(End::Server, READER);
        assert_eq!(get(&mut pipe, End::Server, 64).1, b"data");
    }

    #[test]
    fn a_waiting_writer_terminated() {
        // The capture: the total after it 0, a read then gets nothing, and the pipe goes on.
        let mut pipe = pipe(4096);
        let writer = Writer::start(&mut pipe, End::Client, &big());
        assert!(writer.waits());
        assert!(pipe.cancel_write(writer.ticket()).is_empty());
        assert_eq!(total(&pipe), 0);
        assert_eq!(
            pipe.read(End::Server, &mut [0; 64], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        pipe.cancel_read(End::Server, READER);
        assert_eq!(put(&mut pipe, End::Client, b"after"), WriteStep::Done(5));
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(5), b"after".to_vec())
        );
        // A cancel once it is forgotten does nothing; its ticket answers broken.
        assert!(pipe.cancel_write(writer.ticket()).is_empty());
        assert_eq!(
            pipe.feed(writer.ticket(), &[]).outcome,
            WriteStep::Failed(PipeError::Broken)
        );
    }

    #[test]
    fn a_waiting_writer_terminated_after_part_was_read() {
        let big = big();
        let mut pipe = pipe(4096);
        assert_eq!(put(&mut pipe, End::Client, b"before"), WriteStep::Done(6));
        let mut writer = Writer::start(&mut pipe, End::Client, &big);
        assert!(writer.waits());
        // The earlier write and part of the pending one read.
        assert_eq!(
            get(&mut pipe, End::Server, 1006).1,
            [&b"before"[..], &big[..1000]].concat()
        );
        writer.resume(&mut pipe);
        assert!(writer.waits());
        // Cancelled: the rest of it goes; what was read stays read.
        pipe.cancel_write(writer.ticket());
        assert_eq!(total(&pipe), 0);
        assert_eq!(pipe.queue(Direction::Inbound).quota_available(), 4096);
        assert_eq!(put(&mut pipe, End::Client, b"after"), WriteStep::Done(5));
        assert_eq!(get(&mut pipe, End::Server, 64).1, b"after");
    }

    #[test]
    fn a_waiting_writer_terminated_behind_other_entries() {
        let mut pipe = pipe(4096);
        assert_eq!(
            put(&mut pipe, End::Client, &[b'a'; 3000]),
            WriteStep::Done(3000)
        );
        let writer = Writer::start(&mut pipe, End::Client, &[b'b'; 3000]);
        assert!(writer.waits());
        assert_eq!(total(&pipe), 6000);
        pipe.cancel_write(writer.ticket());
        assert_eq!(total(&pipe), 3000);
        let (outcome, bytes) = get(&mut pipe, End::Server, 8192);
        assert_eq!(outcome, ReadOutcome::Moved(3000));
        assert!(bytes.iter().all(|&b| b == b'a'));
    }

    #[test]
    fn a_write_completed_by_a_read_keeps_its_bytes_when_cancelled() {
        let mut pipe = pipe(4096);
        assert_eq!(
            put(&mut pipe, End::Client, &[b'a'; 4072]),
            WriteStep::Done(4072)
        );
        let writer = Writer::start(&mut pipe, End::Client, b"bc");
        assert!(writer.waits());
        // The read completes it, and wakes its writer...
        let answer = pipe.read(End::Server, &mut [0; 100], Some(READER));
        assert_eq!(woken(answer.wake), [WRITER]);
        // ...which ends before it comes back: the bytes stay.
        pipe.cancel_write(writer.ticket());
        assert_eq!(total(&pipe), 3974);
        assert_eq!(get(&mut pipe, End::Server, 8192).1[3972..], *b"bc");
    }

    #[test]
    fn a_write_completed_by_a_read_is_collected_by_its_writer() {
        let mut pipe = pipe(4096);
        assert_eq!(
            put(&mut pipe, End::Client, &[b'a'; 4072]),
            WriteStep::Done(4072)
        );
        let mut writer = Writer::start(&mut pipe, End::Client, b"bc");
        let answer = pipe.read(End::Server, &mut [0; 100], Some(READER));
        assert_eq!(woken(answer.wake), [WRITER]);
        writer.resume(&mut pipe);
        assert_eq!(writer.step, WriteStep::Done(2));
        // Collected once: the next write begins afresh.
        assert_eq!(put(&mut pipe, End::Client, b"d"), WriteStep::Done(1));
    }

    #[test]
    fn a_waiting_write_ended_by_the_read_end_closing() {
        let mut pipe = pipe(4096);
        let mut writer = Writer::start(&mut pipe, End::Client, &big());
        assert!(writer.waits());
        assert_eq!(woken(pipe.cleanup(End::Server)), [WRITER]);
        writer.resume(&mut pipe);
        assert_eq!(writer.step, WriteStep::Failed(PipeError::Broken));
    }

    #[test]
    fn a_fitting_write_completes_when_the_read_end_closes_while_it_is_fed() {
        let mut pipe = pipe(4096);
        let answer = pipe.write(End::Client, 2000, WRITER);
        let WriteStep::Feed { ticket, .. } = answer.outcome else {
            panic!("{:?}", answer.outcome)
        };
        assert_eq!(
            pipe.feed(ticket, &[0; 512]).outcome,
            WriteStep::Feed {
                ticket,
                offset: 512,
                room: 1488
            }
        );
        assert!(pipe.cleanup(End::Server).is_empty());
        assert_eq!(pipe.feed(ticket, &[0; 512]).outcome, WriteStep::Done(2000));
    }

    #[test]
    fn the_write_end_closed_under_its_own_waiting_write() {
        let mut pipe = pipe(4096);
        assert_eq!(put(&mut pipe, End::Client, b"kept"), WriteStep::Done(4));
        let mut writer = Writer::start(&mut pipe, End::Client, &big());
        assert!(writer.waits());
        assert_eq!(woken(pipe.cleanup(End::Client)), [WRITER]);
        writer.resume(&mut pipe);
        assert_eq!(writer.step, WriteStep::Failed(PipeError::Broken));
        assert_eq!(
            get(&mut pipe, End::Server, 64),
            (ReadOutcome::Moved(4), b"kept".to_vec())
        );
        assert_eq!(
            get(&mut pipe, End::Server, 64).0,
            ReadOutcome::Failed(PipeError::Broken)
        );
    }

    #[test]
    fn a_read_waits_for_bytes_a_writer_has_yet_to_feed() {
        let mut pipe = pipe(0);
        let answer = pipe.write(End::Client, 3, WRITER);
        let WriteStep::Feed { ticket, .. } = answer.outcome else {
            panic!("{:?}", answer.outcome)
        };
        // Counted, not yet in the ring: a zero-byte read completes, a read waits.
        assert_eq!(total(&pipe), 3);
        assert_eq!(
            pipe.read(End::Server, &mut [], Some(READER)).outcome,
            ReadOutcome::Moved(0)
        );
        assert_eq!(
            pipe.read(End::Server, &mut [0; 8], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        let answer = pipe.feed(ticket, b"abc");
        assert_eq!(woken(answer.wake), [READER]);
        assert_eq!(get(&mut pipe, End::Server, 8).1, b"abc");
    }

    // --- flush, connection, one call per end --------------------------------------------------

    #[test]
    fn a_flush_waits_until_the_reader_drains_the_queue() {
        let mut pipe = pipe(0);
        assert_eq!(pipe.flush(End::Client, FLUSHER).outcome, FlushOutcome::Done);
        assert_eq!(put(&mut pipe, End::Client, b"abc"), WriteStep::Done(3));
        assert_eq!(pipe.flush(End::Client, FLUSHER).outcome, FlushOutcome::Wait);
        let answer = pipe.read(End::Server, &mut [0; 2], Some(READER));
        assert!(answer.wake.is_empty());
        let answer = pipe.read(End::Server, &mut [0; 2], Some(READER));
        assert_eq!(woken(answer.wake), [FLUSHER]);
        assert_eq!(pipe.flush(End::Client, FLUSHER).outcome, FlushOutcome::Done);
        // Cancelled, then woken by the reader's close.
        assert_eq!(put(&mut pipe, End::Client, b"abc"), WriteStep::Done(3));
        assert_eq!(pipe.flush(End::Client, FLUSHER).outcome, FlushOutcome::Wait);
        pipe.cancel_flush(End::Client, FLUSHER);
        assert_eq!(get(&mut pipe, End::Server, 1).0, ReadOutcome::Moved(1));
        assert_eq!(pipe.flush(End::Client, FLUSHER).outcome, FlushOutcome::Wait);
        assert_eq!(woken(pipe.cleanup(End::Server)), [FLUSHER]);
        assert_eq!(pipe.flush(End::Client, FLUSHER).outcome, FlushOutcome::Done);
    }

    #[test]
    fn a_listening_pipe() {
        let size = ring_size(0).unwrap();
        let queue = || Queue::new(vec![0; size], 0).ok().unwrap();
        let mut pipe = Pipe::new(queue(), queue());
        assert_eq!(pipe.state(End::Server), PipeState::Listening);
        assert_eq!(
            get(&mut pipe, End::Server, 4).0,
            ReadOutcome::Failed(PipeError::Listening)
        );
        assert_eq!(
            pipe.write(End::Server, 4, WRITER).outcome,
            WriteStep::Failed(PipeError::Listening)
        );
        assert_eq!(
            pipe.peek(End::Server, 0, &mut []).err(),
            Some(PipeError::InvalidState)
        );
        assert_eq!(pipe.connect(), Ok(()));
        assert_eq!(pipe.connect(), Err(PipeError::NotAvailable));
        assert_eq!(pipe.state(End::Server), PipeState::Connected);
        // A server gone before any client: the instance is unused.
        let mut pipe = Pipe::new(queue(), queue());
        assert!(pipe.cleanup(End::Server).is_empty());
        assert!(pipe.is_unused());
        assert_eq!(pipe.connect(), Err(PipeError::NotAvailable));
    }

    #[test]
    fn one_waiting_call_per_end() {
        let mut pipe = pipe(0);
        assert_eq!(
            pipe.read(End::Server, &mut [0; 4], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        assert_eq!(
            pipe.read(End::Server, &mut [0; 4], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        assert_eq!(
            pipe.read(End::Server, &mut [0; 4], Some(Waiter(9))).outcome,
            ReadOutcome::Failed(PipeError::Busy)
        );
        let writer = Writer::start(&mut pipe, End::Client, &[0; 5000]);
        assert!(writer.waits());
        assert_eq!(
            pipe.write(End::Client, 1, Waiter(9)).outcome,
            WriteStep::Failed(PipeError::Busy)
        );
    }

    #[test]
    fn both_directions() {
        let mut pipe = pipe(64);
        // The server writes the outbound queue and the client reads it, apart from the inbound one.
        assert_eq!(
            put(&mut pipe, End::Server, b"to the client"),
            WriteStep::Done(13)
        );
        assert_eq!(
            put(&mut pipe, End::Client, b"to the server"),
            WriteStep::Done(13)
        );
        assert_eq!(pipe.queue(Direction::Outbound).available(), 13);
        assert_eq!(pipe.queue(Direction::Inbound).available(), 13);
        assert_eq!(get(&mut pipe, End::Client, 64).1, b"to the client");
        assert_eq!(get(&mut pipe, End::Server, 64).1, b"to the server");
        // A pending write outbound, read through by the client; a read waiting inbound meanwhile.
        let data: Vec<u8> = (0..100).collect();
        let mut out = Writer::start(&mut pipe, End::Server, &data);
        assert!(out.waits());
        assert_eq!(
            pipe.read(End::Server, &mut [0; 8], Some(READER)).outcome,
            ReadOutcome::Wait
        );
        let mut got: Vec<u8> = Vec::new();
        while got.len() < data.len() {
            let mut buf = [0; 30];
            if let ReadOutcome::Moved(moved) =
                pipe.read(End::Client, &mut buf, Some(Waiter(7))).outcome
            {
                got.extend(&buf[..moved as usize]);
            }
            if out.waits() {
                out.resume(&mut pipe);
            }
        }
        assert_eq!(got, data);
        assert_eq!(out.step, WriteStep::Done(100));
        // The client's close breaks the server's waiting read, and closes the server's writes.
        assert_eq!(woken(pipe.cleanup(End::Client)), [READER]);
        assert_eq!(
            get(&mut pipe, End::Server, 8).0,
            ReadOutcome::Failed(PipeError::Broken)
        );
        assert_eq!(
            put(&mut pipe, End::Server, b"x"),
            WriteStep::Failed(PipeError::Closing)
        );
    }

    // --- the ring -----------------------------------------------------------------------------

    #[test]
    fn entries_across_the_ring_wrap() {
        // A 64-byte quota, a 68-byte ring: the start walks round, so headers and data straddle the
        // wrap at every offset.
        let mut pipe = pipe(64);
        for round in 0..200u32 {
            let len = 1 + (round % 37) as usize;
            let data: Vec<u8> = (0..len).map(|i| (round as usize * 31 + i) as u8).collect();
            assert_eq!(
                put(&mut pipe, End::Client, &data),
                WriteStep::Done(len as u32)
            );
            let mut peeked = vec![0; len];
            assert_eq!(
                pipe.peek(End::Server, 0, &mut peeked).unwrap().copied as usize,
                len
            );
            assert_eq!(peeked, data);
            assert_eq!(get(&mut pipe, End::Server, len).1, data);
        }
        // Two entries at once (24 + 9 and 24 + 7 at most fill the quota), round the wrap.
        for round in 0..100u32 {
            let a: Vec<u8> = (0..(round % 9 + 1)).map(|i| i as u8).collect();
            let b: Vec<u8> = (0..(round % 7 + 1)).map(|i| 0x80 | i as u8).collect();
            assert!(matches!(
                put(&mut pipe, End::Client, &a),
                WriteStep::Done(_)
            ));
            assert!(matches!(
                put(&mut pipe, End::Client, &b),
                WriteStep::Done(_)
            ));
            assert_eq!(get(&mut pipe, End::Server, 64).1, [a, b].concat());
        }
    }

    #[test]
    fn a_header_split_by_the_wrap() {
        // A 68-byte ring: two entries of 4 + 30 and 4 + 28 read leave the start 2 bytes before its
        // end.
        let mut pipe = pipe(64);
        assert_eq!(put(&mut pipe, End::Client, &[1; 30]), WriteStep::Done(30));
        assert_eq!(get(&mut pipe, End::Server, 30).0, ReadOutcome::Moved(30));
        assert_eq!(put(&mut pipe, End::Client, &[2; 28]), WriteStep::Done(28));
        assert_eq!(get(&mut pipe, End::Server, 28).0, ReadOutcome::Moved(28));
        assert_eq!(pipe.queue(Direction::Inbound).start, 66);
        assert_eq!(put(&mut pipe, End::Client, b"split"), WriteStep::Done(5));
        let mut data = [0; 5];
        assert_eq!(pipe.peek(End::Server, 0, &mut data).unwrap().copied, 5);
        assert_eq!(&data, b"split");
        assert_eq!(get(&mut pipe, End::Server, 64).1, b"split");
    }

    #[test]
    fn a_pending_write_across_the_wrap() {
        // A pending write fed round the ring's end as reads free its start.
        let mut pipe = pipe(64);
        assert_eq!(put(&mut pipe, End::Client, &[0; 40]), WriteStep::Done(40));
        assert_eq!(get(&mut pipe, End::Server, 40).0, ReadOutcome::Moved(40));
        let data: Vec<u8> = (0..200).collect();
        let mut writer = Writer::start(&mut pipe, End::Client, &data);
        let mut got = Vec::new();
        while got.len() < data.len() {
            let (outcome, bytes) = get(&mut pipe, End::Server, 23);
            if let ReadOutcome::Moved(_) = outcome {
                got.extend(bytes);
            }
            if writer.waits() {
                writer.resume(&mut pipe);
            }
        }
        assert_eq!(got, data);
        assert_eq!(writer.step, WriteStep::Done(200));
    }

    /// A small deterministic generator.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self, below: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) % below
        }
    }

    #[test]
    fn writes_and_reads_against_a_model() {
        // Random writes (fitting and pending), reads of random lengths and cancelled writers, each
        // waiter calling again only once woken: the bytes arrive in order, the totals agree, the
        // ring never overruns, with no write in progress the quota holds, and a reader and a writer
        // never both wait unwoken.
        for quota in [1, 7, 64, 300, 4096] {
            let mut rng = Lcg(u64::from(quota));
            let mut pipe = pipe(quota);
            let mut sent: Vec<u8> = Vec::new();
            let mut received: Vec<u8> = Vec::new();
            let mut writer: Option<Writer> = None;
            let mut writer_woken = false;
            let mut reader_waits = false;
            let mut next = 0u8;
            for round in 0..4000 {
                let draining = round >= 3000;
                let mut woke = Vec::new();
                match rng.next(3) {
                    0 if writer.is_none() && !draining => {
                        let len = rng.next(2 * u64::from(quota) + 50) as usize;
                        let data: Vec<u8> = (0..len)
                            .map(|_| {
                                next = next.wrapping_add(1);
                                next
                            })
                            .collect();
                        sent.extend(&data);
                        let started = Writer::start(&mut pipe, End::Client, &data);
                        woke.extend(&started.woke);
                        if !matches!(started.step, WriteStep::Done(_)) {
                            assert!(started.waits());
                            writer = Some(started);
                            writer_woken = false;
                        }
                    }
                    1 if writer.as_ref().is_some_and(Writer::waits)
                        && !draining
                        && rng.next(8) == 0 =>
                    {
                        // The writer ends: its unread bytes go.
                        let ticket = writer.take().map(|writer| writer.ticket()).unwrap();
                        woke.extend(pipe.cancel_write(ticket).iter());
                        sent.truncate(received.len() + total(&pipe) as usize);
                    }
                    _ if !reader_waits => {
                        let len = rng.next(2 * u64::from(quota) + 20) as usize;
                        let (outcome, bytes, read_woke) = get_waking(&mut pipe, End::Server, len);
                        woke.extend(read_woke);
                        match outcome {
                            ReadOutcome::Moved(_) => received.extend(bytes),
                            ReadOutcome::Wait => reader_waits = true,
                            ReadOutcome::Failed(error) => panic!("{error:?}"),
                        }
                    }
                    _ => {}
                }
                // Wake whom the calls named, and let a woken writer go on.
                loop {
                    for waiter in woke.drain(..) {
                        match waiter {
                            READER => reader_waits = false,
                            WRITER => writer_woken = true,
                            other => panic!("woke {other:?}"),
                        }
                    }
                    let Some(active) = writer.as_mut().filter(|_| writer_woken) else {
                        break;
                    };
                    writer_woken = false;
                    woke = active.resume(&mut pipe);
                    if let WriteStep::Done(len) = active.step {
                        assert_eq!(len as usize, active.data.len());
                        writer = None;
                    }
                }
                assert!(
                    !(reader_waits && writer.is_some()),
                    "a reader and a writer both waiting"
                );
                let queue = pipe.queue(Direction::Inbound);
                assert_eq!(received.len() + queue.available() as usize, sent.len());
                assert!(queue.used <= queue.capacity());
                assert_eq!(sent[..received.len()], received);
                if queue.write.is_none() {
                    assert!(queue.within_quota());
                }
            }
            // Drained in the end: every byte sent arrived.
            assert!(writer.is_none());
            assert_eq!(received, sent);
        }
    }
}

//! The named-pipe file system's instances (NPFS, `\Device\NamedPipe`): the pool of pipe instances,
//! the waits of the calls through their ends, and the copies between their queues and the callers'
//! memory. What each call does to a pipe is [`super::npfs`]'s; this module holds the pipes, takes
//! their lock, waits and copies.
//!
//! An instance is made by NtCreateNamedPipeFile (its server end) and connected by a create or open
//! of its name (its client end); each end is one file object ([`crate::fs::file::Context::Pipe`]),
//! and the instance goes with the last of them (its close), as Windows 2000's NPFS deletes a pipe
//! instance's control block with its last file object. One instance per name: a pipe of several
//! instances, message mode and non-blocking completion are the stub path (STATUS_NOT_IMPLEMENTED).
//!
//! Memory. The instances live in a pool of [`PIPES`] records under one short lock (the kernel's
//! image holds their fixed parts); their data queues' rings are blocks of the nonpaged pool
//! ([`crate::mem::pool`]), taken at the create and given back with the instance, as Windows 2000
//! keeps a pipe's data in nonpaged pool. A direction the server end can never serve (an anonymous
//! pipe's outbound queue: its server end cannot write) takes no block: its queue's ring is a few
//! bytes in the record, of quota 1. A queue's quota is the create's (0: the default, 4096), at
//! most [`MAX_QUOTA`]: MSDN has the buffer sizes advisory, the system using its minimum or maximum
//! in their place, so a create asking for more gets that much. A create finding every record taken,
//! or the pool unable to give its blocks (the region full, or the frames gone), is
//! STATUS_INSUFFICIENT_RESOURCES. No quota is charged to the creating process (Windows 2000
//! charges the pipe's pool to it, and fails a create past the process's quota with
//! STATUS_QUOTA_EXCEEDED): F2K keeps no per-process pool quotas.
//!
//! Waits. A pipe's state is changed only under the lock, briefly, never across a wait or a copy
//! of user memory. A call that must wait ([`npfs::ReadOutcome::Wait`] and kin) drops the lock and
//! waits on its role's event (each queue's reader, writer and flusher has one: [`Waiter`] names
//! it); a call that lets a waiter go on sets the waiter's event once it has dropped the lock, and
//! the woken caller calls again. The waits are user-mode ones, as Windows 2000's synchronous I/O
//! waits in the caller's mode, outside any critical region: a termination interrupts them
//! (STATUS_USER_APC), and the call cancels what it registered before it returns, so the thread
//! ends and the pipe forgets it. User bytes pass through a 512-byte buffer on the service's stack,
//! a chunk at a time, copied at the passive level with the lock dropped.

use super::npfs::{self, Direction, End, Waiter};

/// How many pipe instances can exist at once.
pub const PIPES: usize = 64;

/// The longest pipe name a create or open takes, in units: the part after `\Device\NamedPipe\`
/// (MSDN's limit for a pipe's name is 256 characters).
pub const MAX_PIPE_NAME: usize = 256;

/// The largest quota a queue takes: 1 MiB (see the module notes).
pub const MAX_QUOTA: u32 = 1 << 20;

/// The chunk user bytes move through.
const CHUNK: usize = 512;

/// The priority increment a woken waiter gets: IO_NAMED_PIPE_INCREMENT (ntddk.h), what Windows
/// 2000's NPFS completes a waiting request with.
const WAKE_INCREMENT: i8 = 2;

/// The share access bits a server's create reads its pipe's configuration from: a client may write
/// (the inbound direction) when FILE_SHARE_WRITE is given, read (outbound) when FILE_SHARE_READ is.
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;

/// One end of a pipe instance, as the file object open on it names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipeEnd {
    /// The instance's record in the pool.
    pub instance: u16,
    pub end: End,
}

/// A pipe's name: the units after `\Device\NamedPipe\`, as the create spelled them. Names compare
/// case-insensitively (ASCII letters), as Windows' pipe names do.
#[derive(Clone, Copy)]
pub struct PipeName {
    units: [u16; MAX_PIPE_NAME],
    length: usize,
}

impl PipeName {
    /// The name `units` spell; none when they are more than [`MAX_PIPE_NAME`].
    pub fn new(units: &[u16]) -> Option<PipeName> {
        let mut name = PipeName {
            units: [0; MAX_PIPE_NAME],
            length: units.len(),
        };
        name.units.get_mut(..units.len())?.copy_from_slice(units);
        Some(name)
    }

    /// The name's units.
    pub fn units(&self) -> &[u16] {
        &self.units[..self.length]
    }

    /// Whether `other` names the same pipe.
    pub fn matches(&self, other: &PipeName) -> bool {
        let fold = |unit: u16| match u8::try_from(unit) {
            Ok(byte) => u16::from(byte.to_ascii_uppercase()),
            Err(_) => unit,
        };
        self.length == other.length
            && self
                .units()
                .iter()
                .zip(other.units())
                .all(|(&a, &b)| fold(a) == fold(b))
    }
}

/// The waiter roles of a queue: the read waiting for data, the write waiting for room, the flush
/// waiting for the reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Reader,
    Writer,
    Flusher,
}

/// How many waiter roles an instance has: three per queue.
const ROLES: usize = 6;

/// The waiter a call through a queue registers as, which names its event among the instance's
/// [`ROLES`].
fn waiter(direction: Direction, role: Role) -> Waiter {
    let queue = match direction {
        Direction::Inbound => 0,
        Direction::Outbound => 3,
    };
    let role = match role {
        Role::Reader => 0,
        Role::Writer => 1,
        Role::Flusher => 2,
    };
    Waiter(queue + role)
}

/// The quota a create's InboundQuota or OutboundQuota gives a queue: the default for 0, at most
/// [`MAX_QUOTA`].
pub fn quota(asked: u32) -> u32 {
    npfs::resolve_quota(asked).min(MAX_QUOTA)
}

/// Which queues a server end serves, so which need a ring of their quota: the inbound one when the
/// pipe takes a client's writes (FILE_SHARE_WRITE) and the server may read (FILE_READ_DATA), the
/// outbound one when it takes a client's reads (FILE_SHARE_READ) and the server may write
/// (FILE_WRITE_DATA).
pub fn served(share: u32, granted: u32) -> [bool; 2] {
    use crate::fs::file::rights::{FILE_READ_DATA, FILE_WRITE_DATA};
    [
        share & FILE_SHARE_WRITE != 0 && granted & FILE_READ_DATA != 0,
        share & FILE_SHARE_READ != 0 && granted & FILE_WRITE_DATA != 0,
    ]
}

/// Whether a client asking `granted` may open a pipe its server created sharing `share`: reading
/// needs an outbound pipe (FILE_SHARE_READ), writing an inbound one (FILE_SHARE_WRITE).
pub fn client_allowed(share: u32, granted: u32) -> bool {
    use crate::fs::file::rights::{FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA};
    let reads = granted & FILE_READ_DATA != 0;
    let writes = granted & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0;
    (!reads || share & FILE_SHARE_READ != 0) && (!writes || share & FILE_SHARE_WRITE != 0)
}

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use core::cell::UnsafeCell;
    use core::ptr::NonNull;

    use super::*;
    use crate::fs::npfs::{FlushOutcome, Pipe, PipeError, Queue, ReadOutcome, Wake, WriteStep};
    use crate::interrupt::irql;
    use crate::level::{At, Dispatch, Passive};
    use crate::mem::pool::{self, Block};
    use crate::nt::call::UserAddr;
    use crate::sched::event::{Event, EventKind};
    use crate::sched::wait::{WaitMode, WaitReason, Waitable, WaitableId};
    use crate::status::*;
    use crate::sync::ShortLock;
    use crate::user::syscall::{read_user, write_user};

    /// The ring of a queue: a block of the nonpaged pool, or, for a direction the server never
    /// serves, the smallest ring a queue takes, in the record.
    enum Ring {
        Pool(Block),
        Unused([u8; UNUSED_RING]),
    }

    /// The smallest ring: a queue of quota 1's.
    const UNUSED_RING: usize = 5;

    impl AsRef<[u8]> for Ring {
        fn as_ref(&self) -> &[u8] {
            match self {
                Ring::Pool(block) => block.as_ref(),
                Ring::Unused(bytes) => bytes,
            }
        }
    }

    impl AsMut<[u8]> for Ring {
        fn as_mut(&mut self) -> &mut [u8] {
            match self {
                Ring::Pool(block) => block.as_mut(),
                Ring::Unused(bytes) => bytes,
            }
        }
    }

    /// One pipe instance: its ends and queues, its name, its quotas as the create gave them, and
    /// how many file objects are open on it.
    struct Instance {
        pipe: Pipe<Ring>,
        name: PipeName,
        quotas: [u32; 2],
        /// The share access the server's create gave: which ways a client may open it.
        share: u32,
        objects: u8,
    }

    /// The pool: every instance's record, and whether each record's events are named yet.
    struct Pipes {
        instances: [Option<Instance>; PIPES],
        named: [bool; PIPES],
    }

    impl Pipes {
        /// The instance `end` is open on: it lives while any file object is open on it.
        fn pipe(&mut self, end: PipeEnd) -> &mut Pipe<Ring> {
            &mut self.instance(end.instance).pipe
        }

        fn instance(&mut self, index: u16) -> &mut Instance {
            self.instances[usize::from(index)]
                .as_mut()
                .expect("a pipe instance lives while a file object is open on it")
        }

        /// The live instance named `name`, by its record.
        fn find(&self, name: &PipeName) -> Option<u16> {
            self.instances
                .iter()
                .position(|instance| instance.as_ref().is_some_and(|it| it.name.matches(name)))
                .map(|index| index as u16)
        }
    }

    /// The pool, behind its lock.
    static PIPES_LOCK: ShortLock<Pipes> = ShortLock::new(Pipes {
        instances: [const { None }; PIPES],
        named: [false; PIPES],
    });

    /// Each instance record's waiter events, one per role (see [`waiter`]): synchronization
    /// events, outside the lock's value, since the dispatcher walks a waited event's list while
    /// other threads hold the lock. A signal set before its waiter parks stays on the event and
    /// lets the wait through, to call again.
    struct Signals([[UnsafeCell<Event>; ROLES]; PIPES]);

    // SAFETY: an event is reached only by its address, inside the wait discipline (which runs at
    // the dispatch level, serialized on one processor), and named once ([`name_signals`]), under
    // the pool's lock, before anything can wait on it.
    unsafe impl Sync for Signals {}

    static SIGNALS: Signals = Signals(
        [const { [const { UnsafeCell::new(Event::new(EventKind::Synchronization, false)) }; ROLES] };
            PIPES],
    );

    /// The event of `waiter` in record `instance`, by its header's address: no reference to it is
    /// formed, as the dispatcher may be walking its waiters.
    fn signal(instance: u16, waiter: Waiter) -> WaitableId {
        let cell = &SIGNALS.0[usize::from(instance)][waiter.0];
        // SAFETY: a projection inside the static's cell: it computes the header's address and
        // reads nothing.
        let header: *mut Waitable = unsafe { core::ptr::addr_of_mut!((*cell.get()).waitable) };
        WaitableId::Embedded(NonNull::new(header).expect("a static is not null"))
    }

    /// Make record `instance`'s events ready for a new instance: named at their addresses the
    /// first time, their signals cleared every time. No thread waits on them: their previous
    /// instance went with its last file object, and every call waits holding one.
    fn name_signals(pipes: &mut Pipes, instance: u16) {
        let index = usize::from(instance);
        if !pipes.named[index] {
            for cell in &SIGNALS.0[index] {
                // SAFETY: under the pool's lock, before the record's first instance: nothing has
                // the events' addresses yet, so this is the only reference to each.
                unsafe { (*cell.get()).init() };
            }
            pipes.named[index] = true;
        }
        crate::level::raised::<Dispatch, _>(|dispatch| {
            let dispatcher = crate::sched::DISPATCHER.get(dispatch);
            for role in 0..ROLES {
                dispatcher.reset_event(signal(instance, Waiter(role)));
            }
        });
    }

    /// Run `f` on the locked pool: the bridge for the services, which hold no passive token here.
    ///
    /// # Panics
    ///
    /// The processor is above the passive level (inside the lock already, or raised).
    fn with_pipes<R>(f: impl FnOnce(&mut Pipes) -> R) -> R {
        assert_eq!(
            crate::pcr::pcr().current(),
            irql::PASSIVE,
            "the pipes' bridge entered above the passive level"
        );
        // SAFETY: a passive entry (see `At::enter`): the ledger reads the passive level, and the
        // token stays on this thread, dropped with this frame.
        let mut passive = unsafe { At::<Passive>::enter() };
        let mut pipes = PIPES_LOCK.lock(&mut passive);
        f(&mut pipes)
    }

    /// Wake the waiters a call let go on, the pool's lock dropped.
    fn wake(instance: u16, wake: Wake) {
        if wake.is_empty() {
            return;
        }
        crate::level::raised::<Dispatch, _>(|dispatch| {
            let dispatcher = crate::sched::DISPATCHER.get(dispatch);
            for waiter in wake.iter() {
                dispatcher.set_event(signal(instance, waiter), WAKE_INCREMENT);
            }
        });
    }

    /// Wait to be woken as `waiter` of `instance`: STATUS_SUCCESS once woken, or the status a
    /// termination's interruption ends the wait with (STATUS_USER_APC).
    fn wait_as(instance: u16, waiter: Waiter) -> NtStatus {
        crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, _replay| {
            dispatcher.wait_for(
                thread,
                signal(instance, waiter),
                WaitReason::Executive,
                WaitMode::User,
                false,
                None,
                stamp,
            )
        })
    }

    /// A ring for a queue of `quota`: a pool block when the server serves the direction, else the
    /// record's few bytes (quota 1). None when the pool has no block to give.
    fn ring(served: bool, quota: u32) -> Option<(Ring, u32)> {
        if !served {
            return Some((Ring::Unused([0; UNUSED_RING]), 1));
        }
        let bytes = npfs::ring_size(quota)?;
        Some((Ring::Pool(pool::allocate(bytes)?), quota))
    }

    /// What NtCreateNamedPipeFile asks of the file system: a new instance named `name`, its server
    /// end open (and listening), its queues of the quotas asked (see [`quota`]), sharing `share`
    /// (its configuration) and granted `granted` (which queues it serves). A name already taken is
    /// `Err(None)`, for the service to answer as its disposition says; a full pool
    /// STATUS_INSUFFICIENT_RESOURCES.
    pub fn create(
        name: &PipeName,
        share: u32,
        granted: u32,
        inbound: u32,
        outbound: u32,
    ) -> Result<PipeEnd, Option<NtStatus>> {
        let [serves_in, serves_out] = served(share, granted);
        let quotas = [quota(inbound), quota(outbound)];
        // The rings first, outside the lock (their pages are zeroed as they are mapped).
        let insufficient = Some(STATUS_INSUFFICIENT_RESOURCES);
        let (inbound_ring, inbound_quota) = ring(serves_in, quotas[0]).ok_or(insufficient)?;
        let (outbound_ring, outbound_quota) = ring(serves_out, quotas[1]).ok_or(insufficient)?;
        let made = with_pipes(|pipes| {
            if pipes.find(name).is_some() {
                return Err(None);
            }
            let index = pipes
                .instances
                .iter()
                .position(Option::is_none)
                .ok_or(insufficient)? as u16;
            let (Ok(inbound), Ok(outbound)) = (
                Queue::new(inbound_ring, inbound_quota),
                Queue::new(outbound_ring, outbound_quota),
            ) else {
                unreachable!("each ring is its quota's size");
            };
            name_signals(pipes, index);
            pipes.instances[usize::from(index)] = Some(Instance {
                pipe: Pipe::new(inbound, outbound),
                name: *name,
                quotas,
                share,
                objects: 1,
            });
            Ok(index)
        })?;
        Ok(PipeEnd {
            instance: made,
            end: End::Server,
        })
    }

    /// Whether a pipe named `name` exists.
    pub fn exists(name: &PipeName) -> bool {
        with_pipes(|pipes| pipes.find(name).is_some())
    }

    /// What a create or open of a pipe's name asks of the file system: the client end of the
    /// instance named `name`, connected, for a client granted `granted`.
    /// STATUS_OBJECT_NAME_NOT_FOUND when no pipe has the name; STATUS_PIPE_NOT_AVAILABLE when its
    /// instance has a client already (or its server end is closed); STATUS_ACCESS_DENIED for a
    /// client asking a way the pipe does not go (see [`client_allowed`]).
    pub fn connect(name: &PipeName, granted: u32) -> Result<PipeEnd, NtStatus> {
        with_pipes(|pipes| {
            let index = pipes.find(name).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            let instance = pipes.instance(index);
            if !client_allowed(instance.share, granted) {
                return Err(STATUS_ACCESS_DENIED);
            }
            instance.pipe.connect().map_err(PipeError::status)?;
            instance.objects += 1;
            Ok(PipeEnd {
                instance: index,
                end: End::Client,
            })
        })
    }

    /// Undo a create's or a connect's end when no file object came of it: its cleanup and close.
    pub fn abandon(end: PipeEnd) {
        cleanup(end);
        close(end);
    }

    /// An end's cleanup, its file object's last handle closed: the end closes and the waiters it
    /// leaves nothing to wait for are woken (see [`npfs::Pipe::cleanup`]).
    pub fn cleanup(end: PipeEnd) {
        let woken = with_pipes(|pipes| pipes.pipe(end).cleanup(end.end));
        wake(end.instance, woken);
    }

    /// An end's close, its file object gone: the instance goes with the last, its rings given back
    /// to the pool once the lock is dropped.
    pub fn close(end: PipeEnd) {
        let gone = with_pipes(|pipes| {
            let instance = pipes.instance(end.instance);
            instance.objects -= 1;
            if instance.objects == 0 {
                debug_assert!(
                    instance.pipe.is_unused(),
                    "a pipe instance goes once both its ends are cleaned up"
                );
                pipes.instances[usize::from(end.instance)].take()
            } else {
                None
            }
        });
        drop(gone);
    }

    /// At quiescence (no process left, so no file object): any instance still in the pool is a
    /// leak, dropped with its rings. How many there were.
    pub fn sweep() -> usize {
        let mut leaked = 0;
        while let Some(instance) = with_pipes(|pipes| {
            pipes
                .instances
                .iter_mut()
                .find(|instance| instance.is_some())
                .and_then(Option::take)
        }) {
            drop(instance);
            leaked += 1;
        }
        leaked
    }

    /// A read through `end` of up to `length` bytes into the caller's `buffer`: whatever is queued,
    /// at least a byte, waiting for some while the writing end is open (see
    /// [`npfs::Pipe::read`]). The count moved; a fault copying out is STATUS_ACCESS_VIOLATION (the
    /// bytes taken are lost, as the caller's buffer refused them).
    pub fn read(end: PipeEnd, buffer: UserAddr, length: u32) -> Result<u32, NtStatus> {
        let waiter = waiter(end.end.reads(), Role::Reader);
        let mut chunk = [0u8; CHUNK];
        let mut moved = 0u32;
        loop {
            let take = (length - moved).min(CHUNK as u32) as usize;
            // The first chunk may wait; the rest take what more is there.
            let first = (moved == 0).then_some(waiter);
            let answer =
                with_pipes(|pipes| pipes.pipe(end).read(end.end, &mut chunk[..take], first));
            wake(end.instance, answer.wake);
            match answer.outcome {
                ReadOutcome::Moved(count) => {
                    if count > 0 {
                        write_user(buffer.raw().wrapping_add(moved), &chunk[..count as usize])
                            .map_err(|_| STATUS_ACCESS_VIOLATION)?;
                    }
                    moved += count;
                    if (count as usize) < take || moved == length {
                        return Ok(moved);
                    }
                }
                ReadOutcome::Wait => {
                    let status = wait_as(end.instance, waiter);
                    if status != STATUS_SUCCESS {
                        with_pipes(|pipes| pipes.pipe(end).cancel_read(end.end, waiter));
                        return Err(status);
                    }
                }
                ReadOutcome::Failed(error) => return Err(error.status()),
            }
        }
    }

    /// A write through `end` of the caller's `length` bytes at `buffer`: queued, fed a chunk at a
    /// time as the queue has room, done once its charge fits the quota (see
    /// [`npfs::Pipe::write`]). The count written (all of them); a fault copying in is
    /// STATUS_ACCESS_VIOLATION, the write cancelled.
    pub fn write(end: PipeEnd, buffer: UserAddr, length: u32) -> Result<u32, NtStatus> {
        let waiter = waiter(end.end.writes(), Role::Writer);
        let answer = with_pipes(|pipes| pipes.pipe(end).write(end.end, length, waiter));
        wake(end.instance, answer.wake);
        let mut step = answer.outcome;
        let mut chunk = [0u8; CHUNK];
        loop {
            let ticket = match step {
                WriteStep::Done(count) => return Ok(count),
                WriteStep::Failed(error) => return Err(error.status()),
                WriteStep::Feed {
                    ticket,
                    offset,
                    room,
                } => {
                    let count = room.min(CHUNK as u32) as usize;
                    let copied = read_user(buffer.raw().wrapping_add(offset), &mut chunk[..count]);
                    if copied.is_err() {
                        let woken = with_pipes(|pipes| pipes.pipe(end).cancel_write(ticket));
                        wake(end.instance, woken);
                        return Err(STATUS_ACCESS_VIOLATION);
                    }
                    let answer = with_pipes(|pipes| pipes.pipe(end).feed(ticket, &chunk[..count]));
                    wake(end.instance, answer.wake);
                    step = answer.outcome;
                    continue;
                }
                WriteStep::Wait(ticket) => ticket,
            };
            let status = wait_as(end.instance, waiter);
            if status != STATUS_SUCCESS {
                let woken = with_pipes(|pipes| pipes.pipe(end).cancel_write(ticket));
                wake(end.instance, woken);
                return Err(status);
            }
            let answer = with_pipes(|pipes| pipes.pipe(end).feed(ticket, &[]));
            wake(end.instance, answer.wake);
            step = answer.outcome;
        }
    }

    /// A flush through `end`: done once the reader has taken everything this end wrote (or is
    /// gone), waiting until then (see [`npfs::Pipe::flush`]).
    pub fn flush(end: PipeEnd) -> Result<(), NtStatus> {
        let waiter = waiter(end.end.writes(), Role::Flusher);
        loop {
            let answer = with_pipes(|pipes| pipes.pipe(end).flush(end.end, waiter));
            wake(end.instance, answer.wake);
            match answer.outcome {
                FlushOutcome::Done => return Ok(()),
                FlushOutcome::Failed(error) => return Err(error.status()),
                FlushOutcome::Wait => {
                    let status = wait_as(end.instance, waiter);
                    if status != STATUS_SUCCESS {
                        with_pipes(|pipes| pipes.pipe(end).cancel_flush(end.end, waiter));
                        return Err(status);
                    }
                }
            }
        }
    }

    /// FSCTL_PIPE_PEEK through `end` into the caller's `output` of `length` bytes:
    /// FILE_PIPE_PEEK_BUFFER's header, then as many of the unread bytes as fit, none consumed
    /// (see [`npfs::Pipe::peek`]). The status (STATUS_BUFFER_OVERFLOW when not every byte fits)
    /// and the bytes written; a buffer shorter than the header is STATUS_INVALID_PARAMETER, nothing
    /// written. The header is the first chunk's, and the bytes after it at most what it counts.
    pub fn peek(end: PipeEnd, output: UserAddr, length: u32) -> Result<(NtStatus, u32), NtStatus> {
        let room = npfs::peek_data_room(length).map_err(PipeError::status)?;
        let mut chunk = [0u8; CHUNK];
        let mut header = None;
        let mut copied = 0u32;
        loop {
            let take = (room - copied).min(CHUNK as u32) as usize;
            let peeked =
                with_pipes(|pipes| pipes.pipe(end).peek(end.end, copied, &mut chunk[..take]))
                    .map_err(PipeError::status)?;
            let header = *header.get_or_insert(peeked.header);
            let count = peeked.copied.min(header.read_data_available - copied);
            let at = output.offset(npfs::PEEK_HEADER + copied);
            at.write(&chunk[..count as usize])
                .map_err(|_| STATUS_ACCESS_VIOLATION)?;
            copied += count;
            if count == 0 || copied == room || copied == header.read_data_available {
                let status = npfs::Peeked { header, copied }.status(room);
                output
                    .cast::<npfs::FilePipePeekBuffer>()
                    .write(header)
                    .map_err(|_| STATUS_ACCESS_VIOLATION)?;
                return Ok((status, npfs::PEEK_HEADER + copied));
            }
        }
    }

    /// FILE_STANDARD_INFORMATION's sizes for `end`'s pipe: the allocation, both queues' quotas as
    /// the create gave them, and the end of file, every byte in the pipe (the capture's GetFileSize
    /// answers 5 through either end of a pipe holding 5).
    pub fn sizes(end: PipeEnd) -> (u64, u64) {
        with_pipes(|pipes| {
            let instance = pipes.instance(end.instance);
            let bytes = instance.pipe.queue(Direction::Inbound).available()
                + instance.pipe.queue(Direction::Outbound).available();
            let allocation = u64::from(instance.quotas[0]) + u64::from(instance.quotas[1]);
            (allocation, u64::from(bytes))
        })
    }

    /// `end`'s pipe's name, into `out` (as much of it as fits: [`MAX_PIPE_NAME`] units hold any):
    /// the units written.
    pub fn name_of(end: PipeEnd, out: &mut [u16]) -> usize {
        with_pipes(|pipes| {
            let units = pipes.instance(end.instance).name.units();
            let count = units.len().min(out.len());
            out[..count].copy_from_slice(&units[..count]);
            count
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::file::rights::{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_WRITE_ATTRIBUTES};

    fn name(text: &str) -> PipeName {
        let units: std::vec::Vec<u16> = text.encode_utf16().collect();
        PipeName::new(&units).unwrap()
    }

    /// Names compare as Windows' pipe names do: ASCII letters in either case, the rest exactly; a
    /// name past the limit is none.
    #[test]
    fn names_compare_case_insensitively() {
        assert!(name("Win32Pipes.0000001c.00000001").matches(&name("WIN32PIPES.0000001C.00000001")));
        assert!(!name("a").matches(&name("ab")));
        assert!(!name("\u{e9}").matches(&name("\u{c9}")), "only ASCII folds");
        assert!(PipeName::new(&[b'x' as u16; MAX_PIPE_NAME]).is_some());
        assert!(PipeName::new(&[b'x' as u16; MAX_PIPE_NAME + 1]).is_none());
    }

    /// Each queue's three roles name six distinct events.
    #[test]
    fn every_role_has_its_event() {
        let mut seen = std::vec::Vec::new();
        for direction in [Direction::Inbound, Direction::Outbound] {
            for role in [Role::Reader, Role::Writer, Role::Flusher] {
                let Waiter(index) = waiter(direction, role);
                assert!(index < ROLES && !seen.contains(&index));
                seen.push(index);
            }
        }
    }

    /// The default for 0, the create's own up to the ceiling, the ceiling past it.
    #[test]
    fn quotas_are_the_create_s_within_the_ceiling() {
        assert_eq!(quota(0), 4096);
        assert_eq!(quota(1), 1);
        assert_eq!(quota(65536), 65536);
        assert_eq!(quota(MAX_QUOTA + 1), MAX_QUOTA);
        assert_eq!(quota(u32::MAX), MAX_QUOTA);
    }

    /// CreatePipe's read end (a server granted read, sharing both ways) serves the inbound queue
    /// alone; its write end may open it to write, not to read through an outbound queue it
    /// cannot have.
    #[test]
    fn an_anonymous_pipe_serves_its_inbound_queue() {
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
        assert_eq!(
            served(share, FILE_GENERIC_READ | FILE_WRITE_ATTRIBUTES),
            [true, false]
        );
        assert_eq!(served(FILE_SHARE_READ, FILE_GENERIC_READ), [false, false]);
        assert_eq!(
            served(share, FILE_GENERIC_READ | FILE_GENERIC_WRITE),
            [true, true]
        );
        assert!(client_allowed(share, FILE_GENERIC_WRITE));
        assert!(!client_allowed(FILE_SHARE_READ, FILE_GENERIC_WRITE));
        assert!(!client_allowed(FILE_SHARE_WRITE, FILE_GENERIC_READ));
        assert!(client_allowed(FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES));
    }
}

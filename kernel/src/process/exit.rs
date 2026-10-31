//! The end of a thread and of its process, as decisions: how a thread's end routes, what the
//! process's end reports on COM1, and what the kernel does once the process is torn down.
//!
//! One exit path serves every boot. A thread's return ends the running thread, and the last live
//! thread's end is the process's end. NtTerminateProcess and a fault end the process outright: the
//! process's end is decided, every other thread is terminated — each runs its own exit, at its
//! next window for a kernel APC (a thread inside a critical region, holding the volume and its
//! drive, at the region's end) — and the calling thread ends; whichever thread exits last ends the
//! process with the end decided. The process's end is then reported, and the idle thread tears the
//! process down — after which a suite (a boot of several programs, each one leg) starts its next
//! leg or prints its summary, and a one-process boot rests.

use core::fmt;

/// A process-ending fault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    /// The CPU exception vector.
    pub vector: u32,
    /// The NTSTATUS the fault raises (see [`fault_status`]): the process's exit code, as an
    /// unhandled exception's code is on Windows.
    pub status: u32,
    /// Whether the fault was raised inside the kernel's copy of user memory (a bad user pointer
    /// passed to a service) rather than by user code itself; either way it is the process's.
    pub in_user_copy: bool,
}

/// The vector a raised exception's end reports: it came from RaiseException, not a CPU trap.
pub const RAISED_VECTOR: u32 = u32::MAX;

/// The exception codes the faults raise (the documented NTSTATUS values).
pub mod status {
    pub const ACCESS_VIOLATION: u32 = 0xC000_0005;
    pub const ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
    pub const ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000_008C;
    pub const FLOAT_INVALID_OPERATION: u32 = 0xC000_0090;
    pub const INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
    pub const INTEGER_OVERFLOW: u32 = 0xC000_0095;
    pub const PRIVILEGED_INSTRUCTION: u32 = 0xC000_0096;
    /// Raised when the stack's guard page cannot grow it (with only the reservation's
    /// never-committed bottom page left).
    pub const STACK_OVERFLOW: u32 = 0xC000_00FD;
    pub const FLOAT_MULTIPLE_TRAPS: u32 = 0xC000_02B5;
    /// A guard page fired outside the running thread's stack (its access raises this, once).
    pub const GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;
    pub const DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
    pub const BREAKPOINT: u32 = 0x8000_0003;
    pub const SINGLE_STEP: u32 = 0x8000_0004;
}

/// The exception code a user-mode trap raises, as Windows 2000's trap handlers map them. A general
/// protection fault is a privileged instruction when the faulting instruction is one (`privileged`,
/// see [`is_privileged_instruction`]) and an access violation otherwise; a page fault is an access
/// violation (the stack overflow is decided before this, from the stack's own bookkeeping).
pub fn fault_status(vector: u32, privileged: bool) -> u32 {
    match vector {
        0 => status::INTEGER_DIVIDE_BY_ZERO,
        1 => status::SINGLE_STEP,
        3 => status::BREAKPOINT,
        4 => status::INTEGER_OVERFLOW,
        5 => status::ARRAY_BOUNDS_EXCEEDED,
        6 => status::ILLEGAL_INSTRUCTION,
        13 if privileged => status::PRIVILEGED_INSTRUCTION,
        16 => status::FLOAT_INVALID_OPERATION,
        17 => status::DATATYPE_MISALIGNMENT,
        19 => status::FLOAT_MULTIPLE_TRAPS,
        _ => status::ACCESS_VIOLATION,
    }
}

/// Whether the instruction starting at `code` (its first bytes) is one ring 3 may not execute: the
/// I/O instructions (IOPL is 0), HLT, CLI/STI, and the system-register group. Prefixes are skipped.
pub fn is_privileged_instruction(code: &[u8]) -> bool {
    const PREFIXES: [u8; 11] = [
        0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3,
    ];
    let mut bytes = code
        .iter()
        .copied()
        .skip_while(|byte| PREFIXES.contains(byte));
    match bytes.next() {
        // in/out imm8, in/out dx, ins/outs, hlt, cli, sti.
        Some(0xE4..=0xE7 | 0xEC..=0xEF | 0x6C..=0x6F | 0xF4 | 0xFA | 0xFB) => true,
        // lgdt/lidt/lmsw/invlpg (0F 01 /2 /3 /6 /7), lldt/ltr (0F 00 /2 /3), clts, invd, wbinvd,
        // mov to and from control and debug registers, wrmsr, rdmsr.
        Some(0x0F) => match bytes.next() {
            Some(0x01) => matches!(
                bytes.next().map(|modrm| (modrm >> 3) & 7),
                Some(2 | 3 | 6 | 7)
            ),
            Some(0x00) => matches!(bytes.next().map(|modrm| (modrm >> 3) & 7), Some(2 | 3)),
            Some(0x06 | 0x08 | 0x09 | 0x20..=0x23 | 0x30 | 0x32) => true,
            _ => false,
        },
        _ => false,
    }
}

/// Why a thread ends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreadEnd {
    /// The thread's own end (NtTerminateThread: kernel32's ExitThread, a start routine's return),
    /// with the exit status.
    Exit(i32),
    /// NtTerminateProcess: the process ends with this exit code, all its threads with it.
    ExitProcess(u32),
    /// A fault raised on the thread's behalf.
    Fault(Fault),
    /// Another thread terminated this one (its exit APC ran), with this exit status.
    Terminated(u32),
}

impl ThreadEnd {
    /// The thread's exit status, for GetExitCodeThread: its own, or the process's end.
    pub fn status(self) -> u32 {
        match self {
            ThreadEnd::Exit(status) => status as u32,
            ThreadEnd::ExitProcess(code) | ThreadEnd::Terminated(code) => code,
            ThreadEnd::Fault(fault) => fault.status,
        }
    }

    /// The end this thread's end decides for its whole process, whatever lives on:
    /// NtTerminateProcess's and a fault's — every other thread is terminated, and the last to
    /// exit ends the process with it. None for an end of the thread alone.
    pub fn ends_process(self) -> Option<ProcessEnd> {
        match self {
            ThreadEnd::ExitProcess(code) => Some(ProcessEnd::Exited(code)),
            ThreadEnd::Fault(fault) => Some(ProcessEnd::Faulted(fault)),
            ThreadEnd::Exit(_) | ThreadEnd::Terminated(_) => None,
        }
    }

    /// The process's end when this thread is its last, `started` saying whether it reached user
    /// mode, and `decided` the end decided for the process earlier (an NtTerminateProcess's or a
    /// fault's, which the first to decide holds). Windows 2000's process exit status is its last
    /// thread's (LastThreadExitStatus): the last thread's own status is the exit code, whatever
    /// was decided before it — the spawn fixture's lastcode block: NtTerminateProcess(NULL, 3),
    /// then the caller's ExitThread(4), ends the process with 4. A fault, decided earlier or this
    /// thread's own, ends it as a fault (its exception code). A thread that never reached user mode
    /// ends it with the end decided for it, when there is one: a child terminated before any of its
    /// threads ran exits with 0, as the spawn fixture's capture shows.
    pub fn last_thread_end(self, decided: Option<ProcessEnd>, started: bool) -> ProcessEnd {
        match (decided, self) {
            (Some(ProcessEnd::Faulted(fault)), _) | (_, ThreadEnd::Fault(fault)) => {
                ProcessEnd::Faulted(fault)
            }
            (Some(decided), _) if !started => decided,
            _ => ProcessEnd::Exited(self.status()),
        }
    }
}

/// Why a process ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessEnd {
    /// Its last thread exited with this code.
    Exited(u32),
    /// A fault in one of its threads ended it.
    Faulted(Fault),
}

impl ProcessEnd {
    /// The process's exit code (GetExitCodeProcess's answer, and its object's on signaling): the
    /// exit code, or the fault's exception code, as an unhandled exception's is on Windows.
    pub fn exit_status(self) -> u32 {
        match self {
            ProcessEnd::Exited(code) => code,
            ProcessEnd::Faulted(fault) => fault.status,
        }
    }
}

/// Who a process's end reports as: the boot's one program, a leg of a suite, or a child — the
/// name borrowed from the process's record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Identity<'a> {
    /// The one program of a one-process boot (or of a boot no runner drives: the fault tests').
    Lone,
    /// A suite's leg: its 1-based index and its image's name.
    Leg(u32, &'a str),
    /// A process another process started, not one the boot's command line lists: its process id
    /// and its image's name.
    Child(u32, &'a str),
}

/// The identity a process reports its end under: `leg` its leg of the boot's `legs` programs
/// (none for a child), `id` its process id, `name` its image's name. A leg of a boot of one
/// program — or of none, a boot the runner does not drive — is the lone program.
pub fn identity(leg: Option<u32>, legs: u32, id: u32, name: &str) -> Identity<'_> {
    match leg {
        None => Identity::Child(id, name),
        Some(index) if legs > 1 => Identity::Leg(index, name),
        Some(_) => Identity::Lone,
    }
}

/// The process-end report line: the one-process boot's form, the suite's with the leg's index and
/// name, or a child's with its process id and name.
pub struct EndReport<'a> {
    pub end: ProcessEnd,
    pub identity: Identity<'a>,
}

impl fmt::Display for EndReport<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (prefix, number, name) = match self.identity {
            Identity::Lone => return self.fmt_lone(out),
            Identity::Leg(index, name) => ("process", index, name),
            Identity::Child(id, name) => ("child process", id, name),
        };
        match self.end {
            ProcessEnd::Exited(code) => write!(
                out,
                "F2K: {prefix} {number} ({name}) exited normally (exit code={code})"
            ),
            ProcessEnd::Faulted(fault) => write!(
                out,
                "F2K: {prefix} {number} ({name}) ended by fault (vector {}, exit code={})",
                fault.vector, fault.status
            ),
        }
    }
}

impl EndReport<'_> {
    /// The one-process boot's form, which names the kind of fault and that the boot halts.
    fn fmt_lone(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.end {
            ProcessEnd::Exited(code) => {
                write!(out, "F2K: user process exited normally (exit code={code})")
            }
            ProcessEnd::Faulted(fault) if fault.in_user_copy => write!(
                out,
                "F2K: user process ended by fault (bad user argument pointer, exit code={}); \
                 halting",
                fault.status
            ),
            ProcessEnd::Faulted(fault) if fault.vector == RAISED_VECTOR => write!(
                out,
                "F2K: user process ended by fault (raised exception, exit code={}); halting",
                fault.status
            ),
            ProcessEnd::Faulted(fault) => write!(
                out,
                "F2K: user process ended by fault (vector {}, exit code={}); halting",
                fault.vector, fault.status
            ),
        }
    }
}

/// What a teardown audit found wrong: the frame database's available count against the post-boot
/// baseline, and whether its own structure audit held.
#[cfg(any(test, target_arch = "x86"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leak {
    /// Free frames after the teardown.
    pub available: u32,
    /// Free frames before the process started.
    pub baseline: u32,
    /// Whether the frame database's structure audit held.
    pub frames_audit_ok: bool,
}

/// The teardown audit line every process's end is followed by: the frame database back at the
/// post-boot baseline, or what is off. A suite leg's line names the leg's index; a one-process
/// boot's names none.
#[cfg(any(test, target_arch = "x86"))]
pub struct AuditReport {
    pub index: Option<u32>,
    pub audit: Result<(), Leak>,
}

#[cfg(any(test, target_arch = "x86"))]
impl fmt::Display for AuditReport {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("F2K: ")?;
        if let Some(index) = self.index {
            write!(out, "process {index} ")?;
        }
        match self.audit {
            Ok(()) => out.write_str("teardown audit: frame database ok"),
            Err(leak) => write!(
                out,
                "teardown audit FAILED: {} frames available, {} before the process (frame database {})",
                leak.available,
                leak.baseline,
                if leak.frames_audit_ok { "ok" } else { "corrupt" }
            ),
        }
    }
}

/// A torn-down process whose teardown audit line waits for the next quiescent point: its leg's
/// index (none on a one-process boot), how it ended, and the frame database's structure audit
/// taken at its reap (it holds at any time; the comparison with the post-boot baseline does not).
#[cfg(any(test, target_arch = "x86"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reaped {
    pub index: Option<u32>,
    pub end: ProcessEnd,
    /// Whether the frame database's structure audit held at the reap.
    pub frames_audit_ok: bool,
}

/// The teardown audits deferred to the next quiescent point, in reap order.
///
/// The frame database stands at the post-boot baseline only when no process holds a frame, so the
/// comparison is made at quiescence — once no process remains that has not been torn down — and
/// every process torn down since the last quiescent point shares its verdict: while processes
/// overlap, no frame count tells whose a missing frame was. A boot that runs one process at a time
/// reaches quiescence at every reap, and reports each process's line there, as it always did.
///
/// The ledger holds as many audits as there can be processes: a boot's legs start one after
/// another, each at the quiescent point after the last's reap, or all at once (children of a
/// process report no audit line).
#[cfg(any(test, target_arch = "x86"))]
pub struct DeferredAudits {
    reaped: [Option<Reaped>; crate::process::MAX_PROCESSES],
}

#[cfg(any(test, target_arch = "x86"))]
impl DeferredAudits {
    /// None deferred.
    pub const fn new() -> Self {
        DeferredAudits {
            reaped: [None; crate::process::MAX_PROCESSES],
        }
    }

    /// Defer `reaped`'s audit to the next quiescent point.
    ///
    /// # Panics
    ///
    /// More audits wait than there can be processes (see the type's notes).
    pub fn defer(&mut self, reaped: Reaped) {
        let free = self
            .reaped
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("a deferred audit per process");
        *free = Some(reaped);
    }

    /// The quiescent point: with `available` free frames against the post-boot `baseline`, hand
    /// each deferred audit and its verdict to `report`, in reap order, and forget them.
    pub fn settle(
        &mut self,
        available: u32,
        baseline: u32,
        mut report: impl FnMut(Reaped, Result<(), Leak>),
    ) {
        for slot in self.reaped.iter_mut() {
            let Some(reaped) = slot.take() else {
                break;
            };
            let verdict = if reaped.frames_audit_ok && available == baseline {
                Ok(())
            } else {
                Err(Leak {
                    available,
                    baseline,
                    frames_audit_ok: reaped.frames_audit_ok,
                })
            };
            report(reaped, verdict);
        }
    }
}

/// What follows a suite leg's teardown.
#[cfg(any(test, target_arch = "x86"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AfterLeg {
    /// The next leg (1-based).
    Next(u32),
    /// The last leg finished: print the summary, then rest.
    Summary,
}

/// The decision after leg `index` (1-based) of `legs` is torn down: the next leg until the last,
/// then the summary.
#[cfg(any(test, target_arch = "x86"))]
pub fn after_leg(index: u32, legs: u32) -> AfterLeg {
    assert!(index >= 1 && index <= legs, "suite leg {index} of {legs}");
    if index < legs {
        AfterLeg::Next(index + 1)
    } else {
        AfterLeg::Summary
    }
}

/// The suite's running counts, and its summary line.
#[cfg(any(test, target_arch = "x86"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SuiteTally {
    pub run: u32,
    pub faulted: u32,
    pub leaks: u32,
}

#[cfg(any(test, target_arch = "x86"))]
impl SuiteTally {
    /// Nothing run yet.
    pub const fn new() -> Self {
        SuiteTally {
            run: 0,
            faulted: 0,
            leaks: 0,
        }
    }

    /// Count one torn-down leg: how it ended, and whether its audit leaked.
    pub fn record(&mut self, end: ProcessEnd, audit_ok: bool) {
        self.run += 1;
        if matches!(end, ProcessEnd::Faulted(_)) {
            self.faulted += 1;
        }
        if !audit_ok {
            self.leaks += 1;
        }
    }
}

#[cfg(any(test, target_arch = "x86"))]
impl fmt::Display for SuiteTally {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "F2K: process suite complete: {} run, {} faulted, {} leaks",
            self.run, self.faulted, self.leaks
        )
    }
}

/// What follows a quiescent point (see [`Suite::settle`]).
#[cfg(any(test, target_arch = "x86"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AtQuiescence {
    /// Start this leg (1-based): the one after the last leg reaped.
    Start(u32),
    /// Every leg of the suite is reaped and its audit line printed: print this summary, then rest.
    Summary(SuiteTally),
    /// Nothing follows: a one-process boot's program has ended.
    Rest,
}

/// The runner's account of the boot's programs, kept by the reaped process's own leg — never by
/// which leg was started last, since legs may overlap. A leg's reap defers its audit line and names
/// the leg that follows it (unless that one has started already); at the next quiescent point the
/// deferred lines are reported, each leg counted in the tally, and the next leg starts — or, once
/// every leg is reaped, the summary prints. A child (a process with no leg) counts for nothing: no
/// audit line, no tally entry, no next leg; its reap may still be the quiescent point that settles
/// its parent's line.
///
/// Starting the next leg at the quiescent point rather than at its predecessor's reap keeps each
/// leg's lines — its children's ends, its audit line — before the next leg's start line, where the
/// test harness splits the log. A boot that runs one process at a time reaches quiescence at every
/// reap, so the next leg starts at the reap, as it always did.
#[cfg(any(test, target_arch = "x86"))]
pub struct Suite {
    /// How many programs the boot runs: 0 until the runner starts (a boot it does not drive).
    legs: u32,
    /// The highest leg started: a leg already running is never named to start again.
    started: u32,
    /// How many legs have been reaped.
    reaped: u32,
    /// The leg to start at the next quiescent point.
    next: Option<u32>,
    /// The legs whose audit lines have been printed, counted.
    tally: SuiteTally,
    /// The audit lines waiting for the next quiescent point.
    audits: DeferredAudits,
}

#[cfg(any(test, target_arch = "x86"))]
impl Suite {
    /// No programs yet.
    pub const fn new() -> Self {
        Suite {
            legs: 0,
            started: 0,
            reaped: 0,
            next: None,
            tally: SuiteTally::new(),
            audits: DeferredAudits::new(),
        }
    }

    /// The boot runs `legs` programs.
    pub fn begin(&mut self, legs: u32) {
        self.legs = legs;
    }

    /// How many programs the boot runs: 0 until the runner starts (a boot it does not drive).
    pub fn legs(&self) -> u32 {
        self.legs
    }

    /// Leg `index` has started.
    pub fn started(&mut self, index: u32) {
        self.started = self.started.max(index);
    }

    /// A process torn down: `leg` its leg (none for a child), `end` how it ended, and the frame
    /// database's structure audit taken at its reap. A leg's audit line is deferred to the next
    /// quiescent point, and on a suite the leg after it is named to start there (see
    /// [`after_leg`]) unless it has started already (legs started together).
    pub fn reaped(&mut self, leg: Option<u32>, end: ProcessEnd, frames_audit_ok: bool) {
        let Some(index) = leg else {
            return;
        };
        self.reaped += 1;
        let suite = self.legs > 1;
        self.audits.defer(Reaped {
            index: suite.then_some(index),
            end,
            frames_audit_ok,
        });
        if suite {
            match after_leg(index, self.legs) {
                AfterLeg::Next(next) if next > self.started => self.next = Some(next),
                _ => {}
            }
        }
    }

    /// The quiescent point: with `available` free frames against the post-boot `baseline`, hand
    /// each deferred audit line to `report`, in reap order, counting each leg in the tally on a
    /// suite; then say what follows.
    pub fn settle(
        &mut self,
        available: u32,
        baseline: u32,
        mut report: impl FnMut(AuditReport),
    ) -> AtQuiescence {
        let suite = self.legs > 1;
        let tally = &mut self.tally;
        self.audits.settle(available, baseline, |reaped, audit| {
            report(AuditReport {
                index: reaped.index,
                audit,
            });
            if suite {
                tally.record(reaped.end, audit.is_ok());
            }
        });
        if let Some(next) = self.next.take() {
            AtQuiescence::Start(next)
        } else if suite && self.reaped == self.legs {
            AtQuiescence::Summary(self.tally)
        } else {
            AtQuiescence::Rest
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_FAULT: Fault = Fault {
        vector: 14,
        status: status::ACCESS_VIOLATION,
        in_user_copy: false,
    };
    const COPY_FAULT: Fault = Fault {
        vector: 14,
        status: status::ACCESS_VIOLATION,
        in_user_copy: true,
    };

    /// A process's exit code: its last thread's or ExitProcess's code, or the ending fault's
    /// exception code (what its object signals with).
    #[test]
    fn a_process_exits_with_its_code_or_its_fault() {
        assert_eq!(ProcessEnd::Exited(3).exit_status(), 3);
        assert_eq!(ProcessEnd::Faulted(PAGE_FAULT).exit_status(), 0xC000_0005);
    }

    /// The trap codes, as Windows 2000 raises them (the bare fixture's capture: an access
    /// violation 0xC0000005, divide by zero 0xC0000094, ud2 0xC000001D, int3 0x80000003, hlt/cli/in
    /// 0xC0000096, into 0xC0000095).
    #[test]
    fn faults_raise_their_exception_codes() {
        assert_eq!(fault_status(14, false), 0xC000_0005);
        assert_eq!(fault_status(0, false), 0xC000_0094);
        assert_eq!(fault_status(6, false), 0xC000_001D);
        assert_eq!(fault_status(3, false), 0x8000_0003);
        assert_eq!(fault_status(13, true), 0xC000_0096);
        assert_eq!(fault_status(13, false), 0xC000_0005);
        assert_eq!(fault_status(4, false), 0xC000_0095);
        assert_eq!(status::STACK_OVERFLOW, 0xC000_00FD);
    }

    /// The privileged-instruction decode: the fixture's hlt, cli and `in al, dx`, the rest of the
    /// group, prefixes skipped; ordinary instructions are not.
    #[test]
    fn privileged_instructions_are_recognized() {
        for code in [
            &[0xF4][..],
            &[0xFA],
            &[0xFB],
            &[0xEC],
            &[0xE4, 0x60],
            &[0xEE],
            &[0x66, 0xED],
            &[0xF3, 0x6C],
            &[0x0F, 0x01, 0x15],
            &[0x0F, 0x01, 0x38],
            &[0x0F, 0x00, 0x18],
            &[0x0F, 0x20, 0xC0],
            &[0x0F, 0x22, 0xD8],
            &[0x0F, 0x30],
            &[0x0F, 0x06],
        ] {
            assert!(is_privileged_instruction(code), "{code:02X?}");
        }
        for code in [
            &[0x8B, 0x00][..],
            &[0xCD, 0x2E],
            &[0x0F, 0x01, 0x05],
            &[0x0F, 0x0B],
            &[0x0F, 0xA2],
            &[0x66],
            &[],
        ] {
            assert!(!is_privileged_instruction(code), "{code:02X?}");
        }
    }

    /// A thread's return ends only its thread: it decides nothing for the process, and as the last
    /// thread it ends the process with its status as the exit code. It never terminates anyone
    /// else.
    #[test]
    fn a_return_ends_the_process_only_from_the_last_thread() {
        assert_eq!(ThreadEnd::Exit(0).ends_process(), None);
        assert_eq!(ThreadEnd::Exit(7).status(), 7);
        assert_eq!(
            ThreadEnd::Exit(7).last_thread_end(None, true),
            ProcessEnd::Exited(7)
        );
        // The status reports as the unsigned code the exit line has always printed.
        assert_eq!(
            ThreadEnd::Exit(0xC000_001Cu32 as i32).last_thread_end(None, true),
            ProcessEnd::Exited(3_221_225_500)
        );
    }

    /// NtTerminateProcess ends the process from any thread, with its own code: the code is the
    /// caller's, never a survivor's.
    #[test]
    fn the_exit_service_ends_the_process_from_any_thread() {
        assert_eq!(
            ThreadEnd::ExitProcess(1).ends_process(),
            Some(ProcessEnd::Exited(1))
        );
        assert_eq!(ThreadEnd::ExitProcess(1).status(), 1);
        assert_eq!(
            ThreadEnd::ExitProcess(0).last_thread_end(None, true),
            ProcessEnd::Exited(0)
        );
    }

    /// A fault ends the process from any thread, and the end is the fault; the thread's status is
    /// its exception code.
    #[test]
    fn a_fault_ends_the_process_from_any_thread() {
        assert_eq!(
            ThreadEnd::Fault(PAGE_FAULT).ends_process(),
            Some(ProcessEnd::Faulted(PAGE_FAULT))
        );
        assert_eq!(ThreadEnd::Fault(PAGE_FAULT).status(), 0xC000_0005);
        assert_eq!(
            ThreadEnd::Fault(COPY_FAULT).last_thread_end(None, true),
            ProcessEnd::Faulted(COPY_FAULT)
        );
    }

    /// The one-process boot's end lines, byte for byte: the exit, the user fault, and the
    /// user-copy fault.
    #[test]
    fn the_one_process_report_lines() {
        let line = |end| {
            EndReport {
                end,
                identity: Identity::Lone,
            }
            .to_string()
        };
        assert_eq!(
            line(ProcessEnd::Exited(0)),
            "F2K: user process exited normally (exit code=0)"
        );
        assert_eq!(
            line(ProcessEnd::Exited(3_221_225_500)),
            "F2K: user process exited normally (exit code=3221225500)"
        );
        assert_eq!(
            line(ProcessEnd::Faulted(PAGE_FAULT)),
            "F2K: user process ended by fault (vector 14, exit code=3221225477); halting"
        );
        assert_eq!(
            line(ProcessEnd::Faulted(COPY_FAULT)),
            "F2K: user process ended by fault (bad user argument pointer, exit code=3221225477); \
             halting"
        );
    }

    /// The suite's per-leg lines, byte for byte: both end forms carry the index and name, and a
    /// user-copy fault reports its vector like any other.
    #[test]
    fn the_suite_report_lines() {
        let line = |end, (index, name)| {
            EndReport {
                end,
                identity: Identity::Leg(index, name),
            }
            .to_string()
        };
        assert_eq!(
            line(ProcessEnd::Exited(0), (1, "exit0")),
            "F2K: process 1 (exit0) exited normally (exit code=0)"
        );
        assert_eq!(
            line(ProcessEnd::Faulted(PAGE_FAULT), (5, "bare")),
            "F2K: process 5 (bare) ended by fault (vector 14, exit code=3221225477)"
        );
        assert_eq!(
            line(ProcessEnd::Faulted(COPY_FAULT), (2, "ret0")),
            "F2K: process 2 (ret0) ended by fault (vector 14, exit code=3221225477)"
        );
        assert_eq!(
            AuditReport {
                index: Some(3),
                audit: Ok(())
            }
            .to_string(),
            "F2K: process 3 teardown audit: frame database ok"
        );
        let leak = Leak {
            available: 1234,
            baseline: 1240,
            frames_audit_ok: true,
        };
        assert_eq!(
            AuditReport {
                index: Some(4),
                audit: Err(leak)
            }
            .to_string(),
            "F2K: process 4 teardown audit FAILED: 1234 frames available, 1240 before the process \
             (frame database ok)"
        );
        // A one-process boot's line names no leg.
        assert_eq!(
            AuditReport {
                index: None,
                audit: Ok(())
            }
            .to_string(),
            "F2K: teardown audit: frame database ok"
        );
        assert_eq!(
            AuditReport {
                index: None,
                audit: Err(Leak {
                    frames_audit_ok: false,
                    ..leak
                })
            }
            .to_string(),
            "F2K: teardown audit FAILED: 1234 frames available, 1240 before the process \
             (frame database corrupt)"
        );
    }

    /// A reaped process as the deferred-audit tests build it.
    fn reaped(index: u32, end: ProcessEnd) -> Reaped {
        Reaped {
            index: Some(index),
            end,
            frames_audit_ok: true,
        }
    }

    /// The deferred audits settled at quiescence: each in reap order with its own structure
    /// audits, all sharing the baseline comparison; settled, the ledger is empty.
    #[test]
    fn deferred_audits_settle_at_quiescence() {
        let mut audits = DeferredAudits::new();
        let first = Reaped {
            frames_audit_ok: false,
            ..reaped(1, ProcessEnd::Exited(0))
        };
        audits.defer(first);
        audits.defer(reaped(2, ProcessEnd::Faulted(PAGE_FAULT)));
        let mut lines = Vec::new();
        audits.settle(1240, 1240, |reaped, audit| lines.push((reaped, audit)));
        assert_eq!(
            lines,
            vec![
                (
                    first,
                    Err(Leak {
                        available: 1240,
                        baseline: 1240,
                        frames_audit_ok: false,
                    })
                ),
                (reaped(2, ProcessEnd::Faulted(PAGE_FAULT)), Ok(())),
            ],
            "the structure audits stay each process's own"
        );
        let mut more = 0;
        audits.settle(1240, 1240, |_, _| more += 1);
        assert_eq!(more, 0, "settled once");

        // Frames missing at quiescence: every process since the last quiescent point reports it.
        audits.defer(reaped(3, ProcessEnd::Exited(0)));
        audits.defer(reaped(4, ProcessEnd::Exited(0)));
        let mut lines = Vec::new();
        audits.settle(1238, 1240, |reaped, audit| {
            lines.push(
                AuditReport {
                    index: reaped.index,
                    audit,
                }
                .to_string(),
            )
        });
        assert_eq!(
            lines,
            [3, 4].map(|index| format!(
                "F2K: process {index} teardown audit FAILED: 1238 frames available, 1240 before \
                 the process (frame database ok)"
            ))
        );
    }

    /// A process at a time: every reap is quiescent, and the one deferred line is today's.
    #[test]
    fn a_lone_process_settles_at_its_own_reap() {
        let mut audits = DeferredAudits::new();
        for _ in 0..crate::process::MAX_PROCESSES * 2 {
            audits.defer(Reaped {
                index: None,
                ..reaped(0, ProcessEnd::Exited(0))
            });
            let mut lines = Vec::new();
            audits.settle(1240, 1240, |reaped, audit| {
                lines.push(
                    AuditReport {
                        index: reaped.index,
                        audit,
                    }
                    .to_string(),
                )
            });
            assert_eq!(lines, ["F2K: teardown audit: frame database ok"]);
        }
    }

    /// More audits waiting than there can be processes is a bug, not a lost line.
    #[test]
    #[should_panic(expected = "a deferred audit per process")]
    fn deferred_audits_refuse_past_the_process_pool() {
        let mut audits = DeferredAudits::new();
        for index in 0..=crate::process::MAX_PROCESSES as u32 {
            audits.defer(reaped(index + 1, ProcessEnd::Exited(0)));
        }
    }

    /// After a leg's teardown: the suite walks its legs in order and ends with the summary.
    #[test]
    fn after_leg_walks_the_legs_then_summarizes() {
        for index in 1..6 {
            assert_eq!(after_leg(index, 6), AfterLeg::Next(index + 1));
        }
        assert_eq!(after_leg(6, 6), AfterLeg::Summary);
    }

    /// A leg index outside the suite is a bug, not a wrap.
    #[test]
    #[should_panic(expected = "suite leg 7 of 6")]
    fn after_leg_refuses_a_leg_past_the_suite() {
        after_leg(7, 6);
    }

    /// The tally over the suite's six legs — four exits, one fault, all audits clean — prints the
    /// pinned summary; a leaked audit counts as a leak.
    #[test]
    fn the_suite_tally_and_summary() {
        let mut tally = SuiteTally::new();
        for end in [
            ProcessEnd::Exited(0),
            ProcessEnd::Exited(0),
            ProcessEnd::Exited(0),
            ProcessEnd::Exited(0),
            ProcessEnd::Faulted(PAGE_FAULT),
            ProcessEnd::Exited(0),
        ] {
            tally.record(end, true);
        }
        assert_eq!(
            tally.to_string(),
            "F2K: process suite complete: 6 run, 1 faulted, 0 leaks"
        );
        tally.record(ProcessEnd::Exited(0), false);
        assert_eq!(
            tally,
            SuiteTally {
                run: 7,
                faulted: 1,
                leaks: 1
            }
        );
    }

    /// A terminated thread ends with the status its termination gave it, decides nothing for the
    /// process, and as the last thread ends it with its status as the exit code — or as the fault
    /// decided for it.
    #[test]
    fn a_terminated_thread_ends_the_process_with_its_status() {
        assert_eq!(ThreadEnd::Terminated(5).status(), 5);
        assert_eq!(ThreadEnd::Terminated(5).ends_process(), None);
        assert_eq!(
            ThreadEnd::Terminated(5).last_thread_end(Some(ProcessEnd::Exited(3)), true),
            ProcessEnd::Exited(5)
        );
        assert_eq!(
            ThreadEnd::Terminated(5).last_thread_end(Some(ProcessEnd::Faulted(PAGE_FAULT)), true),
            ProcessEnd::Faulted(PAGE_FAULT)
        );
        assert_eq!(
            ThreadEnd::Terminated(5).last_thread_end(None, true),
            ProcessEnd::Exited(5)
        );
    }

    /// The last thread's status is the process's exit code, whatever was decided before it
    /// (Windows 2000's LastThreadExitStatus: NtTerminateProcess(NULL, 3), then ExitThread(4), exits
    /// with 4); a fault, its own or decided, ends it as the fault; a last thread that never reached
    /// user mode ends it with the end decided for it.
    #[test]
    fn the_last_threads_status_is_the_exit_code() {
        let decided = ProcessEnd::Exited(3);
        assert_eq!(
            ThreadEnd::Exit(4).last_thread_end(Some(decided), true),
            ProcessEnd::Exited(4)
        );
        assert_eq!(
            ThreadEnd::ExitProcess(9).last_thread_end(Some(decided), true),
            ProcessEnd::Exited(9)
        );
        assert_eq!(
            ThreadEnd::Fault(PAGE_FAULT).last_thread_end(Some(decided), true),
            ProcessEnd::Faulted(PAGE_FAULT)
        );
        assert_eq!(
            ThreadEnd::Terminated(0xC000_004B).last_thread_end(Some(ProcessEnd::Exited(0)), false),
            ProcessEnd::Exited(0)
        );
        assert_eq!(
            ThreadEnd::Terminated(0xC000_004B).last_thread_end(None, false),
            ProcessEnd::Exited(0xC000_004B)
        );
    }

    /// Who reports: a leg of a suite by its index, the one program of a one-process boot (or of a
    /// boot no runner drives) as the lone program, and a process with no leg as a child.
    #[test]
    fn a_process_reports_by_its_own_leg() {
        assert_eq!(identity(Some(2), 6, 136, "bare"), Identity::Leg(2, "bare"));
        assert_eq!(identity(Some(1), 1, 136, "exit0"), Identity::Lone);
        assert_eq!(identity(Some(1), 0, 136, "stub"), Identity::Lone);
        for legs in [0, 1, 6] {
            assert_eq!(
                identity(None, legs, 136, "spawn"),
                Identity::Child(136, "spawn")
            );
        }
    }

    /// A child's end lines, byte for byte: its process id in decimal and its image's name, in a
    /// form the harness's batch pattern does not read as a leg's end; every fault names its vector,
    /// as a leg's does.
    #[test]
    fn the_child_report_lines() {
        let line = |end| {
            EndReport {
                end,
                identity: Identity::Child(136, "spawn"),
            }
            .to_string()
        };
        assert_eq!(
            line(ProcessEnd::Exited(0)),
            "F2K: child process 136 (spawn) exited normally (exit code=0)"
        );
        assert_eq!(
            line(ProcessEnd::Exited(3_221_225_500)),
            "F2K: child process 136 (spawn) exited normally (exit code=3221225500)"
        );
        assert_eq!(
            line(ProcessEnd::Faulted(PAGE_FAULT)),
            "F2K: child process 136 (spawn) ended by fault (vector 14, exit code=3221225477)"
        );
        assert_eq!(
            line(ProcessEnd::Faulted(COPY_FAULT)),
            "F2K: child process 136 (spawn) ended by fault (vector 14, exit code=3221225477)"
        );
    }

    /// One quiescent point of a suite: the audit lines it reports, and what follows.
    fn settle(suite: &mut Suite, available: u32) -> (Vec<String>, AtQuiescence) {
        let mut lines = Vec::new();
        let after = suite.settle(available, 1240, |report| lines.push(report.to_string()));
        (lines, after)
    }

    /// The suite a process at a time, every reap quiescent: each leg's audit line at its own reap,
    /// then the next leg, and after the last the summary — today's sequence, line for line.
    #[test]
    fn a_suite_one_leg_at_a_time() {
        let mut suite = Suite::new();
        suite.begin(3);
        suite.started(1);
        for index in 1..=3 {
            let end = if index == 2 {
                ProcessEnd::Faulted(PAGE_FAULT)
            } else {
                ProcessEnd::Exited(0)
            };
            suite.reaped(Some(index), end, true);
            let (lines, after) = settle(&mut suite, 1240);
            assert_eq!(
                lines,
                [format!(
                    "F2K: process {index} teardown audit: frame database ok"
                )]
            );
            let expected = if index < 3 {
                AtQuiescence::Start(index + 1)
            } else {
                AtQuiescence::Summary(SuiteTally {
                    run: 3,
                    faulted: 1,
                    leaks: 0,
                })
            };
            assert_eq!(after, expected);
            if let AtQuiescence::Start(next) = after {
                suite.started(next);
            }
        }
    }

    /// A one-process boot: its line names no leg, nothing is counted, and the boot rests. A boot
    /// the runner does not drive (no legs) reports its one program the same way.
    #[test]
    fn a_lone_program_reports_and_rests() {
        for legs in [0, 1] {
            let mut suite = Suite::new();
            assert_eq!(suite.legs(), 0);
            suite.begin(legs);
            assert_eq!(suite.legs(), legs);
            if legs == 1 {
                suite.started(1);
            }
            suite.reaped(Some(1), ProcessEnd::Faulted(PAGE_FAULT), true);
            assert_eq!(
                settle(&mut suite, 1238),
                (
                    vec![
                        "F2K: teardown audit FAILED: 1238 frames available, 1240 before the \
                         process (frame database ok)"
                            .to_string()
                    ],
                    AtQuiescence::Rest
                )
            );
            assert_eq!(suite.tally, SuiteTally::new());
        }
    }

    /// Legs started together, reaped out of order: each line carries its own leg's index, in reap
    /// order, at the one quiescent point; the tally counts both, no leg starts twice, and the
    /// summary follows once every leg is reaped.
    #[test]
    fn overlapping_legs_report_by_their_own_index() {
        let mut suite = Suite::new();
        suite.begin(2);
        suite.started(1);
        suite.started(2);
        suite.reaped(Some(2), ProcessEnd::Faulted(PAGE_FAULT), true);
        suite.reaped(Some(1), ProcessEnd::Exited(0), false);
        let (lines, after) = settle(&mut suite, 1240);
        assert_eq!(
            lines,
            [
                "F2K: process 2 teardown audit: frame database ok",
                "F2K: process 1 teardown audit FAILED: 1240 frames available, 1240 before the \
                 process (frame database corrupt)",
            ]
        );
        let tally = SuiteTally {
            run: 2,
            faulted: 1,
            leaks: 1,
        };
        assert_eq!(suite.tally, tally);
        assert_eq!(after, AtQuiescence::Summary(tally));
    }

    /// A child counts for nothing: no audit line, no tally entry, no next leg. When it outlives
    /// its parent's leg, its reap is the quiescent point: the leg's line prints there, and the next
    /// leg starts only then — after the child's end, inside the leg's part of the log.
    #[test]
    fn a_child_reports_nothing_but_may_settle_its_parent() {
        let mut suite = Suite::new();
        suite.begin(3);
        suite.started(1);

        // A child ended inside its parent's leg: the parent's reap settles one line.
        suite.reaped(None, ProcessEnd::Exited(0), true);
        suite.reaped(Some(1), ProcessEnd::Exited(0), true);
        assert_eq!(
            settle(&mut suite, 1240),
            (
                vec!["F2K: process 1 teardown audit: frame database ok".to_string()],
                AtQuiescence::Start(2)
            )
        );
        suite.started(2);

        // A child outliving its parent: the leg's reap is not quiescent; the child's is, and only
        // then the leg's line and the next leg's start.
        suite.reaped(Some(2), ProcessEnd::Exited(0), true);
        suite.reaped(None, ProcessEnd::Faulted(PAGE_FAULT), true);
        assert_eq!(
            settle(&mut suite, 1240),
            (
                vec!["F2K: process 2 teardown audit: frame database ok".to_string()],
                AtQuiescence::Start(3)
            )
        );
        suite.started(3);

        // The same past the last leg: the summary waits for the child's reap.
        suite.reaped(Some(3), ProcessEnd::Exited(0), true);
        suite.reaped(None, ProcessEnd::Exited(0), true);
        assert_eq!(
            settle(&mut suite, 1240),
            (
                vec!["F2K: process 3 teardown audit: frame database ok".to_string()],
                AtQuiescence::Summary(SuiteTally {
                    run: 3,
                    faulted: 0,
                    leaks: 0
                })
            )
        );

        // A child alone at a quiescent point, its parent's line already printed: nothing.
        let mut lone = Suite::new();
        lone.begin(1);
        lone.started(1);
        lone.reaped(None, ProcessEnd::Exited(0), true);
        assert_eq!(settle(&mut lone, 1240), (vec![], AtQuiescence::Rest));
    }
}

//! The end of a thread and of its process, as decisions: how a thread's end routes, what the
//! process's end reports on COM1, and what the kernel does once the process is torn down.
//!
//! One exit path serves every boot. A thread's return ends the running thread, and the last live
//! thread's end is the process's end. The exit service and a fault end the process outright:
//! every other thread is terminated first, without running again, then the calling thread. A
//! thread inside a critical region (holding the volume and its drive) is the exception: it runs on
//! to the region's end and ends itself there, and the process's end passes to the last such
//! thread. The process's end is then reported, and the idle thread tears the process down — after
//! which a suite boot starts its next leg (or prints its summary) and a one-process boot rests.

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
    pub const STACK_OVERFLOW: u32 = 0xC000_00FD;
    pub const FLOAT_MULTIPLE_TRAPS: u32 = 0xC000_02B5;
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
    /// The thread's return (its exit trampoline), with the exit status.
    Exit(i32),
    /// The exit service: the process ends with this exit code, all its threads with it.
    ExitProcess(u32),
    /// A fault raised on the thread's behalf.
    Fault(Fault),
    /// A termination deferred by a critical region, completing as the thread leaves it. It carries
    /// the process's end, handed on by the exit or fault that requested the termination.
    Terminated(ProcessEnd),
}

/// Why a process ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessEnd {
    /// Its last thread exited with this code.
    Exited(u32),
    /// A fault in one of its threads ended it.
    Faulted(Fault),
}

/// What a thread's end does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExitPlan {
    /// Terminate every other thread of the process before this one ends.
    pub terminate_others: bool,
    /// The process ends with this thread, for this reason; none while other threads live on.
    pub process_end: Option<ProcessEnd>,
}

/// Route a thread's end, given how many other threads of its process are still attached. A
/// thread's return ends only its thread while others live on, and the process — with that status
/// as its code — from the last thread; the exit service and a fault end the process whatever lives
/// on, terminating the others first.
pub fn plan(end: ThreadEnd, others: u16) -> ExitPlan {
    match end {
        ThreadEnd::Exit(status) => ExitPlan {
            terminate_others: false,
            process_end: (others == 0).then_some(ProcessEnd::Exited(status as u32)),
        },
        ThreadEnd::ExitProcess(code) => ExitPlan {
            terminate_others: others > 0,
            process_end: Some(ProcessEnd::Exited(code)),
        },
        ThreadEnd::Fault(fault) => ExitPlan {
            terminate_others: others > 0,
            process_end: Some(ProcessEnd::Faulted(fault)),
        },
        ThreadEnd::Terminated(end) => ExitPlan {
            terminate_others: false,
            process_end: (others == 0).then_some(end),
        },
    }
}

/// The plan once the other threads' terminations ran, `deferred` of them still finishing a
/// critical region: the process does not end with this thread then — its end passes to the last
/// of them (returned, for the process to hold until that thread's exit).
pub fn hand_over(plan: ExitPlan, deferred: u16) -> (ExitPlan, Option<ProcessEnd>) {
    if deferred == 0 {
        return (plan, None);
    }
    (
        ExitPlan {
            process_end: None,
            ..plan
        },
        plan.process_end,
    )
}

/// The suite leg a process runs as: its 1-based index and fixture name. A one-process boot has
/// none.
pub type Leg = (u32, &'static str);

/// The process-end report line: the one-process boot's form, or the suite's with the leg's index
/// and name.
pub struct EndReport {
    pub end: ProcessEnd,
    pub leg: Option<Leg>,
}

impl fmt::Display for EndReport {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.leg, self.end) {
            (None, ProcessEnd::Exited(code)) => {
                write!(out, "F2K: user process exited normally (exit code={code})")
            }
            (None, ProcessEnd::Faulted(fault)) if fault.in_user_copy => write!(
                out,
                "F2K: user process ended by fault (bad user argument pointer, exit code={}); \
                 halting",
                fault.status
            ),
            (None, ProcessEnd::Faulted(fault)) if fault.vector == RAISED_VECTOR => write!(
                out,
                "F2K: user process ended by fault (raised exception, exit code={}); halting",
                fault.status
            ),
            (None, ProcessEnd::Faulted(fault)) => write!(
                out,
                "F2K: user process ended by fault (vector {}, exit code={}); halting",
                fault.vector, fault.status
            ),
            (Some((index, name)), ProcessEnd::Exited(code)) => write!(
                out,
                "F2K: process {index} ({name}) exited normally (exit code={code})"
            ),
            (Some((index, name)), ProcessEnd::Faulted(fault)) => write!(
                out,
                "F2K: process {index} ({name}) ended by fault (vector {}, exit code={})",
                fault.vector, fault.status
            ),
        }
    }
}

/// The suite's per-leg teardown audit line: the allocators back at the post-boot baseline, or the
/// leak with the frame database's available count.
#[cfg(any(test, feature = "run-process-suite"))]
pub struct AuditReport {
    pub index: u32,
    pub audit: Result<(), u32>,
}

#[cfg(any(test, feature = "run-process-suite"))]
impl fmt::Display for AuditReport {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.audit {
            Ok(()) => write!(
                out,
                "F2K: process {} teardown audit: frame database ok, kernel heap ok",
                self.index
            ),
            Err(available) => write!(
                out,
                "F2K: process {} teardown audit FAILED: allocator state leaked (available {})",
                self.index, available
            ),
        }
    }
}

/// What follows a suite leg's teardown.
#[cfg(any(test, feature = "run-process-suite"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AfterLeg {
    /// The next leg (1-based).
    Next(u32),
    /// The last leg finished: print the summary, then rest.
    Summary,
}

/// The decision after leg `index` (1-based) of `legs` is torn down: the next leg until the last,
/// then the summary.
#[cfg(any(test, feature = "run-process-suite"))]
pub fn after_leg(index: u32, legs: u32) -> AfterLeg {
    assert!(index >= 1 && index <= legs, "suite leg {index} of {legs}");
    if index < legs {
        AfterLeg::Next(index + 1)
    } else {
        AfterLeg::Summary
    }
}

/// The suite's running counts, and its summary line.
#[cfg(any(test, feature = "run-process-suite"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SuiteTally {
    pub run: u32,
    pub faulted: u32,
    pub leaks: u32,
}

#[cfg(any(test, feature = "run-process-suite"))]
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

#[cfg(any(test, feature = "run-process-suite"))]
impl fmt::Display for SuiteTally {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "F2K: process suite complete: {} run, {} faulted, {} leaks",
            self.run, self.faulted, self.leaks
        )
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

    /// A thread's return ends only its thread while others live on, and the process — with its
    /// status as the exit code — from the last thread. It never terminates anyone else.
    #[test]
    fn a_return_ends_the_process_only_from_the_last_thread() {
        assert_eq!(
            plan(ThreadEnd::Exit(0), 2),
            ExitPlan {
                terminate_others: false,
                process_end: None
            }
        );
        assert_eq!(
            plan(ThreadEnd::Exit(7), 0),
            ExitPlan {
                terminate_others: false,
                process_end: Some(ProcessEnd::Exited(7))
            }
        );
        // The status reports as the unsigned code the exit line has always printed.
        assert_eq!(
            plan(ThreadEnd::Exit(0xC000_001Cu32 as i32), 0).process_end,
            Some(ProcessEnd::Exited(3_221_225_500))
        );
    }

    /// The exit service ends the process from any thread, with its own code: the others are
    /// terminated first when there are any — the code is the caller's, never a survivor's.
    #[test]
    fn the_exit_service_ends_the_process_from_any_thread() {
        assert_eq!(
            plan(ThreadEnd::ExitProcess(1), 2),
            ExitPlan {
                terminate_others: true,
                process_end: Some(ProcessEnd::Exited(1))
            }
        );
        assert_eq!(
            plan(ThreadEnd::ExitProcess(0), 0),
            ExitPlan {
                terminate_others: false,
                process_end: Some(ProcessEnd::Exited(0))
            }
        );
    }

    /// A fault ends the process from any thread: the others are terminated first when there are
    /// any, and the end is the fault.
    #[test]
    fn a_fault_ends_the_process_from_any_thread() {
        assert_eq!(
            plan(ThreadEnd::Fault(PAGE_FAULT), 2),
            ExitPlan {
                terminate_others: true,
                process_end: Some(ProcessEnd::Faulted(PAGE_FAULT))
            }
        );
        assert_eq!(
            plan(ThreadEnd::Fault(COPY_FAULT), 0),
            ExitPlan {
                terminate_others: false,
                process_end: Some(ProcessEnd::Faulted(COPY_FAULT))
            }
        );
    }

    /// The one-process boot's end lines, byte for byte: the exit, the user fault, and the
    /// user-copy fault.
    #[test]
    fn the_one_process_report_lines() {
        let line = |end| EndReport { end, leg: None }.to_string();
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
        let line = |end, leg| {
            EndReport {
                end,
                leg: Some(leg),
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
                index: 3,
                audit: Ok(())
            }
            .to_string(),
            "F2K: process 3 teardown audit: frame database ok, kernel heap ok"
        );
        assert_eq!(
            AuditReport {
                index: 4,
                audit: Err(1234)
            }
            .to_string(),
            "F2K: process 4 teardown audit FAILED: allocator state leaked (available 1234)"
        );
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

    /// A deferred termination ends its thread with the end it was handed, and the process with it
    /// only from the last thread; it never terminates others.
    #[test]
    fn a_deferred_termination_carries_the_handed_end() {
        let end = ProcessEnd::Exited(0);
        assert_eq!(
            plan(ThreadEnd::Terminated(end), 1),
            ExitPlan {
                terminate_others: false,
                process_end: None
            }
        );
        assert_eq!(
            plan(ThreadEnd::Terminated(end), 0),
            ExitPlan {
                terminate_others: false,
                process_end: Some(end)
            }
        );
    }

    /// The hand-over: with every other thread terminated the plan stands; with some still finishing
    /// a critical region, the process's end passes to them and this thread ends alone.
    #[test]
    fn the_process_end_passes_to_deferred_threads() {
        let fault = PAGE_FAULT;
        for end in [ThreadEnd::ExitProcess(3), ThreadEnd::Fault(fault)] {
            let planned = plan(end, 2);
            assert_eq!(hand_over(planned, 0), (planned, None));
            let (after, handed) = hand_over(planned, 1);
            assert_eq!(after.process_end, None);
            assert!(after.terminate_others);
            assert_eq!(handed, planned.process_end);
            assert!(handed.is_some());
        }
    }
}

//! The thread object: the scheduling state every thread carries.

use core::ptr::{addr_of_mut, null_mut};

use super::apc::{nop_kernel_routine, suspend_apc_normal, Apc, ApcMode};
use super::process::SchedProcess;
use super::semaphore::Semaphore;
use super::wait::{
    Timer,
    WaitBlock,
    WaitKind,
    WaitMode,
    WaitReason,
    Waitable,
    STATUS_TIMEOUT,
    TIMER_BLOCK,
    WAIT_BLOCKS,
};
use super::Links;
use super::List;
use crate::interrupt::irql::{self, LevelSnapshot};

/// The gate-slot index of a thread whose slot is not allocated yet.
pub const NO_GATE_SLOT: u16 = 0xFFFF;

/// A thread's saved floating-point state, in the `fxsave`/`fxrstor` image: the x87 control,
/// status and abridged tag words, the last instruction and operand pointers, MXCSR, the eight x87
/// registers and the eight XMM registers. The system DLLs are compiled for SSE2, so the XMM
/// registers and MXCSR are live in user code as much as the x87 registers are. The context switch
/// saves the outgoing thread's and restores the incoming one's on every switch, so a preempted
/// computation never resumes on another thread's registers. The instructions fault on an image
/// that is not 16-byte aligned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C, align(16))]
pub struct FpuState(pub [u8; FPU_STATE_BYTES]);

/// The `fxsave` image's size, and the alignment `fxsave` and `fxrstor` need.
pub const FPU_STATE_BYTES: usize = 512;
pub const FPU_STATE_ALIGN: usize = 16;

/// The image's fields, by byte offset: the x87 control word, status word, abridged tag byte (a bit
/// per register, set when it holds a value) and last opcode; MXCSR and the mask of its writable
/// bits; the x87/MMX registers and the XMM registers, 16 bytes each.
pub const FPU_FCW: usize = 0;
pub const FPU_FSW: usize = 2;
pub const FPU_FTW: usize = 4;
pub const FPU_FOP: usize = 6;
pub const FPU_MXCSR: usize = 24;
pub const FPU_MXCSR_MASK: usize = 28;
pub const FPU_ST0: usize = 32;
pub const FPU_XMM0: usize = 160;

/// The control word a new thread starts with: every exception masked, 53-bit precision, round to
/// nearest — the value Windows NT gives a fresh thread (`fninit` alone would leave 64-bit
/// precision).
pub const INITIAL_FPU_CONTROL: u16 = 0x027F;

/// The MXCSR a new thread starts with: every SIMD exception masked, round to nearest, denormals
/// kept (the processor's reset value).
pub const INITIAL_MXCSR: u32 = 0x1F80;

impl FpuState {
    /// A fresh thread's image: the initial control word and MXCSR, a clear status word, every
    /// register empty (an abridged tag of zero), everything else zero.
    pub const fn initial() -> Self {
        let mut bytes = [0u8; FPU_STATE_BYTES];
        let control = INITIAL_FPU_CONTROL.to_le_bytes();
        bytes[FPU_FCW] = control[0];
        bytes[FPU_FCW + 1] = control[1];
        let mxcsr = INITIAL_MXCSR.to_le_bytes();
        let mut index = 0;
        while index < mxcsr.len() {
            bytes[FPU_MXCSR + index] = mxcsr[index];
            index += 1;
        }
        FpuState(bytes)
    }
}

/// A thread's scheduling state, as the dispatcher moves it around: created, queued, on the
/// processor, selected as the processor's next thread, exited, blocked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ThreadState {
    /// Created, never yet readied.
    Initialized = 0,
    /// On a ready list, waiting for the processor.
    Ready = 1,
    /// On the processor.
    Running = 2,
    /// Selected as the processor's next thread.
    Standby = 3,
    /// Exited; no longer scheduled.
    Terminated = 4,
    /// Blocked on a dispatcher object (the wait machinery's state).
    Waiting = 5,
    /// Between wake and ready, waiting for its kernel stack to be swapped in. Never entered: F2K
    /// never swaps kernel stacks out, so a woken thread goes straight to ready.
    Transition = 6,
}

/// The exit status of a thread that has not ended (the documented STILL_ACTIVE).
pub const STILL_ACTIVE: u32 = 259;

/// A thread: one schedulable unit of execution.
///
/// An intrusive kernel object: it carries the links for the ready queue and its process's thread
/// list, so queueing allocates nothing. The record leads with its machine state — the words the
/// context switch's assembly addresses through pinned, compile-time checked offsets (saved esp,
/// stack top, TEB page, level ledger).
#[repr(C)]
pub struct Thread {
    // --- Machine state (the context switch's ABI) ---
    /// The scheduling state.
    pub(crate) state: ThreadState,
    /// The owning process; the source of the quantum and of the priority class rules, and the
    /// identity a switch compares to decide the CR3 load. Valid for the thread's lifetime.
    pub(crate) process: *mut SchedProcess,
    /// The saved kernel stack pointer: where a switch-out stored this thread's switch frame, and
    /// what a switch-in loads as the new `esp`. The startup-frame builder plants it for a
    /// never-run thread.
    pub(crate) kernel_stack: u32,
    /// The kernel stack's top: this thread's gate-stack slot top, which the switch installs as the
    /// TSS `esp0`.
    pub(crate) initial_stack: u32,
    /// The thread's TEB page: the base the switch writes into the TEB segment descriptor. Zero for
    /// kernel and idle threads.
    pub(crate) teb_va: u32,
    /// The thread's client id (what GetCurrentThreadId reports, through its TEB): handed out when
    /// a user thread is created; zero for kernel threads.
    pub(crate) thread_id: u32,
    /// The base of the thread's user-stack reservation, released with the record (zero for kernel
    /// threads, and for the main thread, whose stack is a system region). How far the stack has
    /// grown is the TEB's to say (see `user::stack`).
    pub(crate) stack_reservation: u32,
    /// The thread's exit status: [`STILL_ACTIVE`] while it lives, then the status it ended with.
    pub(crate) exit_status: u32,
    /// The thread's level ledger: captured at switch-out, restored at resume. A fresh thread
    /// adopts an empty one.
    pub(crate) level: LevelSnapshot,
    /// The thread's gate-stack slot index in its process's window, or the empty slot's value
    /// before allocation.
    pub(crate) gate_slot: u16,
    /// The slot's frames, recorded for exactly-once release (the guard page below them is never
    /// mapped, so it is never recorded).
    pub(crate) gate_frames: [u32; crate::mem::paging::GATE_STACK_PAGES],
    /// The thread's floating-point state while it is off the processor (saved and restored by the
    /// switch, at the offset the assembly takes from this layout; 16-byte aligned, as the record).
    pub(crate) fpu: FpuState,

    // --- Scheduling state ---
    /// The priority the scheduler queues and preempts by.
    pub(crate) priority: i8,
    /// The priority the thread decays toward and is floored by.
    pub(crate) base_priority: i8,
    /// Outstanding decay debt: subtracted once at the next decay, then cleared.
    pub(crate) priority_decrement: i8,
    /// Round trips left on a sticky boost before the thread drops back to its base priority.
    pub(crate) decrement_count: u8,
    /// Run time left before the scheduler reconsiders the processor.
    pub(crate) quantum: i8,
    /// Whether a base-priority change pinned this thread to a class edge: -1 pinned low, +1 pinned
    /// high, 0 free.
    pub(crate) saturation: i8,
    /// Whether wait-exit boosts are refused for this thread (the wait-exit gate; the wake boost
    /// itself does not consult it).
    pub(crate) disable_boost: bool,
    /// Set when the thread is pushed off the processor (or the standby slot) by a higher-priority
    /// arrival: it then requeues at the head of its ready list rather than the tail.
    pub(crate) preempted: bool,
    /// Always false in F2K: processes are never swapped out, so no thread is ever parked on its
    /// process. The flag survives as the priority-change guard for the parked shape.
    pub(crate) parked_on_process: bool,
    /// Set when the thread exits: the thread-object waits observe it. The thread is itself a
    /// waitable object; this is its header's signal state.
    pub(crate) waitable: Waitable,

    // --- Wait state (the block discipline) ---
    /// The wait blocks this thread owns: the first holds a single-object wait, the last slot its
    /// timer block.
    pub(crate) wait_blocks: [WaitBlock; WAIT_BLOCKS],
    /// The circular chain head of the current wait's blocks, null between waits.
    pub(crate) wait_block_head: *mut WaitBlock,
    /// The completion status of the current or last wait.
    pub(crate) wait_status: i32,
    /// Why the thread is waiting (diagnostic data).
    pub(crate) wait_reason: WaitReason,
    /// The mode of the current wait (inert until the APC machinery exists).
    pub(crate) wait_mode: WaitMode,
    /// Whether an APC may break the current wait (inert until the APC machinery exists).
    pub(crate) wait_alertable: bool,
    /// The tick stamp of the current wait.
    pub(crate) wait_time: u64,
    /// The thread's wait-timeout timer.
    pub(crate) timer: Timer,
    /// The dispatcher's waiting-list membership link.
    pub(crate) wait_links: Links,

    /// The ready-queue membership link.
    pub(crate) ready_links: Links,
    /// The owning process's thread-list membership link.
    pub(crate) process_links: Links,

    // --- The APC machinery ---
    /// The kernel-mode APC queue's sentinel.
    pub(crate) kernel_apcs: List,
    /// The user-mode APC queue's sentinel: QueueUserAPC's and the waitable timers' APCs, delivered
    /// in user mode (see [`crate::user::apc`]).
    pub(crate) user_apcs: List,
    /// Whether a kernel APC is queued: the delivery windows' question, armed by the insert.
    pub(crate) kernel_apc_pending: bool,
    /// Whether a user APC's delivery is armed: an alertable wait completed for one, or
    /// NtContinue's test alert found more queued.
    pub(crate) user_apc_pending: bool,
    /// Whether a normal kernel APC's normal half is running — the gate that makes a blocking
    /// normal routine safe (the suspend APC parks inside one).
    pub(crate) kernel_apc_in_progress: bool,
    /// The critical-region count: while nonzero, normal kernel APCs neither break waits nor
    /// deliver, and a termination waits for the thread to leave. Code that holds a shared resource
    /// across a blocking wait (the boot volume and its drive) runs inside one.
    pub(crate) kernel_apc_disable: i8,
    /// Whether APCs may be queued on this thread. On from attach, off from the exit path on.
    pub(crate) apc_queueable: bool,
    /// Whether a termination waits for this thread to leave its critical region: set by the
    /// request (see [`Dispatcher::request_termination`]), acted on by the thread itself as it
    /// leaves.
    ///
    /// [`Dispatcher::request_termination`]: super::dispatcher::Dispatcher::request_termination
    pub(crate) terminate_pending: bool,
    /// The thread's builtin suspend APC: a no-op kernel half, a normal half that parks on the
    /// suspend semaphore.
    pub(crate) suspend_apc: Apc,
    /// The thread's builtin suspend semaphore — the suspend APC parks on it, resume releases it.
    pub(crate) suspend_semaphore: Semaphore,
    /// How many suspends are outstanding.
    pub(crate) suspend_count: u8,
    /// A second suspend authority's count. Constant zero in F2K — nothing freezes threads — but
    /// the suspend and resume gates read it.
    pub(crate) freeze_count: u8,
    /// The level the current wait was entered at: a wait above the passive level is not
    /// APC-breakable. F2K's waits are always entered at the passive level; the gate stays armed.
    pub(crate) wait_irql: irql::Irql,
    /// The mutexes the thread owns (see [`super::mutex`]): its end abandons them.
    pub(crate) owned_mutexes: List,
    /// The blocks of a multiple-object wait, one per object. They live in the record, not on the
    /// waiting thread's stack: a wake may unwind them from any thread's context, and the kernel
    /// stacks are mapped per process.
    pub(crate) multi_blocks: [WaitBlock; super::wait::MAXIMUM_WAIT_OBJECTS],
    /// Whether the thread runs its own exit path: a critical region it leaves there (the exit's
    /// own volume work) no longer ends it.
    pub(crate) exiting: bool,
}

// The machine-state layout contract with the switch's assembly: on the 32-bit target the offsets it
// addresses threads through are the real ones, or the kernel does not build. Host builds skip the
// pin (their pointer width differs) and pin the field order below instead.
#[cfg(target_arch = "x86")]
const _: () = {
    assert!(core::mem::offset_of!(Thread, state) as u32 == super::switch::THREAD_STATE_OFF);
    assert!(core::mem::offset_of!(Thread, process) as u32 == super::switch::THREAD_PROCESS_OFF);
    assert!(
        core::mem::offset_of!(Thread, kernel_stack) as u32
            == super::switch::THREAD_KERNEL_STACK_OFF
    );
    assert!(
        core::mem::offset_of!(Thread, initial_stack) as u32
            == super::switch::THREAD_INITIAL_STACK_OFF
    );
    assert!(core::mem::offset_of!(Thread, teb_va) as u32 == super::switch::THREAD_TEB_VA_OFF);
};

/// The machine block leads the record in the assembly's field order, on every pointer width: state
/// first, then the owner pointer, then the three stack/TEB words. (The host layout widens the
/// pointer; the order is what stays pinned here.)
const _: () = {
    assert!(core::mem::offset_of!(Thread, state) == 0);
    assert!(core::mem::offset_of!(Thread, process) > 0);
    assert!(core::mem::offset_of!(Thread, kernel_stack) > core::mem::offset_of!(Thread, process));
    assert!(
        core::mem::offset_of!(Thread, initial_stack) > core::mem::offset_of!(Thread, kernel_stack)
    );
    assert!(core::mem::offset_of!(Thread, teb_va) > core::mem::offset_of!(Thread, initial_stack));
    // `fxsave` and `fxrstor` fault on an unaligned image: the record's alignment carries it.
    assert!(core::mem::offset_of!(Thread, fpu) % FPU_STATE_ALIGN == 0);
    assert!(core::mem::align_of::<Thread>() >= FPU_STATE_ALIGN);
};

impl Thread {
    /// A fresh, detached thread. Call [`Thread::attach_to`] before any scheduler operation, and
    /// give it machine state (stacks, TEB) before it is ever readied.
    pub const fn empty() -> Self {
        Thread {
            state: ThreadState::Initialized,
            process: core::ptr::null_mut(),
            kernel_stack: 0,
            initial_stack: 0,
            teb_va: 0,
            thread_id: 0,
            stack_reservation: 0,
            exit_status: STILL_ACTIVE,
            level: LevelSnapshot::empty(),
            gate_slot: NO_GATE_SLOT,
            gate_frames: [0; crate::mem::paging::GATE_STACK_PAGES],
            fpu: FpuState::initial(),
            priority: 0,
            base_priority: 0,
            priority_decrement: 0,
            decrement_count: 0,
            quantum: 0,
            saturation: 0,
            disable_boost: false,
            preempted: false,
            parked_on_process: false,
            waitable: Waitable::new(WaitKind::Thread, 0),
            wait_blocks: [WaitBlock::detached(); WAIT_BLOCKS],
            wait_block_head: null_mut(),
            wait_status: 0,
            wait_reason: WaitReason::Executive,
            wait_mode: WaitMode::Kernel,
            wait_alertable: false,
            wait_time: 0,
            timer: Timer::new(),
            wait_links: Links::detached(),
            ready_links: Links::detached(),
            process_links: Links::detached(),
            kernel_apcs: List::empty(),
            user_apcs: List::empty(),
            kernel_apc_pending: false,
            user_apc_pending: false,
            kernel_apc_in_progress: false,
            kernel_apc_disable: 0,
            apc_queueable: true,
            terminate_pending: false,
            suspend_apc: Apc::detached(),
            suspend_semaphore: Semaphore::new(super::apc::SUSPEND_SEMAPHORE_LIMIT),
            suspend_count: 0,
            freeze_count: 0,
            wait_irql: irql::PASSIVE,
            owned_mutexes: List::empty(),
            multi_blocks: [WaitBlock::detached(); super::wait::MAXIMUM_WAIT_OBJECTS],
            exiting: false,
        }
    }

    /// Attach to `process`: take the process's base priority, quantum and boost policy, join its
    /// thread list, and account the kernel stack. After this the thread is Initialized and
    /// schedulable.
    ///
    /// # Safety
    ///
    /// The process must outlive the thread's membership in its list (the first link is written
    /// here), and both objects must be at their final addresses.
    pub unsafe fn attach_to(&mut self, process: &mut SchedProcess) {
        // Every thread is attached at its final address before it first runs: the place the
        // switch saves its floating-point state to.
        assert!(
            (core::ptr::addr_of!(self.fpu) as usize).is_multiple_of(FPU_STATE_ALIGN),
            "a thread's floating-point area is 16-byte aligned"
        );
        self.process = process as *mut SchedProcess;
        self.base_priority = process.base_priority;
        self.priority = self.base_priority;
        self.quantum = process.thread_quantum;
        self.disable_boost = process.disable_boost;
        self.state = ThreadState::Initialized;

        // The wait discipline's fixed wiring. The thread is a waitable object in its own right,
        // every block names its owner, and the timer block's claim is constant for the thread's
        // life — its object is the thread's own timer and its key the timeout status — so a wait
        // only ever re-links it.
        self.waitable.init();
        self.timer.init();
        let thread = self as *mut Thread;
        for block in self.wait_blocks.iter_mut() {
            block.thread = thread;
        }
        // SAFETY: the thread and its timer are at their final addresses; the pointer stays valid
        // for the thread's lifetime.
        self.wait_blocks[TIMER_BLOCK].object = addr_of_mut!(self.timer.waitable);
        self.wait_blocks[TIMER_BLOCK].key = STATUS_TIMEOUT;
        self.wait_blocks[TIMER_BLOCK].wait_all = false;

        // SAFETY: the thread's process link is detached and the process's thread list is
        // initialized (caller contract).
        unsafe { process.threads.push_back(addr_of_mut!(self.process_links)) };
        if process.stack_count == super::process::NO_THREADS {
            process.stack_count = 1;
        } else {
            process.stack_count += 1;
        }
        process.thread_seed = process.thread_seed.wrapping_add(1);

        // The APC machinery's fixed wiring: the queues' sentinels, the suspend semaphore, and the
        // builtin suspend APC — its kernel half does nothing, its normal half parks the thread on
        // the semaphore (the suspend itself).
        self.kernel_apcs.init();
        self.user_apcs.init();
        self.owned_mutexes.init();
        self.suspend_semaphore.init();
        self.suspend_apc.init(
            thread,
            nop_kernel_routine,
            Some(suspend_apc_normal),
            ApcMode::Kernel,
            0,
        );
    }

    /// The scheduling state.
    pub fn state(&self) -> ThreadState {
        self.state
    }

    /// Enter a critical region (regions nest): until the thread leaves the outermost, normal kernel
    /// APCs wait, and so does a termination.
    pub fn enter_critical_region(&mut self) {
        self.kernel_apc_disable = self
            .kernel_apc_disable
            .checked_add(1)
            .expect("critical regions nest too deep");
    }

    /// Leave a critical region; true when it was the outermost.
    pub fn leave_critical_region(&mut self) -> bool {
        assert!(
            self.kernel_apc_disable > 0,
            "leaving a critical region never entered"
        );
        self.kernel_apc_disable -= 1;
        self.kernel_apc_disable == 0
    }

    /// Whether the thread is inside a critical region.
    pub fn in_critical_region(&self) -> bool {
        self.kernel_apc_disable != 0
    }

    /// Whether a termination waits for the thread to leave its critical region.
    pub fn termination_pending(&self) -> bool {
        self.terminate_pending
    }

    /// The current priority.
    pub fn priority(&self) -> i8 {
        self.priority
    }

    /// The base priority.
    pub fn base_priority(&self) -> i8 {
        self.base_priority
    }

    /// The remaining quantum.
    pub fn quantum(&self) -> i8 {
        self.quantum
    }

    /// The saved kernel stack pointer (what a switch-in loads).
    pub fn kernel_stack(&self) -> u32 {
        self.kernel_stack
    }

    /// The kernel stack's top (what the switch installs as `esp0`).
    pub fn initial_stack(&self) -> u32 {
        self.initial_stack
    }

    /// The thread's TEB page (the FS descriptor's base).
    pub fn teb_va(&self) -> u32 {
        self.teb_va
    }

    /// The thread's exit status (what GetExitCodeThread reports): [`STILL_ACTIVE`] until it ends.
    pub fn exit_status(&self) -> u32 {
        self.exit_status
    }

    /// The thread's client id, zero for kernel threads.
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// The thread's gate-stack slot index, or [`NO_GATE_SLOT`] before allocation.
    pub fn gate_slot(&self) -> u16 {
        self.gate_slot
    }

    /// The outstanding decay debt.
    pub fn priority_decrement(&self) -> i8 {
        self.priority_decrement
    }

    /// The round trips left on a sticky boost.
    pub fn decrement_count(&self) -> u8 {
        self.decrement_count
    }

    /// The class-edge pin state (-1, 0, +1).
    pub fn saturation(&self) -> i8 {
        self.saturation
    }

    /// Whether the thread has exited: its waitable header's signal state, set once at termination.
    pub fn signaled(&self) -> bool {
        self.waitable.signal_state > 0
    }

    /// The waitable header, as the wait entry takes it.
    pub fn waitable(&mut self) -> *mut Waitable {
        addr_of_mut!(self.waitable)
    }

    /// The thread a thread-kind waitable header belongs to: the header is the thread's own, at a
    /// fixed offset in the record. The caller must know the header is a thread's (a handle table
    /// slot's kind, say); a foreign header is a caller bug.
    pub fn from_waitable(waitable: *mut Waitable) -> *mut Thread {
        debug_assert_eq!(unsafe { (*waitable).kind() }, WaitKind::Thread);
        (waitable as usize - core::mem::offset_of!(Thread, waitable)) as *mut Thread
    }

    /// The completion status of the current or last wait.
    pub fn wait_status(&self) -> i32 {
        self.wait_status
    }

    /// Why the thread is waiting.
    pub fn wait_reason(&self) -> WaitReason {
        self.wait_reason
    }

    /// The mode of the current wait.
    pub fn wait_mode(&self) -> WaitMode {
        self.wait_mode
    }

    /// Whether an APC may break the current wait.
    pub fn wait_alertable(&self) -> bool {
        self.wait_alertable
    }

    /// The tick stamp of the current wait.
    pub fn wait_time(&self) -> u64 {
        self.wait_time
    }

    /// The owning process.
    ///
    /// # Safety
    ///
    /// The thread is attached (its lifetime pins the process).
    pub unsafe fn process(&self) -> &SchedProcess {
        unsafe { &*self.process }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh thread's image, in the `fxsave` layout the switch restores from: the NT control
    /// word, the reset MXCSR, every register empty, everything else zero.
    #[test]
    fn a_fresh_thread_starts_with_the_initial_fpu_image() {
        let image = Thread::empty().fpu.0;
        assert_eq!(image.len(), 512);
        let half = |at: usize| u16::from_le_bytes([image[at], image[at + 1]]);
        let word = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        assert_eq!(half(FPU_FCW), 0x027F, "control word");
        assert_eq!(word(FPU_MXCSR), 0x1F80, "MXCSR");
        for (at, &byte) in image.iter().enumerate() {
            let set =
                (FPU_FCW..FPU_FCW + 2).contains(&at) || (FPU_MXCSR..FPU_MXCSR + 4).contains(&at);
            if !set {
                assert_eq!(byte, 0, "byte {at}: status, tag and registers clear");
            }
        }
    }

    /// The image's layout: the field offsets, the eight x87/MMX registers between the header and
    /// the eight XMM registers, all inside the image.
    #[test]
    fn the_fpu_image_layout() {
        assert_eq!((FPU_FCW, FPU_FSW, FPU_FTW, FPU_FOP), (0, 2, 4, 6));
        assert_eq!((FPU_MXCSR, FPU_MXCSR_MASK), (24, 28));
        assert_eq!(FPU_ST0 + 8 * 16, FPU_XMM0);
        assert!(FPU_XMM0 + 8 * 16 <= FPU_STATE_BYTES);
        assert_eq!(core::mem::size_of::<FpuState>(), 512);
    }

    /// The alignment rule: the image type, its place in the record and the record itself are
    /// 16-byte aligned, so every thread record holds an image `fxsave` accepts.
    #[test]
    fn the_fpu_image_is_16_byte_aligned() {
        assert_eq!(core::mem::align_of::<FpuState>(), 16);
        assert_eq!(core::mem::offset_of!(Thread, fpu) % 16, 0);
        assert!(core::mem::align_of::<Thread>() >= 16);
        assert_eq!(super::super::switch::THREAD_FPU_OFF % 16, 0);
        let thread = Box::new(Thread::empty());
        assert_eq!(core::ptr::addr_of!(thread.fpu) as usize % 16, 0);
    }

    /// The state ordinals: stable, distinct, with the lifecycle order the dump paths and any raw
    /// state byte depend on.
    #[test]
    fn state_ordinals() {
        assert_eq!(ThreadState::Initialized as u8, 0);
        assert_eq!(ThreadState::Ready as u8, 1);
        assert_eq!(ThreadState::Running as u8, 2);
        assert_eq!(ThreadState::Standby as u8, 3);
        assert_eq!(ThreadState::Terminated as u8, 4);
        assert_eq!(ThreadState::Waiting as u8, 5);
        assert_eq!(ThreadState::Transition as u8, 6);
    }

    /// The waitable header belongs to its thread: the reverse mapping returns the owning record.
    #[test]
    fn from_waitable_returns_the_owning_thread() {
        let p = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        p.init();
        let t = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both objects are leaked at their final addresses.
        unsafe { t.attach_to(&mut *p) };
        assert!(core::ptr::eq(
            Thread::from_waitable(t.waitable()),
            t as *const Thread as *mut Thread
        ));
    }

    /// Attaching takes the scheduling data from the process: base and current priority, quantum,
    /// boost policy; the state is Initialized; the stack count moves off its sentinel and the seed
    /// advances per thread.
    #[test]
    fn attach_takes_process_data() {
        let process = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        process.init();

        let t1 = Box::leak(Box::new(Thread::empty()));
        // SAFETY: both objects are boxed at their final addresses.
        unsafe { t1.attach_to(process) };
        assert_eq!(t1.base_priority(), 8);
        assert_eq!(t1.priority(), 8);
        assert_eq!(t1.quantum(), 6);
        assert_eq!(t1.state(), ThreadState::Initialized);
        assert!(!t1.signaled());
        assert_eq!(process.stack_count(), 1);
        let seed_after_first = process.thread_seed();

        let t2 = Box::leak(Box::new(Thread::empty()));
        // SAFETY: as above.
        unsafe { t2.attach_to(process) };
        assert_eq!(process.stack_count(), 2);
        assert_eq!(process.thread_seed(), seed_after_first.wrapping_add(1));

        // The process list holds both, in creation order.
        // SAFETY: initialized list; entries stay linked.
        let first = unsafe { process.threads.first() };
        assert_eq!(first, core::ptr::addr_of_mut!(t1.process_links));
        assert!(!process.threads.is_empty());
    }

    /// Critical regions nest: only leaving the outermost reports it, and the count is the gate the
    /// APC machinery reads.
    #[test]
    fn critical_regions_nest() {
        let mut thread = Thread::empty();
        assert!(!thread.in_critical_region());
        thread.enter_critical_region();
        thread.enter_critical_region();
        assert!(thread.in_critical_region());
        assert_eq!(thread.kernel_apc_disable, 2);
        assert!(!thread.leave_critical_region(), "the inner region");
        assert!(thread.in_critical_region());
        assert!(thread.leave_critical_region(), "the outermost");
        assert!(!thread.in_critical_region());
        assert!(!thread.termination_pending());
    }

    #[test]
    #[should_panic(expected = "never entered")]
    fn leaving_an_unentered_region_is_a_contract_violation() {
        Thread::empty().leave_critical_region();
    }
}

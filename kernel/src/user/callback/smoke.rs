//! The `callback-smoke` boot diagnostic: user-mode callbacks issued from a system call, their
//! answers reported on COM1.
//!
//! The first win32k service of a process whose callback table is set (user32's process attach sets
//! it) runs the sequence on its way out, through user32's smoke slot ([`rtl::callback`]): a simple
//! callback; one nested three deep (each level calls back through the smoke's own entry,
//! [`service`]); a fault taken and handled inside a callback; an exception that escapes a nested
//! callback into the level above, whose issuer gets STATUS_CALLBACK_POP_STACK; a user APC
//! delivered at a nested level's return; the room check refusing a callback nested as deep as the
//! kernel stack allows; NtCallbackReturn with none outstanding; and, last, the process's end from a
//! callback two deep, its levels given up with its kernel stack (the teardown audits follow).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rtl::callback::{op, SmokeReply, SmokeRequest, SMOKE_APC_CONTEXT, SMOKE_API, SMOKE_EXIT_CODE};
use rtl::pod::Pod;

use super::{call_user_mode, outstanding, Reply};
use crate::level::{At, Passive};
use crate::serial_println;
use crate::status::*;
use crate::user::args::UserPtr;
use crate::user::TrapFrame;

/// NtQuerySystemInformation's Windows 2000 service number.
const NT_QUERY_SYSTEM_INFORMATION: u32 = 0x97;

/// Whether a system call is the smoke's own entry: NtQuerySystemInformation (`number`) of the smoke
/// class (the first of `args`).
pub fn claims(number: u32, args: &[u32]) -> bool {
    crate::user::syscall::service_table(number) == crate::user::syscall::NT_TABLE
        && number & crate::user::syscall::SERVICE_INDEX_MASK == NT_QUERY_SYSTEM_INFORMATION
        && args[0] == rtl::callback::SMOKE_INFORMATION_CLASS
}

/// Whether the sequence has run (once a boot).
static STARTED: AtomicBool = AtomicBool::new(false);
/// The status the issuer of the escaping callback got.
static ESCAPED: AtomicU32 = AtomicU32::new(0);
/// How many callbacks were outstanding when the room check refused one.
static REFUSED_AT: AtomicU32 = AtomicU32::new(0);

/// Call the smoke slot with `request`: its status, and its reply when it answered one.
fn call(passive: &mut At<Passive>, request: SmokeRequest) -> (NtStatus, Option<SmokeReply>) {
    let Reply {
        status,
        output,
        length,
    } = call_user_mode(passive, SMOKE_API, &[request.as_bytes()]);
    if status == STATUS_STACK_OVERFLOW {
        REFUSED_AT.fetch_max(outstanding(), Ordering::Relaxed);
    }
    let reply = (length as usize == core::mem::size_of::<SmokeReply>())
        .then(|| UserPtr::<SmokeReply>::at(output).read().ok())
        .flatten();
    (status, reply)
}

/// The smoke's entry (NtQuerySystemInformation's arguments: the class, the request, its length, the
/// reply's address): the request's callback one level deeper (its reply written back, its status
/// answered), a user APC queued on the caller and armed, or the process's end.
pub fn service(frame: &mut TrapFrame, args: &[u32], passive: &mut At<Passive>) {
    let reply_at = args[3];
    let Ok(request) = UserPtr::<SmokeRequest>::at(args[1]).read() else {
        frame.eax = STATUS_ACCESS_VIOLATION.0;
        return;
    };
    let status = match request.op {
        op::APC => {
            use crate::nt::call::{Handle, NtCall, UserAddr};
            let queued = crate::nt::sync::queue_apc_thread(
                &mut NtCall::new(frame, passive),
                Handle(crate::nt::object::CURRENT_THREAD),
                UserAddr(request.argument),
                UserAddr(SMOKE_APC_CONTEXT),
                UserAddr(0),
                UserAddr(0),
            );
            // As an alertable wait that found it: delivered on this service's way out.
            crate::user::apc::test_alert();
            queued.unwrap_or_else(|status| status)
        }
        op::EXIT if request.depth == 0 => crate::process::threads::exit_process(SMOKE_EXIT_CODE),
        _ => {
            let (status, reply) = call(passive, request);
            if request.op == op::RAISE {
                ESCAPED.store(status.0, Ordering::Relaxed);
            }
            if let Some(reply) = reply {
                let _ = UserPtr::<SmokeReply>::at(reply_at).write(reply);
            }
            status
        }
    };
    frame.eax = status.0;
}

/// The running thread is back at its own level: no callback outstanding, its stack top its slot's.
fn at_own_level() -> bool {
    use crate::level::{raised, Dispatch};
    let (top, slot) = raised::<Dispatch, _>(|dispatch| {
        let record = crate::sched::DISPATCHER
            .get(dispatch)
            .thread(crate::sched::current_thread());
        (record.initial_stack, record.gate_slot)
    });
    outstanding() == 0 && top == crate::mem::paging::gate_slot_top(slot as u32)
}

/// The TEB's PEB pointer and the PEB's KernelCallbackTable.
const TEB_PEB: u32 = core::mem::offset_of!(rtl::peb::Teb<u32>, process_environment_block) as u32;
const PEB_CALLBACK_TABLE: u32 =
    core::mem::offset_of!(rtl::peb::Peb<u32>, kernel_callback_table) as u32;

/// The calling process's callback table (its PEB's KernelCallbackTable), zero when unset.
fn callback_table() -> u32 {
    let teb = crate::level::raised::<crate::level::Dispatch, _>(|dispatch| {
        crate::sched::DISPATCHER
            .get(dispatch)
            .thread(crate::sched::current_thread())
            .teb_va
    });
    let peb = UserPtr::<u32>::at(teb + TEB_PEB).read().unwrap_or(0);
    if peb == 0 {
        return 0;
    }
    UserPtr::<u32>::at(peb + PEB_CALLBACK_TABLE)
        .read()
        .unwrap_or(0)
}

fn request(op: u32, depth: u32, argument: u32) -> SmokeRequest {
    SmokeRequest {
        op,
        depth,
        argument,
    }
}

/// A user address no process maps: the 64 KiB below the kernel's half.
const UNMAPPED: u32 = 0x7FFF_0000;

/// Run the sequence, the first time a win32k service of a process with a callback table returns.
pub fn run_once(passive: &mut At<Passive>) {
    if callback_table() == 0 || STARTED.swap(true, Ordering::Relaxed) {
        return;
    }
    let answer = |reply: Option<SmokeReply>| reply.map_or(0, |reply| reply.answer);
    let mut clean = true;

    let (status, reply) = call(passive, request(op::ECHO, 0, 0x1234));
    clean &= at_own_level();
    serial_println!(
        "F2K: callback-smoke: simple: status {:#010x}, answer {:#010x}",
        status.0,
        answer(reply)
    );

    let (status, reply) = call(passive, request(op::NEST, 3, 0));
    clean &= at_own_level();
    serial_println!(
        "F2K: callback-smoke: nested 3 deep: status {:#010x}, answer {}",
        status.0,
        answer(reply)
    );

    let (status, reply) = call(passive, request(op::PROBE, 0, UNMAPPED));
    clean &= at_own_level();
    serial_println!(
        "F2K: callback-smoke: fault handled inside the callback: status {:#010x}, readable {}",
        status.0,
        answer(reply)
    );

    let (status, reply) = call(passive, request(op::ESCAPE, 0, UNMAPPED));
    clean &= at_own_level();
    serial_println!(
        "F2K: callback-smoke: escape: status {:#010x}, inner issuer got {:#010x}, outer caught {:#010x}",
        status.0,
        ESCAPED.load(Ordering::Relaxed),
        answer(reply)
    );

    let (status, reply) = call(passive, request(op::APC, 0, 0));
    clean &= at_own_level();
    serial_println!(
        "F2K: callback-smoke: user APC at a nested return: status {:#010x}, context {:#010x}",
        status.0,
        answer(reply)
    );

    let (status, _) = call(passive, request(op::NEST, 1000, 0));
    clean &= at_own_level();
    serial_println!(
        "F2K: callback-smoke: room check: status {:#010x}, refused {} deep",
        status.0,
        REFUSED_AT.load(Ordering::Relaxed)
    );

    let mut frame = TrapFrame::default();
    let refused = super::callback_return(
        &mut crate::nt::call::NtCall::new(&mut frame, passive),
        crate::nt::call::UserAddr(0),
        0,
        0,
    );
    serial_println!(
        "F2K: callback-smoke: NtCallbackReturn with no callback: {:#010x}",
        refused.unwrap_or_else(|status| status).0
    );
    serial_println!(
        "F2K: callback-smoke: back at the thread's own level after each: {}",
        if clean { "yes" } else { "no" }
    );

    serial_println!("F2K: callback-smoke: ending the process 2 deep");
    let (status, _) = call(passive, request(op::EXIT, 2, 0));
    serial_println!(
        "F2K: callback-smoke: FAILED: the process outlived its end ({:#010x})",
        status.0
    );
}

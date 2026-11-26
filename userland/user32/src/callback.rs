//! The kernel's user-mode callbacks, user32's side (Windows 2000's apfnDispatch): the table its
//! process attach points PEB.KernelCallbackTable at ([`attach`]), which ntdll's
//! KiUserCallbackDispatcher calls through with the input block's address and length.
//!
//! The message slots (`__fnDWORD`, `__fnINLPCREATESTRUCT`, `__fnNCDESTROY`, the structure thunks
//! and the text thunks, rtl::callback's FN_*) carry a message the window manager sends to one of
//! the thread's windows while it decides, or one another thread sent, delivered from inside the
//! thread's read or wait: [`serve`] points the lParam at the structure or text the block carries
//! (a CREATESTRUCTW's lpszName at the name after it, a COPYDATASTRUCT's lpData at the data after
//! it, WM_GETTEXT's at the buffer in the block), calls the procedure ([`crate::message::invoke`]),
//! and the routine answers its LRESULT through NtCallbackReturn, then the in-out structure or
//! WM_GETTEXT's text. The other Windows 2000 slots are not served yet: each answers
//! STATUS_NOT_IMPLEMENTED, by returning it (the dispatcher hands a returned value to
//! NtCallbackReturn as the status). The last slot is F2K's smoke routine ([`rtl::callback`]), which
//! the kernel calls only in its `callback-smoke` boot; [`answer`] decides what it does, over the
//! kernel and the thread as [`Kernel`] reaches them.

use rtl::callback::{
    op,
    CallbackMsg,
    SmokeReply,
    SmokeRequest,
    FN_COPYDATA,
    FN_DWORD,
    FN_INLPCREATESTRUCT,
    FN_INLPWINDOWPOS,
    FN_INOUTLPPOINT5,
    FN_INOUTLPWINDOWPOS,
    FN_INOUTNCCALCSIZE,
    FN_INOUTSTYLECHANGE,
    FN_INSTRINGNULL,
    FN_NCDESTROY,
    FN_OUTSTRING,
};
use rtl::gdi::Rect;
use rtl::pod::Pod;
use rtl::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use rtl::user::{CreateStructW, MinMaxInfo, Msg, StyleStruct};
use rtl::window::{NcCalcSizeParams, WindowPos};

/// The size of the structure a message slot's block carries after its [`CallbackMsg`] (none for a
/// plain message; WM_NCCALCSIZE's by its form, `wparam`: a RECT, or an NCCALCSIZE_PARAMS and the
/// WINDOWPOS it points at); none for a slot that is not a message's.
fn carried_size(api: u32, wparam: u32) -> Option<usize> {
    Some(match api {
        FN_DWORD | FN_NCDESTROY => 0,
        FN_INLPCREATESTRUCT => core::mem::size_of::<CreateStructW>(),
        FN_INLPWINDOWPOS | FN_INOUTLPWINDOWPOS => core::mem::size_of::<WindowPos>(),
        FN_INOUTNCCALCSIZE if wparam != 0 => {
            core::mem::size_of::<NcCalcSizeParams>() + core::mem::size_of::<WindowPos>()
        }
        FN_INOUTNCCALCSIZE => core::mem::size_of::<Rect>(),
        FN_INOUTSTYLECHANGE => core::mem::size_of::<StyleStruct>(),
        FN_INOUTLPPOINT5 => core::mem::size_of::<MinMaxInfo>(),
        _ => return None,
    })
}

/// An address in this process as a message parameter holds it (a host's may not fit: none then,
/// as a receipt's structure on a 64-bit host).
fn address_of(at: *const u8) -> u32 {
    u32::try_from(at as usize).unwrap_or(0)
}

/// A message slot's call: the procedure's answer, and what its output block hands back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Served {
    pub answer: i32,
    pub out: Output,
}

/// What a message slot's output block is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// The LRESULT, then this many bytes of the block from just past its [`CallbackMsg`], the
    /// structure as the procedure left it (rtl::callback's `out_size`; 0 for none).
    Structure(usize),
    /// This range of the block whole: `__fnOUTSTRING`'s LRESULT (written into the block's answer
    /// word) and the units the procedure copied after it.
    Block(usize, usize),
}

/// The head's size: where the structure or the text starts in a block.
const HEAD: usize = core::mem::size_of::<CallbackMsg>();

/// The message the message slot `api`'s input `block` carries, called: the lParam pointed at the
/// structure in the block, a CREATESTRUCTW's lpszName at the name after it, an
/// NCCALCSIZE_PARAMS's lppos at the WINDOWPOS after it (the block is the kernel's copy on this
/// thread's stack, the procedure's to read and write). None for a slot that is not a message's,
/// or a block too short for its slot.
pub fn serve(api: u32, block: &mut [u8]) -> Option<Served> {
    let head = CallbackMsg::from_bytes(block.get(..HEAD)?)?;
    let mut msg = Msg {
        hwnd: head.hwnd,
        message: head.message,
        wparam: head.wparam,
        lparam: head.lparam,
        ..Msg::default()
    };
    if matches!(api, FN_INSTRINGNULL | FN_COPYDATA | FN_OUTSTRING) {
        return serve_text(api, head.proc, msg, block);
    }
    let carried = carried_size(api, head.wparam)?;
    let rest = &mut block[HEAD..];
    if carried != 0 {
        if rest.len() < carried {
            return None;
        }
        let (structure, after) = rest.split_at_mut(carried);
        if api == FN_INLPCREATESTRUCT {
            let mut create = CreateStructW::from_bytes(structure)?;
            // The name, NUL-terminated (a block too short for the terminator names none).
            create.name = if after.len() >= 2 {
                address_of(after.as_ptr())
            } else {
                0
            };
            structure.copy_from_slice(create.as_bytes());
        } else if api == FN_INOUTNCCALCSIZE && head.wparam != 0 {
            let (params, pos) = structure.split_at_mut(core::mem::size_of::<NcCalcSizeParams>());
            let mut calc = NcCalcSizeParams::from_bytes(params)?;
            calc.pos = address_of(pos.as_ptr());
            params.copy_from_slice(calc.as_bytes());
        }
        msg.lparam = address_of(structure.as_ptr()) as i32;
    }
    let answer = crate::message::invoke(head.proc, msg, false);
    Some(Served {
        answer,
        out: Output::Structure(rtl::callback::out_size(api, head.wparam)),
    })
}

/// [`serve`] for a text slot (another process's message: rtl::callback's notes): the procedure
/// `proc` called with `msg`, its lParam pointed at the text after the block's head — WM_SETTEXT's,
/// NUL-terminated; WM_COPYDATA's COPYDATASTRUCT, its lpData pointed at the bytes after it (0 for
/// none); WM_GETTEXT's buffer, past the answer word, zeroed first, its wParam the buffer's units.
/// The text messages reach the procedure in the wide form, translated for a narrow one. None for a
/// block too short for its slot.
fn serve_text(api: u32, proc: u32, mut msg: Msg, block: &mut [u8]) -> Option<Served> {
    let rest = block.get_mut(HEAD..)?;
    let at = address_of(rest.as_ptr());
    let structure = |answer| Served {
        answer,
        out: Output::Structure(0),
    };
    match api {
        FN_INSTRINGNULL => {
            if rest.len() < 2 || rest[rest.len() - 2..] != [0, 0] {
                return None;
            }
            msg.lparam = at as i32;
            Some(structure(crate::message::invoke(proc, msg, true)))
        }
        FN_COPYDATA => {
            let head = rest.get_mut(..2 * rtl::user::COPY_DATA_HEAD)?;
            let count = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
            let data = if count == 0 || at == 0 {
                0
            } else {
                at.wrapping_add(2 * rtl::user::COPY_DATA_HEAD as u32)
            };
            head[8..12].copy_from_slice(&data.to_le_bytes());
            msg.lparam = at as i32;
            Some(structure(crate::message::invoke(proc, msg, false)))
        }
        _ => {
            if rest.len() < 4 {
                return None;
            }
            let room = (rest.len() - 4) / 2;
            rest[4..].fill(0);
            msg.lparam = address_of(rest[4..].as_ptr()) as i32;
            msg.wparam = room as u32;
            let answer = crate::message::invoke(proc, msg, true);
            let count = (answer.max(0) as usize).min(room);
            rest[..4].copy_from_slice(&answer.to_ne_bytes());
            Some(Served {
                answer,
                out: Output::Block(HEAD, 4 + 2 * count),
            })
        }
    }
}

/// What the smoke routine reaches: the kernel's smoke entry, and the thread's memory.
pub trait Kernel {
    /// The smoke entry asked for `request`: its status, and the reply it wrote (zero when none).
    fn call(&mut self, request: SmokeRequest) -> (u32, SmokeReply);
    /// As [`Kernel::call`], under an exception registration of the routine's own: the code of the
    /// exception it took instead, if one escaped the call.
    fn guarded_call(&mut self, request: SmokeRequest) -> Result<(u32, SmokeReply), u32>;
    /// Whether the byte at `address` can be read, read under the probe's own registration.
    fn readable(&mut self, address: u32) -> bool;
    /// Read the byte at `address`, under no registration of the routine's own.
    fn touch(&mut self, address: u32);
    /// Ask the smoke entry to queue the smoke APC routine on this thread: the service's status, and
    /// the context the routine left (0 if it did not run).
    fn queue_apc(&mut self) -> (u32, u32);
}

/// The smoke routine's answer to `request` (see [`rtl::callback::op`]): its status and reply.
pub fn answer(request: SmokeRequest, kernel: &mut impl Kernel) -> (u32, SmokeReply) {
    let reply = |answer, detail| SmokeReply { answer, detail };
    let deeper = |op| SmokeRequest {
        op,
        depth: request.depth.saturating_sub(1),
        argument: request.argument,
    };
    match request.op {
        op::ECHO => (STATUS_SUCCESS, reply(request.argument.wrapping_add(1), 0)),
        op::NEST if request.depth <= 1 => (STATUS_SUCCESS, reply(1, 1)),
        op::NEST => match kernel.call(deeper(op::NEST)) {
            (STATUS_SUCCESS, inner) => (
                STATUS_SUCCESS,
                reply(
                    inner.answer.wrapping_mul(10).wrapping_add(request.depth),
                    request.depth,
                ),
            ),
            (status, inner) => (status, inner),
        },
        op::PROBE => (
            STATUS_SUCCESS,
            reply(kernel.readable(request.argument) as u32, 0),
        ),
        op::ESCAPE => match kernel.guarded_call(deeper(op::RAISE)) {
            Err(code) => (STATUS_SUCCESS, reply(code, 0)),
            Ok((status, _)) => (status, reply(0, 0)),
        },
        op::RAISE => {
            kernel.touch(request.argument);
            (STATUS_SUCCESS, reply(0, 0))
        }
        op::APC => {
            let (status, context) = kernel.queue_apc();
            (status, reply(context, 0))
        }
        op::EXIT => kernel.call(deeper(op::EXIT)),
        _ => (STATUS_INVALID_PARAMETER, reply(0, 0)),
    }
}

#[cfg(all(target_arch = "x86", not(test)))]
pub use target::attach;

#[cfg(all(target_arch = "x86", not(test)))]
mod target {
    use core::sync::atomic::{AtomicU32, Ordering};

    use rtl::callback::{
        op,
        SmokeReply,
        SmokeRequest,
        CALLBACK_SLOTS,
        FN_COPYDATA,
        FN_DWORD,
        FN_INLPCREATESTRUCT,
        FN_INLPWINDOWPOS,
        FN_INOUTLPPOINT5,
        FN_INOUTLPWINDOWPOS,
        FN_INOUTNCCALCSIZE,
        FN_INOUTSTYLECHANGE,
        FN_INSTRINGNULL,
        FN_NCDESTROY,
        FN_OUTSTRING,
        OUT_MAX,
        SMOKE_API,
    };
    use rtl::pod::Pod;
    use rtl::status::{STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};
    use rtl::stub::Memory;

    use super::{answer, serve, Kernel, Output};
    use crate::imports;

    /// A slot's routine: the input block's address and length.
    type Routine = unsafe extern "system" fn(usize, u32) -> u32;

    /// The table KernelCallbackTable points at.
    static TABLE: [Routine; CALLBACK_SLOTS] = {
        let mut table = [unserved as Routine; CALLBACK_SLOTS];
        table[FN_DWORD as usize] = fn_dword;
        table[FN_NCDESTROY as usize] = fn_ncdestroy;
        table[FN_INLPCREATESTRUCT as usize] = fn_inlpcreatestruct;
        table[FN_INLPWINDOWPOS as usize] = fn_inlpwindowpos;
        table[FN_INOUTNCCALCSIZE as usize] = fn_inoutnccalcsize;
        table[FN_INOUTLPWINDOWPOS as usize] = fn_inoutlpwindowpos;
        table[FN_INOUTSTYLECHANGE as usize] = fn_inoutstylechange;
        table[FN_INOUTLPPOINT5 as usize] = fn_inoutlppoint5;
        table[FN_COPYDATA as usize] = fn_copydata;
        table[FN_INSTRINGNULL as usize] = fn_instringnull;
        table[FN_OUTSTRING as usize] = fn_outstring;
        table[SMOKE_API as usize] = smoke;
        table
    };

    /// Point the PEB's KernelCallbackTable at user32's table (its process attach).
    pub fn attach() {
        rtl::sys::set_kernel_callback_table(TABLE.as_ptr() as usize);
    }

    /// A slot not served yet.
    unsafe extern "system" fn unserved(_input: usize, _length: u32) -> u32 {
        STATUS_NOT_IMPLEMENTED
    }

    /// A message slot's routine: the message the block at `input` carries served ([`serve`]), its
    /// answer handed back through NtCallbackReturn, then (an `__fnINOUT*` slot's) the structure
    /// as the procedure left it.
    ///
    /// # Safety
    ///
    /// `input` and `length` are the dispatcher's: the kernel's copy of the block, on this
    /// callback's stack, writable.
    unsafe fn message(api: u32, input: usize, length: u32) -> u32 {
        // SAFETY: the caller's contract.
        let block = unsafe { core::slice::from_raw_parts_mut(input as *mut u8, length as usize) };
        let Some(served) = serve(api, block) else {
            return STATUS_INVALID_PARAMETER;
        };
        let out = match served.out {
            // WM_GETTEXT's answer and text, straight from the block (`serve` keeps it inside).
            Output::Block(from, length) => {
                return imports::callback_return(&block[from..from + length], STATUS_SUCCESS);
            }
            Output::Structure(out) => out,
        };
        let mut output = [0u8; 4 + OUT_MAX];
        output[..4].copy_from_slice(&served.answer.to_ne_bytes());
        let at = core::mem::size_of::<rtl::callback::CallbackMsg>();
        // `serve` checked the block holds the structure; `out` is never longer than it.
        let out = out.min(OUT_MAX).min(block.len() - at);
        output[4..4 + out].copy_from_slice(&block[at..at + out]);
        imports::callback_return(&output[..4 + out], STATUS_SUCCESS)
    }

    /// `__fnDWORD`.
    unsafe extern "system" fn fn_dword(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_DWORD, input, length) }
    }

    /// `__fnNCDESTROY`.
    unsafe extern "system" fn fn_ncdestroy(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_NCDESTROY, input, length) }
    }

    /// `__fnINLPCREATESTRUCT`.
    unsafe extern "system" fn fn_inlpcreatestruct(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_INLPCREATESTRUCT, input, length) }
    }

    /// `__fnINLPWINDOWPOS`.
    unsafe extern "system" fn fn_inlpwindowpos(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_INLPWINDOWPOS, input, length) }
    }

    /// `__fnINOUTNCCALCSIZE`.
    unsafe extern "system" fn fn_inoutnccalcsize(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_INOUTNCCALCSIZE, input, length) }
    }

    /// `__fnINOUTLPWINDOWPOS`.
    unsafe extern "system" fn fn_inoutlpwindowpos(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_INOUTLPWINDOWPOS, input, length) }
    }

    /// `__fnINOUTSTYLECHANGE`.
    unsafe extern "system" fn fn_inoutstylechange(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_INOUTSTYLECHANGE, input, length) }
    }

    /// `__fnINOUTLPPOINT5`.
    unsafe extern "system" fn fn_inoutlppoint5(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_INOUTLPPOINT5, input, length) }
    }

    /// `__fnCOPYDATA`.
    unsafe extern "system" fn fn_copydata(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_COPYDATA, input, length) }
    }

    /// `__fnINSTRINGNULL`.
    unsafe extern "system" fn fn_instringnull(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_INSTRINGNULL, input, length) }
    }

    /// `__fnOUTSTRING`.
    unsafe extern "system" fn fn_outstring(input: usize, length: u32) -> u32 {
        // SAFETY: the dispatcher's block.
        unsafe { message(FN_OUTSTRING, input, length) }
    }

    /// The smoke slot: the request answered through NtCallbackReturn.
    unsafe extern "system" fn smoke(input: usize, length: u32) -> u32 {
        if length as usize != core::mem::size_of::<SmokeRequest>() {
            return STATUS_INVALID_PARAMETER;
        }
        // SAFETY: the kernel's copy of the request, on this callback's stack.
        let request = unsafe { (input as *const SmokeRequest).read_unaligned() };
        let (status, reply) = answer(request, &mut Target);
        imports::callback_return(reply.as_bytes(), status)
    }

    /// The context the smoke APC routine left.
    static APC_CONTEXT: AtomicU32 = AtomicU32::new(0);

    /// The smoke APC routine: leaves its context for the callback that queued it.
    unsafe extern "system" fn smoke_apc(context: u32, _argument1: u32, _argument2: u32) {
        APC_CONTEXT.store(context, Ordering::Relaxed);
    }

    /// The smoke's kernel entry with `request` (NtQuerySystemInformation of the smoke class).
    fn service(request: &SmokeRequest, reply: &mut SmokeReply) -> u32 {
        imports::smoke_query(request.as_bytes(), reply)
    }

    unsafe extern "C" {
        /// Call `routine(argument)` under an exception registration of its own: its answer, or
        /// 0xFFFFFFFF with the code of an exception that escaped it in `code`.
        fn f2k_u32_guarded_call(
            routine: extern "C" fn(u32) -> u32,
            argument: u32,
            code: *mut u32,
        ) -> u32;
    }

    /// The guarded registration's unwind: the chain unwound to it before it resumes its call.
    extern "C" fn guard_unwind(frame: u32, record: u32) {
        // SAFETY: called by the registration's own handler, with its frame and the record it was
        // handed; the frames above it are given up.
        unsafe { imports::unwind_to(frame, record) }
    }

    /// The guarded call's routine: the service asked for a RAISE callback (`argument`'s address),
    /// which escapes.
    extern "C" fn raise_through_kernel(argument: u32) -> u32 {
        let mut reply = SmokeReply::default();
        service(
            &SmokeRequest {
                op: op::RAISE,
                depth: 0,
                argument,
            },
            &mut reply,
        )
    }

    struct Target;

    impl Kernel for Target {
        fn call(&mut self, request: SmokeRequest) -> (u32, SmokeReply) {
            let mut reply = SmokeReply::default();
            let status = service(&request, &mut reply);
            (status, reply)
        }

        fn guarded_call(&mut self, request: SmokeRequest) -> Result<(u32, SmokeReply), u32> {
            let mut code = 0;
            // SAFETY: the routine and the code are this frame's; the registration is the call's.
            let status =
                unsafe { f2k_u32_guarded_call(raise_through_kernel, request.argument, &mut code) };
            if status == u32::MAX {
                Err(code)
            } else {
                Ok((status, SmokeReply::default()))
            }
        }

        fn readable(&mut self, address: u32) -> bool {
            imports::Probed.readable(address as usize)
        }

        fn touch(&mut self, address: u32) {
            // SAFETY: none: the read may fault, and the fault is the point (an exception the
            // routine does not take).
            unsafe { core::ptr::read_volatile(address as *const u8) };
        }

        fn queue_apc(&mut self) -> (u32, u32) {
            APC_CONTEXT.store(0, Ordering::Relaxed);
            let mut reply = SmokeReply::default();
            let status = service(
                &SmokeRequest {
                    op: op::APC,
                    depth: 0,
                    argument: smoke_apc as *const () as usize as u32,
                },
                &mut reply,
            );
            (status, APC_CONTEXT.load(Ordering::Relaxed))
        }
    }

    // The guarded call: a registration {next, handler, resume} right under the saved registers.
    // Its handler takes an exception (an unwind passing through searches on): the chain unwound to
    // the registration, then the call's frame back from it and on to the resume point, the code in
    // EAX.
    core::arch::global_asm!(
        ".text",
        ".p2align 4",
        ".Lf2k_u32_guard_handler:",
        "    mov eax, dword ptr [esp+4]",
        "    test dword ptr [eax+4], 6",
        "    jnz .Lf2k_u32_guard_search",
        "    mov ebx, dword ptr [esp+8]",
        "    mov esi, dword ptr [eax]",
        "    push eax",
        "    push ebx",
        "    call {unwind}",
        "    mov eax, esi",
        "    mov esp, ebx",
        "    lea ebp, [ebx+24]",
        "    jmp dword ptr [ebx+8]",
        ".Lf2k_u32_guard_search:",
        "    mov eax, 1",
        "    ret",
        ".p2align 4",
        ".globl _f2k_u32_guarded_call",
        "_f2k_u32_guarded_call:",
        "    push ebp",
        "    mov ebp, esp",
        "    push ebx",
        "    push esi",
        "    push edi",
        "    mov eax, offset .Lf2k_u32_guard_resume",
        "    push eax",
        "    mov eax, offset .Lf2k_u32_guard_handler",
        "    push eax",
        "    push dword ptr fs:[0]",
        "    mov dword ptr fs:[0], esp",
        "    push dword ptr [ebp+12]",
        "    call dword ptr [ebp+8]",
        "    add esp, 4",
        "    jmp .Lf2k_u32_guard_done",
        ".Lf2k_u32_guard_resume:",
        "    mov ecx, dword ptr [ebp+16]",
        "    mov dword ptr [ecx], eax",
        "    mov eax, -1",
        ".Lf2k_u32_guard_done:",
        "    mov ecx, dword ptr [esp]",
        "    mov dword ptr fs:[0], ecx",
        "    lea esp, [ebp-12]",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
        unwind = sym guard_unwind,
    );
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use rtl::callback::op;
    use rtl::status::STATUS_STACK_OVERFLOW;
    use rtl::user::{WM_COPYDATA, WM_CREATE, WM_DESTROY, WM_GETTEXT, WM_SETTEXT};

    use super::*;
    use crate::imports::host::procedure;

    std::thread_local! {
        static HEARD: RefCell<std::vec::Vec<(u32, u32, u32, u32)>> =
            const { RefCell::new(std::vec::Vec::new()) };
    }

    fn listener(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        HEARD.with(|heard| {
            heard
                .borrow_mut()
                .push((window, message, wparam, lparam as u32))
        });
        -7
    }

    fn block(head: CallbackMsg, carried: &[u8]) -> std::vec::Vec<u8> {
        let mut block = head.as_bytes().to_vec();
        block.extend_from_slice(carried);
        block
    }

    /// A plain message reaches the procedure as it is, and its answer is the routine's; a
    /// structure's lParam points at the block's copy (where an address fits one), a
    /// CREATESTRUCTW's lpszName at the name after it.
    #[test]
    fn a_message_slot_calls_the_procedure() {
        let proc = procedure(listener);
        let head = |message, lparam| CallbackMsg {
            proc,
            hwnd: 0x40,
            message,
            wparam: 9,
            lparam,
        };
        let mut plain = block(head(WM_DESTROY, 77), &[]);
        assert_eq!(
            serve(FN_DWORD, &mut plain),
            Some(Served {
                answer: -7,
                out: Output::Structure(0)
            })
        );
        let heard = HEARD.with(|heard| heard.take());
        assert_eq!(heard, [(0x40, WM_DESTROY, 9, 77)]);

        let create = CreateStructW {
            x: 5,
            class: 0xC123,
            ..CreateStructW::default()
        };
        let mut carried = create.as_bytes().to_vec();
        carried.extend_from_slice(&[b'a', 0, 0, 0]);
        let mut created = block(head(WM_CREATE, 0), &carried);
        assert_eq!(
            serve(FN_INLPCREATESTRUCT, &mut created),
            Some(Served {
                answer: -7,
                out: Output::Structure(0)
            })
        );
        let at = created.as_ptr() as usize + core::mem::size_of::<CallbackMsg>();
        let written =
            CreateStructW::read_from(&created, core::mem::size_of::<CallbackMsg>()).unwrap();
        assert_eq!((written.x, written.class), (5, 0xC123));
        assert_eq!(written.name, address_of((at + 48) as *const u8));
        let heard = HEARD.with(|heard| heard.take());
        assert_eq!(heard.len(), 1);
        assert_eq!(heard[0].3, address_of(at as *const u8));
    }

    /// The in-out slots hand their structure back after the answer (its length the slot's, by
    /// WM_NCCALCSIZE's form); the input-only WM_WINDOWPOSCHANGED's hands back none. WM_NCCALCSIZE's
    /// NCCALCSIZE_PARAMS (wParam TRUE) has its lppos pointed at the WINDOWPOS after it.
    #[test]
    fn the_in_out_slots_hand_their_structure_back() {
        let proc = procedure(listener);
        let head = |message, wparam| CallbackMsg {
            proc,
            hwnd: 0x40,
            message,
            wparam,
            lparam: 0,
        };
        let served = |api, message, wparam, carried: &[u8]| {
            let mut block = block(head(message, wparam), carried);
            let served = serve(api, &mut block);
            (served, block)
        };
        let rect = Rect::new(1, 2, 3, 4);
        let (s, _) = served(FN_INOUTNCCALCSIZE, 0x83, 0, rect.as_bytes());
        assert_eq!(
            s,
            Some(Served {
                answer: -7,
                out: Output::Structure(16)
            })
        );
        let pos = WindowPos {
            cx: 250,
            ..WindowPos::default()
        };
        let (s, _) = served(FN_INOUTLPWINDOWPOS, 0x46, 0, pos.as_bytes());
        assert_eq!(
            s,
            Some(Served {
                answer: -7,
                out: Output::Structure(28)
            })
        );
        let (s, _) = served(FN_INLPWINDOWPOS, 0x47, 0, pos.as_bytes());
        assert_eq!(
            s,
            Some(Served {
                answer: -7,
                out: Output::Structure(0)
            })
        );
        let style = StyleStruct {
            style_old: 1,
            style_new: 2,
        };
        let (s, _) = served(FN_INOUTSTYLECHANGE, 0x7C, 0xFFFF_FFF0, style.as_bytes());
        assert_eq!(
            s,
            Some(Served {
                answer: -7,
                out: Output::Structure(8)
            })
        );
        let mmi = MinMaxInfo {
            max_track: rtl::user::Point { x: 400, y: 300 },
            ..MinMaxInfo::default()
        };
        let (s, block) = served(FN_INOUTLPPOINT5, 0x24, 0, mmi.as_bytes());
        assert_eq!(
            s,
            Some(Served {
                answer: -7,
                out: Output::Structure(40)
            })
        );
        let at = core::mem::size_of::<CallbackMsg>();
        assert_eq!(MinMaxInfo::read_from(&block, at), Some(mmi));
        let heard = HEARD.with(|heard| heard.take());
        assert_eq!(
            heard.last().map(|h| h.3),
            Some(address_of((block.as_ptr() as usize + at) as *const u8))
        );

        let params = NcCalcSizeParams {
            rects: [rect; 3],
            pos: 0xDEAD,
        };
        let mut carried = params.as_bytes().to_vec();
        carried.extend_from_slice(pos.as_bytes());
        let (s, block) = served(FN_INOUTNCCALCSIZE, 0x83, 1, &carried);
        assert_eq!(
            s,
            Some(Served {
                answer: -7,
                out: Output::Structure(52)
            })
        );
        let at = core::mem::size_of::<CallbackMsg>();
        let written = NcCalcSizeParams::read_from(&block, at).unwrap();
        assert_eq!(written.rects, [rect; 3]);
        assert_eq!(
            written.pos,
            address_of((block.as_ptr() as usize + at + 52) as *const u8)
        );
        // The TRUE form's block holds the WINDOWPOS too: without it, nothing is called.
        let (s, _) = served(FN_INOUTNCCALCSIZE, 0x83, 1, params.as_bytes());
        assert_eq!(s, None);
        HEARD.with(|heard| heard.take());
    }

    fn five(window: u32, message: u32, wparam: u32, lparam: i32) -> i32 {
        listener(window, message, wparam, lparam);
        5
    }

    /// The text slots: WM_SETTEXT's text, NUL-terminated (a block without its terminator calls
    /// nothing); WM_COPYDATA's COPYDATASTRUCT, its lpData pointed at the bytes after it (0 for
    /// none, or where no address fits a parameter); WM_GETTEXT's buffer zeroed, its wParam the
    /// buffer's units, the output the answer word and as many units as the answer says, no more
    /// than the buffer holds.
    #[test]
    fn the_text_slots_point_into_the_block() {
        let head = |proc, message, wparam| CallbackMsg {
            proc,
            hwnd: 0x40,
            message,
            wparam,
            lparam: 0,
        };
        let proc = procedure(listener);
        let mut text = block(head(proc, WM_SETTEXT, 0), &[0x48, 0, 0x69, 0, 0, 0]);
        assert_eq!(
            serve(FN_INSTRINGNULL, &mut text),
            Some(Served {
                answer: -7,
                out: Output::Structure(0)
            })
        );
        let mut unterminated = block(head(proc, WM_SETTEXT, 0), &[0x48, 0]);
        assert_eq!(serve(FN_INSTRINGNULL, &mut unterminated), None);
        let heard = HEARD.with(|heard| heard.take());
        assert_eq!(heard.len(), 1);
        assert_eq!(heard[0].3, address_of(text[HEAD..].as_ptr()));

        let mut data = vec![0x1D, 0x4B, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0];
        data.extend_from_slice(b"abc\0");
        let mut copy = block(head(proc, WM_COPYDATA, 0x40), &data);
        assert!(serve(FN_COPYDATA, &mut copy).is_some());
        let at = address_of(copy[HEAD..].as_ptr());
        let expected = if at == 0 { 0 } else { at + 12 };
        assert_eq!(copy[HEAD + 8..HEAD + 12], expected.to_le_bytes());
        let mut none = block(head(proc, WM_COPYDATA, 0x40), &[0; 12]);
        assert!(serve(FN_COPYDATA, &mut none).is_some());
        assert_eq!(none[HEAD + 8..HEAD + 12], [0; 4]);
        assert_eq!(
            serve(FN_COPYDATA, &mut block(head(proc, WM_COPYDATA, 0), &[0; 8])),
            None
        );
        HEARD.with(|heard| heard.take());

        let mut buffer = block(head(procedure(five), WM_GETTEXT, 99), &[0xAA; 4 + 6]);
        assert_eq!(
            serve(FN_OUTSTRING, &mut buffer),
            Some(Served {
                answer: 5,
                out: Output::Block(HEAD, 4 + 6)
            })
        );
        assert_eq!(buffer[HEAD..HEAD + 4], 5i32.to_ne_bytes());
        assert_eq!(buffer[HEAD + 4..], [0; 6], "zeroed for the procedure");
        let heard = HEARD.with(|heard| heard.take());
        assert_eq!(
            (heard[0].1, heard[0].2),
            (WM_GETTEXT, 3),
            "the buffer's units"
        );
        let mut short = block(head(proc, WM_GETTEXT, 3), &[0; 2]);
        assert_eq!(serve(FN_OUTSTRING, &mut short), None);
    }

    /// A block too short for its slot's structure, or a slot that is not a message's, calls
    /// nothing.
    #[test]
    fn a_short_block_or_another_slot_calls_nothing() {
        let proc = procedure(listener);
        let head = CallbackMsg {
            proc,
            ..CallbackMsg::default()
        };
        assert_eq!(serve(FN_INOUTNCCALCSIZE, &mut block(head, &[0; 8])), None);
        assert_eq!(serve(FN_DWORD, &mut [0; 8]), None);
        assert_eq!(serve(rtl::callback::SMOKE_API, &mut block(head, &[])), None);
        assert!(HEARD.with(|heard| heard.take()).is_empty());
    }

    /// A kernel that answers NEST itself, as the real one does by calling back, until `refuse_at`
    /// levels deep; records what else the routine asked for.
    #[derive(Default)]
    struct Fake {
        depth: u32,
        refuse_at: u32,
        asked: Vec<SmokeRequest>,
        escape: Option<u32>,
        readable: bool,
    }

    impl Kernel for Fake {
        fn call(&mut self, request: SmokeRequest) -> (u32, SmokeReply) {
            self.asked.push(request);
            if request.op != op::NEST {
                return (0xC000_0001, SmokeReply::default());
            }
            self.depth += 1;
            if self.refuse_at != 0 && self.depth >= self.refuse_at {
                return (STATUS_STACK_OVERFLOW, SmokeReply::default());
            }
            let answered = answer(request, self);
            self.depth -= 1;
            answered
        }

        fn guarded_call(&mut self, request: SmokeRequest) -> Result<(u32, SmokeReply), u32> {
            self.asked.push(request);
            self.escape
                .map_or(Ok((STATUS_SUCCESS, SmokeReply::default())), Err)
        }

        fn readable(&mut self, _address: u32) -> bool {
            self.readable
        }

        fn touch(&mut self, address: u32) {
            self.asked.push(SmokeRequest {
                op: 0,
                depth: 0,
                argument: address,
            });
        }

        fn queue_apc(&mut self) -> (u32, u32) {
            (STATUS_SUCCESS, rtl::callback::SMOKE_APC_CONTEXT)
        }
    }

    fn request(op: u32, depth: u32, argument: u32) -> SmokeRequest {
        SmokeRequest {
            op,
            depth,
            argument,
        }
    }

    #[test]
    fn echo_answers_the_argument_plus_one() {
        let (status, reply) = answer(request(op::ECHO, 0, 0x1234), &mut Fake::default());
        assert_eq!((status, reply.answer), (STATUS_SUCCESS, 0x1235));
    }

    /// Three deep: 1, then 12, then 123, each level calling the next through the kernel.
    #[test]
    fn nesting_builds_the_answer_level_by_level() {
        let mut kernel = Fake::default();
        let (status, reply) = answer(request(op::NEST, 3, 0), &mut kernel);
        assert_eq!((status, reply.answer), (STATUS_SUCCESS, 123));
        assert_eq!(kernel.asked.len(), 2);
    }

    /// A refused level's status comes back out through every level above it.
    #[test]
    fn a_refusal_propagates_outward() {
        let mut kernel = Fake {
            refuse_at: 4,
            ..Fake::default()
        };
        let (status, _) = answer(request(op::NEST, 1000, 0), &mut kernel);
        assert_eq!(status, STATUS_STACK_OVERFLOW);
        assert_eq!(kernel.asked.len(), 4);
    }

    /// ESCAPE asks for a RAISE of the same address under its registration and answers the code it
    /// caught; RAISE touches the address unguarded.
    #[test]
    fn escape_answers_the_code_it_caught() {
        let mut kernel = Fake {
            escape: Some(0xC000_0005),
            ..Fake::default()
        };
        let (status, reply) = answer(request(op::ESCAPE, 0, 0x7FFF_0000), &mut kernel);
        assert_eq!((status, reply.answer), (STATUS_SUCCESS, 0xC000_0005));
        assert_eq!(kernel.asked, [request(op::RAISE, 0, 0x7FFF_0000)]);

        let mut kernel = Fake::default();
        answer(request(op::RAISE, 0, 0x7FFF_0000), &mut kernel);
        assert_eq!(kernel.asked, [request(0, 0, 0x7FFF_0000)]);
    }

    #[test]
    fn probe_apc_and_exit() {
        let mut kernel = Fake::default();
        assert_eq!(
            answer(request(op::PROBE, 0, 0x7FFF_0000), &mut kernel)
                .1
                .answer,
            0
        );
        assert_eq!(
            answer(request(op::APC, 0, 0), &mut kernel).1.answer,
            rtl::callback::SMOKE_APC_CONTEXT
        );
        answer(request(op::EXIT, 2, 0), &mut kernel);
        answer(request(op::EXIT, 1, 0), &mut kernel);
        assert_eq!(
            kernel.asked,
            [request(op::EXIT, 1, 0), request(op::EXIT, 0, 0)]
        );
        assert_eq!(
            answer(request(99, 0, 0), &mut kernel).0,
            STATUS_INVALID_PARAMETER
        );
    }
}

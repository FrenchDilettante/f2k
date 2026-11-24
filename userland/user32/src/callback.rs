//! The kernel's user-mode callbacks, user32's side (Windows 2000's apfnDispatch): the table its
//! process attach points PEB.KernelCallbackTable at ([`attach`]), which ntdll's
//! KiUserCallbackDispatcher calls through with the input block's address and length.
//!
//! The Windows 2000 slots (`__fnDWORD`, `__fnINLPCREATESTRUCT`, ...) are not served yet: each
//! answers STATUS_NOT_IMPLEMENTED, by returning it (the dispatcher hands a returned value to
//! NtCallbackReturn as the status). The last slot is F2K's smoke routine ([`rtl::callback`]), which
//! the kernel calls only in its `callback-smoke` boot; [`answer`] decides what it does, over the
//! kernel and the thread as [`Kernel`] reaches them.

use rtl::callback::{op, SmokeReply, SmokeRequest};
use rtl::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

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

    use rtl::callback::{op, SmokeReply, SmokeRequest, CALLBACK_SLOTS, SMOKE_API};
    use rtl::pod::Pod;
    use rtl::status::{STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED};
    use rtl::stub::Memory;

    use super::{answer, Kernel};
    use crate::imports;

    /// A slot's routine: the input block's address and length.
    type Routine = unsafe extern "system" fn(usize, u32) -> u32;

    /// The table KernelCallbackTable points at.
    static TABLE: [Routine; CALLBACK_SLOTS] = {
        let mut table = [unserved as Routine; CALLBACK_SLOTS];
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
    use rtl::callback::op;
    use rtl::status::STATUS_STACK_OVERFLOW;

    use super::*;

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

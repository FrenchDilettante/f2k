//! Anonymous pipes: CreatePipe over the named-pipe services and the file stand-in's open
//! ([`crate::nt::pipes`], [`crate::nt::files`]), PeekNamedPipe over the stand-in pipe's peek. The
//! pipe fixture is the contract on the machine; these pin what kernel32 itself decides — the
//! services it asks and how, the counts it hands back, the errors it sets.

use super::last_error;
use crate::base::SecurityAttributes;
use crate::nt::files::{calls, Call};
use crate::nt::host::{CLOSED, FAIL_NEXT, HANDLE};
use crate::nt::pipes::{pipe_calls, PipeCall, FAIL_AFTER_CREATE, PIPE, PIPE_READ};
use crate::pipes::*;

const UNTOUCHED: u32 = 0xF2F2_F2F2;

fn closed() -> Vec<u32> {
    CLOSED.with(|closed| std::mem::take(&mut *closed.borrow_mut()))
}

/// The stand-in pipe holding `bytes`.
fn holding(bytes: &[u8]) {
    PIPE.with(|pipe| pipe.borrow_mut().bytes = bytes.to_vec());
    pipe_calls();
}

/// CreatePipe makes the read end with NtCreateNamedPipeFile (GENERIC_READ, FILE_WRITE_ATTRIBUTES
/// and SYNCHRONIZE; a name of its own under `\Device\NamedPipe\`, case-insensitive and inheritable
/// as the attributes ask; shared both ways; FILE_CREATE, synchronous; a byte stream of one
/// instance, the size both quotas, a 120-second default timeout), then opens the write end with
/// NtOpenFile (GENERIC_WRITE and SYNCHRONIZE, the same name, sharing reading, synchronous and no
/// directory), and stores both handles. Each call's name is new.
///
/// Pins: kernel32.CreatePipe
#[test]
fn create_pipe_makes_the_read_end_and_opens_the_write_end() {
    pipe_calls();
    calls();
    let security = SecurityAttributes {
        length: 12,
        security_descriptor: core::ptr::null(),
        inherit_handle: 1,
    };
    let (mut read, mut write) = (UNTOUCHED, UNTOUCHED);
    let made = unsafe { create_pipe(&mut read, &mut write, &security, 4096) };
    assert_eq!((made, read, write), (1, PIPE_READ, HANDLE));
    let Some(PipeCall::Create {
        access,
        name,
        attributes,
        share,
        disposition,
        options,
        modes,
        instances,
        quotas,
        timeout,
    }) = pipe_calls().pop()
    else {
        panic!("no create");
    };
    assert_eq!(access, 0x8010_0100);
    let (prefix, numbers) = name.split_at("\\Device\\NamedPipe\\Win32Pipes.".len());
    assert_eq!(prefix, "\\Device\\NamedPipe\\Win32Pipes.");
    let digits: Vec<&str> = numbers.split('.').collect();
    assert!(
        digits.len() == 2
            && digits
                .iter()
                .all(|part| part.len() == 8 && part.chars().all(|c| c.is_ascii_hexdigit())),
        "{name}"
    );
    assert_eq!(
        (attributes, share, disposition, options),
        (0x42, 3, 2, 0x20)
    );
    assert_eq!((modes, instances, quotas), ([0, 0, 0], 1, [4096, 4096]));
    assert_eq!(timeout, Some(-1_200_000_000));
    match calls().as_slice() {
        [Call::Open {
            access,
            name: opened,
            share,
            disposition,
            options,
            ..
        }] => {
            assert_eq!(
                (*access, opened, *share, *disposition, *options),
                (0x4010_0000, &name, 1, 1, 0x60)
            );
        }
        other => panic!("{other:?}"),
    }

    // Not inheritable, no attributes: the flags case-insensitive alone, and another name.
    let made = unsafe { create_pipe(&mut read, &mut write, core::ptr::null(), 0) };
    assert_eq!(made, 1);
    let Some(PipeCall::Create {
        name: second,
        attributes,
        quotas,
        ..
    }) = pipe_calls().pop()
    else {
        panic!("no create");
    };
    assert_eq!((attributes, quotas), (0x40, [0, 0]));
    assert_ne!(second, name, "every pipe has a name of its own");
    calls();
}

/// A failed create sets its status's error and stores no handle; a failed open of the write end
/// closes the read end again.
///
/// Pins: kernel32.CreatePipe
#[test]
fn a_failed_create_pipe_keeps_no_handle() {
    pipe_calls();
    calls();
    closed();
    let (mut read, mut write) = (UNTOUCHED, UNTOUCHED);
    FAIL_NEXT.with(|next| next.set(0xC000_009A));
    let made = unsafe { create_pipe(&mut read, &mut write, core::ptr::null(), 0) };
    assert_eq!(
        (made, read, write, last_error()),
        (0, UNTOUCHED, UNTOUCHED, 1450)
    );
    assert!(calls().is_empty(), "no open after a failed create");

    FAIL_AFTER_CREATE.with(|after| after.set(0xC000_011F));
    let made = unsafe { create_pipe(&mut read, &mut write, core::ptr::null(), 0) };
    assert_eq!(
        (made, read, write, last_error()),
        (0, UNTOUCHED, UNTOUCHED, 4)
    );
    assert_eq!(closed(), [PIPE_READ]);
    pipe_calls();
    calls();
}

/// PeekNamedPipe asks the pipe's peek for its header and the buffer's size: the bytes copied, the
/// count, the total, and what is left of the message (0 less the count, a byte stream's); a peek
/// cut to the buffer is a success; counts not asked are not written, nor a buffer not given.
///
/// Pins: kernel32.PeekNamedPipe
#[test]
fn peek_named_pipe_hands_back_the_peek() {
    holding(b"peekdata12");
    let mut buffer = [0xCCu8; 64];
    let (mut read, mut total, mut left) = (UNTOUCHED, UNTOUCHED, UNTOUCHED);
    let ok = unsafe {
        peek_named_pipe(
            PIPE_READ,
            buffer.as_mut_ptr(),
            4,
            &mut read,
            &mut total,
            &mut left,
        )
    };
    assert_eq!((ok, read, total, left), (1, 4, 10, 4_294_967_292));
    assert_eq!(&buffer[..5], b"peek\xCC");
    assert_eq!(
        pipe_calls(),
        [PipeCall::Control {
            handle: PIPE_READ,
            code: 0x0011_400C,
            output_length: 16 + 4,
        }]
    );

    let ok = unsafe {
        peek_named_pipe(
            PIPE_READ,
            buffer.as_mut_ptr(),
            64,
            &mut read,
            &mut total,
            &mut left,
        )
    };
    assert_eq!((ok, read, total, left), (1, 10, 10, 4_294_967_286));
    assert_eq!(&buffer[..11], b"peekdata12\xCC");

    let mut total = UNTOUCHED;
    let none = core::ptr::null_mut();
    let ok =
        unsafe { peek_named_pipe(PIPE_READ, core::ptr::null_mut(), 0, none, &mut total, none) };
    assert_eq!((ok, total), (1, 10));
    pipe_calls();
}

/// A failed peek sets its status's error (the write end's STATUS_ACCESS_DENIED is 5, a broken
/// pipe's 109) and writes no count.
///
/// Pins: kernel32.PeekNamedPipe
#[test]
fn a_failed_peek_sets_its_error() {
    holding(b"x");
    for (status, error) in [(0xC000_0022, 5), (0xC000_014B, 109)] {
        FAIL_NEXT.with(|next| next.set(status));
        let (mut read, mut total, mut left) = (UNTOUCHED, UNTOUCHED, UNTOUCHED);
        let ok = unsafe {
            peek_named_pipe(
                PIPE_READ,
                core::ptr::null_mut(),
                0,
                &mut read,
                &mut total,
                &mut left,
            )
        };
        assert_eq!((ok, last_error()), (0, error));
        assert_eq!((read, total, left), (UNTOUCHED, UNTOUCHED, UNTOUCHED));
    }
    pipe_calls();
}

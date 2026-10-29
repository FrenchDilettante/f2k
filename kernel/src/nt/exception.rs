//! The exception services ntdll's user-mode dispatcher comes back to the kernel through (see
//! [`crate::user::seh`]): NtContinue resumes a CONTEXT — a handled exception's, an unwind's caller,
//! a delivered user APC's interrupted one — and NtRaiseException raises an exception user code
//! built: its first chance dispatched exactly as a fault is (the records copied below the context's
//! stack pointer, KiUserExceptionDispatcher entered), its second chance the process's end with the
//! code (no debugger, no exception port), as Windows 2000 does then.

use rtl::pod::Pod;

use super::call::UserAddr;
use crate::status::*;
use crate::user::seh::{self, Context, ExceptionRecord, EXCEPTION_MAXIMUM_PARAMETERS};

/// The record user code hands NtRaiseException: its fixed part and its parameters (the rest of the
/// 80 bytes zero). More than fifteen parameters is STATUS_INVALID_PARAMETER, as Windows 2000
/// checks; memory that cannot be read, STATUS_ACCESS_VIOLATION.
pub fn read_record(at: UserAddr) -> Result<ExceptionRecord, NtStatus> {
    let mut record = ExceptionRecord::default();
    at.read(&mut record.as_bytes_mut()[..seh::record_length(0)])?;
    if record.count as usize > EXCEPTION_MAXIMUM_PARAMETERS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let length = seh::record_length(record.count);
    at.read(&mut record.as_bytes_mut()[..length])?;
    Ok(record)
}

/// A CONTEXT in user memory.
pub fn read_context(context: UserAddr) -> Result<Context, NtStatus> {
    Ok(context.cast::<Context>().read()?)
}

#[cfg(target_arch = "x86")]
pub use target::{continue_context, raise_exception};

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::nt::call::{NtCall, NtResult};

    /// NtContinue(Context, TestAlert): the context's registers back into the caller's frame (the
    /// sets its flags name; see [`seh::restore_context`]), so the service returns into it — EAX
    /// included. TestAlert (a BOOLEAN) arms the delivery of the thread's next queued user APC, on
    /// the way out.
    pub fn continue_context(call: &mut NtCall, context: UserAddr, test_alert: bool) -> NtResult {
        let context = read_context(context)?;
        let frame = call.frame();
        seh::restore_context(frame, &context);
        if test_alert {
            crate::user::apc::test_alert();
        }
        // EAX as the context restored it: the convention writes it back unchanged.
        Ok(NtStatus(frame.eax))
    }

    /// NtRaiseException(ExceptionRecord, Context, FirstChance): the first chance (a BOOLEAN) puts
    /// the context into the caller's frame and dispatches the exception from there, as a fault is
    /// dispatched; records that cannot be written end the process with the code. The second chance
    /// ends the process with the code.
    pub fn raise_exception(
        call: &mut NtCall,
        record: UserAddr,
        context: UserAddr,
        first_chance: bool,
    ) -> NtResult {
        let record = read_record(record)?;
        let context = read_context(context)?;
        let (code, address) = (record.code, record.address);
        if !first_chance {
            seh::second_chance(code, address);
        }
        let frame = call.frame();
        seh::restore_context(frame, &context);
        if !seh::deliver(frame, &record, &context) {
            seh::second_chance(code, address);
        }
        // EAX as the delivery left it: the convention writes it back unchanged.
        Ok(NtStatus(frame.eax))
    }
}

// The host builds have no thread to resume (the pure parts above are tested).
#[cfg(not(target_arch = "x86"))]
use super::call::{NtCall, NtResult};
#[cfg(not(target_arch = "x86"))]
unserved! {
    continue_context(UserAddr, bool);
    raise_exception(UserAddr, UserAddr, bool);
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::user::syscall::host::{install, UserMemory};

    /// One page of user memory at 0x10000.
    struct Page(Vec<u8>);

    impl UserMemory for Page {
        fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
            let at = pointer
                .checked_sub(0x10000)
                .ok_or(STATUS_ACCESS_VIOLATION)? as usize;
            bytes.copy_from_slice(
                self.0
                    .get(at..at + bytes.len())
                    .ok_or(STATUS_ACCESS_VIOLATION)?,
            );
            Ok(())
        }

        fn write(&mut self, _: u32, _: &[u8]) -> Result<(), NtStatus> {
            Err(STATUS_ACCESS_VIOLATION)
        }
    }

    /// A raised record is read to its parameters; more than fifteen is an invalid parameter, a
    /// record running off the mapped memory an access violation.
    #[test]
    fn a_raised_record_is_read_to_its_parameters() {
        let mut page = vec![0xAAu8; 0x1000];
        for (i, word) in [0xE000_0001u32, 1, 0, 0x7C4E_1234, 2, 0xB, 0x16]
            .iter()
            .enumerate()
        {
            page[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let memory = Rc::new(RefCell::new(Page(page)));
        let _installed = install(memory.clone());
        let record = read_record(UserAddr(0x10000)).unwrap();
        assert_eq!(
            record,
            ExceptionRecord {
                code: 0xE000_0001,
                flags: 1,
                record: 0,
                address: 0x7C4E_1234,
                count: 2,
                information: [0xB, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            "nothing past the parameters"
        );
        memory.borrow_mut().0[16..20].copy_from_slice(&16u32.to_le_bytes());
        assert_eq!(
            read_record(UserAddr(0x10000)),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(read_record(UserAddr(0x10FF0)), Err(STATUS_ACCESS_VIOLATION));
        assert!(read_context(UserAddr(0x10000)).is_ok());
        assert!(read_context(UserAddr(0x10E00)).is_err());
    }
}

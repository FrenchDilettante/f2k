//! NtLoadDriver and NtUnloadDriver: a legacy driver loaded and unloaded by its service key's name
//! (`\Registry\Machine\System\CurrentControlSet\Services\<name>`), with no service control
//! manager, as a program reaches them through ntdll. The caller's token must hold
//! SeLoadDriverPrivilege enabled (STATUS_PRIVILEGE_NOT_HELD, checked before the name is read, as
//! the `drvload` capture's `load` block shows); the work is the I/O manager's
//! ([`crate::dev::io::load_driver`], [`crate::dev::io::unload_driver`]).

/// The longest service key name read, in units.
#[cfg(target_arch = "x86")]
const MAX_SERVICE_NAME: usize = 260;

#[cfg(target_arch = "x86")]
pub use services::*;

#[cfg(target_arch = "x86")]
mod services {
    use rtl::array_vec::ArrayVec;

    use super::super::call::{NtCall, NtResult, UserAddr};
    use super::MAX_SERVICE_NAME;
    use crate::ob;
    use crate::se::SE_LOAD_DRIVER_PRIVILEGE;
    use crate::status::*;

    /// Whether the calling process's token has SeLoadDriverPrivilege enabled
    /// (SeSinglePrivilegeCheck).
    fn privileged(call: &mut NtCall) -> Result<(), NtStatus> {
        let process = call.process().object();
        let token = ob::reference_process_token(process).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let enabled = ob::locked(|directory| {
            directory
                .token(token.id())
                .is_some_and(|body| body.enabled(SE_LOAD_DRIVER_PRIVILEGE))
        });
        drop(token);
        if enabled {
            Ok(())
        } else {
            Err(STATUS_PRIVILEGE_NOT_HELD)
        }
    }

    /// The DriverServiceName UNICODE_STRING at `at`, its units into `name`.
    /// STATUS_INVALID_PARAMETER past [`MAX_SERVICE_NAME`] units or an odd length.
    fn service_name(
        at: UserAddr,
        name: &mut ArrayVec<u16, MAX_SERVICE_NAME>,
    ) -> Result<(), NtStatus> {
        let string = at.cast::<rtl::nt::UnicodeString<u32>>().read()?;
        if string.length % 2 != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let units = name
            .try_extend_default(usize::from(string.length) / 2)
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        UserAddr(string.buffer).read_units(units)?;
        Ok(())
    }

    /// NtLoadDriver(DriverServiceName): the driver the service key names loaded and its
    /// DriverEntry run: DriverEntry's failure status, STATUS_IMAGE_ALREADY_LOADED while it is
    /// loaded, STATUS_OBJECT_NAME_NOT_FOUND for a key that does not exist.
    pub fn load_driver(call: &mut NtCall, name: UserAddr) -> NtResult {
        privileged(call)?;
        let mut units = ArrayVec::new();
        service_name(name, &mut units)?;
        crate::dev::io::load_driver(&units)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUnloadDriver(DriverServiceName): the driver's DriverUnload run and the driver gone:
    /// STATUS_OBJECT_NAME_NOT_FOUND when it is not loaded (or its key does not exist),
    /// STATUS_INVALID_DEVICE_REQUEST when it has no DriverUnload.
    pub fn unload_driver(call: &mut NtCall, name: UserAddr) -> NtResult {
        privileged(call)?;
        let mut units = ArrayVec::new();
        service_name(name, &mut units)?;
        crate::dev::io::unload_driver(&units)?;
        Ok(STATUS_SUCCESS)
    }
}

/// The host builds' services: the table names them; the drivers they load are the target's.
#[cfg(not(target_arch = "x86"))]
mod host {
    use super::super::call::{NtCall, NtResult, UserAddr};

    unserved! {
        load_driver(UserAddr);
        unload_driver(UserAddr);
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

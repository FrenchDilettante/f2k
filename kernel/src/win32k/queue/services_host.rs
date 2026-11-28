//! The host builds have no processes and no user memory: the services answer nothing (the host
//! tests drive the queues themselves).

use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

pub fn post_message(_: &mut NtCall, _: Handle, _: u32, _: u32, _: i32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

pub fn post_thread_message(_: &mut NtCall, _: u32, _: u32, _: u32, _: i32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

pub fn get_message(_: &mut NtCall, _: UserAddr, _: Handle, _: u32, _: u32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

pub fn peek_message(_: &mut NtCall, _: UserAddr, _: Handle, _: u32, _: u32, _: u32) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[allow(clippy::too_many_arguments)]
pub fn message_call(
    _: &mut NtCall,
    _: Handle,
    _: u32,
    _: u32,
    _: i32,
    _: UserPtr<u32>,
    _: UserPtr<i32>,
    _: UserAddr,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

pub fn send_notify_message(
    _: &mut NtCall,
    _: Handle,
    _: u32,
    _: u32,
    _: i32,
    _: UserPtr<u32>,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

#[allow(clippy::too_many_arguments)]
pub fn send_message_callback(
    _: &mut NtCall,
    _: Handle,
    _: u32,
    _: u32,
    _: i32,
    _: u32,
    _: u32,
    _: UserPtr<u32>,
    _: UserPtr<i32>,
) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

pub fn wait_message(_: &mut NtCall) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

pub fn dispatch_message(_: &mut NtCall, _: UserAddr, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

pub fn call_one_param(_: &mut NtCall, _: u32, _: u32, _: UserPtr<u32>) -> NtResult {
    Err(STATUS_NOT_IMPLEMENTED)
}

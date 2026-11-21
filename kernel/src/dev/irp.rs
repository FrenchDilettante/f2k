//! The I/O request packet's major function codes: the documented `IRP_MJ_*` values, the index a
//! request's stack location carries and a driver's `MajorFunction` table is read at
//! ([`MAJOR_FUNCTIONS`] entries, IRP_MJ_CREATE through IRP_MJ_PNP). The packet itself, its stack
//! locations and their lives are the I/O manager's ([`super::ntddk`], [`super::io`]).

// The whole documented set, of which the I/O manager sends some so far (create, cleanup, close,
// read, write, flush, device control).
#![allow(dead_code)]

use super::ntddk::MAJOR_FUNCTIONS;

pub const IRP_MJ_CREATE: u8 = 0x00;
pub const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
pub const IRP_MJ_CLOSE: u8 = 0x02;
pub const IRP_MJ_READ: u8 = 0x03;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
pub const IRP_MJ_QUERY_EA: u8 = 0x07;
pub const IRP_MJ_SET_EA: u8 = 0x08;
pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u8 = 0x0a;
pub const IRP_MJ_SET_VOLUME_INFORMATION: u8 = 0x0b;
pub const IRP_MJ_DIRECTORY_CONTROL: u8 = 0x0c;
pub const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0d;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0e;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0f;
pub const IRP_MJ_SHUTDOWN: u8 = 0x10;
pub const IRP_MJ_LOCK_CONTROL: u8 = 0x11;
pub const IRP_MJ_CLEANUP: u8 = 0x12;
pub const IRP_MJ_CREATE_MAILSLOT: u8 = 0x13;
pub const IRP_MJ_QUERY_SECURITY: u8 = 0x14;
pub const IRP_MJ_SET_SECURITY: u8 = 0x15;
pub const IRP_MJ_POWER: u8 = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: u8 = 0x17;
pub const IRP_MJ_DEVICE_CHANGE: u8 = 0x18;
pub const IRP_MJ_QUERY_QUOTA: u8 = 0x19;
pub const IRP_MJ_SET_QUOTA: u8 = 0x1a;
pub const IRP_MJ_PNP: u8 = 0x1b;

// The codes run 0 to IRP_MJ_PNP, one dispatch-table entry each.
const _: () = assert!(IRP_MJ_PNP as usize + 1 == MAJOR_FUNCTIONS);

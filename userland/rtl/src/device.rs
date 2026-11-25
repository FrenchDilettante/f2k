//! The device types (winioctl.h's FILE_DEVICE_*): one home for the kernel and userland alike, each
//! name and value Windows 2000's headers'. A device object carries one (DEVICE_OBJECT's
//! DeviceType), FileFsDeviceInformation answers it, kernel32's GetFileType sorts handles by it, and
//! an I/O control code carries it in its high word (DeviceIoControl routes a
//! FILE_DEVICE_FILE_SYSTEM code to NtFsControlFile).
//!
//! 0x8 is the *disk* file system's type; the plain FILE_SYSTEM's is 0x9.

pub const FILE_DEVICE_CD_ROM: u32 = 0x02;
pub const FILE_DEVICE_CD_ROM_FILE_SYSTEM: u32 = 0x03;
pub const FILE_DEVICE_CONTROLLER: u32 = 0x04;
pub const FILE_DEVICE_DATALINK: u32 = 0x05;
pub const FILE_DEVICE_DFS: u32 = 0x06;
pub const FILE_DEVICE_DISK: u32 = 0x07;
pub const FILE_DEVICE_DISK_FILE_SYSTEM: u32 = 0x08;
pub const FILE_DEVICE_FILE_SYSTEM: u32 = 0x09;
pub const FILE_DEVICE_KEYBOARD: u32 = 0x0B;
pub const FILE_DEVICE_MOUSE: u32 = 0x0F;
pub const FILE_DEVICE_NAMED_PIPE: u32 = 0x11;
pub const FILE_DEVICE_NETWORK: u32 = 0x12;
pub const FILE_DEVICE_NULL: u32 = 0x15;
pub const FILE_DEVICE_PARALLEL_PORT: u32 = 0x16;
pub const FILE_DEVICE_PRINTER: u32 = 0x18;
pub const FILE_DEVICE_SERIAL_PORT: u32 = 0x1B;
pub const FILE_DEVICE_SCREEN: u32 = 0x1C;
pub const FILE_DEVICE_SOUND: u32 = 0x1D;
pub const FILE_DEVICE_TAPE: u32 = 0x1F;
pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;
pub const FILE_DEVICE_VIRTUAL_DISK: u32 = 0x24;
pub const FILE_DEVICE_MODEM: u32 = 0x2B;

#[cfg(test)]
mod tests {
    use super::*;

    /// The device types are winioctl.h's: the file system's is 0x9, and 0x8 the disk file
    /// system's.
    #[test]
    fn the_device_types_are_winioctl_values() {
        assert_eq!(FILE_DEVICE_DISK_FILE_SYSTEM, 0x8);
        assert_eq!(FILE_DEVICE_FILE_SYSTEM, 0x9);
        assert_eq!(
            [
                FILE_DEVICE_CD_ROM,
                FILE_DEVICE_DISK,
                FILE_DEVICE_KEYBOARD,
                FILE_DEVICE_NETWORK
            ],
            [0x2, 0x7, 0xB, 0x12]
        );
        assert_eq!(
            [
                FILE_DEVICE_TAPE,
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_VIRTUAL_DISK
            ],
            [0x1F, 0x22, 0x24]
        );
    }
}

//! NtQueryVolumeInformationFile: the boot volume's facts through any of its file objects — its
//! label and serial number (the boot sector's), its size and free clusters (the FSInfo sector's
//! count when it carries a plausible one, else a FAT scan), its device type (a disk), and its file
//! system's name, flags and longest component (FAT32's).

use super::super::call::{Handle, NtCall, NtResult, UserAddr};
use super::common::{complete, file_object};
use super::info::{self, Volume, VolumeClass};
use crate::fs::fat32::fat::FatEntry;
use crate::status::*;

/// Read the boot volume's facts.
fn volume_facts() -> Result<Volume, NtStatus> {
    crate::fs::io::with_volume(|volume| {
        let layout = *volume.layout();
        let mut sector = [0u8; 512];
        if volume.device().read(0, &mut sector).is_err() {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        let serial = u32::from_le_bytes([sector[67], sector[68], sector[69], sector[70]]);
        let mut label = [0u8; 11];
        label.copy_from_slice(&sector[71..82]);
        let info_sector = u16::from_le_bytes([sector[48], sector[49]]) as u64;
        let mut free = None;
        if info_sector != 0
            && info_sector != 0xFFFF
            && volume.device().read(info_sector, &mut sector).is_ok()
        {
            let word = |at: usize| {
                u32::from_le_bytes([sector[at], sector[at + 1], sector[at + 2], sector[at + 3]])
            };
            if word(0) == 0x4161_5252
                && word(484) == 0x6141_7272
                && word(488) <= layout.cluster_count
            {
                free = Some(word(488));
            }
        }
        let free = free.unwrap_or_else(|| {
            (2..layout.cluster_count + 2)
                .filter(|&cluster| matches!(volume.fat_entry(cluster), Ok(FatEntry::Free)))
                .count() as u32
        });
        Ok(Volume {
            serial,
            label,
            sectors_per_cluster: layout.sectors_per_cluster,
            clusters: layout.cluster_count,
            free_clusters: free,
        })
    })
}

/// NtQueryVolumeInformationFile: FileFsVolumeInformation, FileFsSizeInformation,
/// FileFsDeviceInformation, FileFsAttributeInformation or FileFsFullSizeInformation (see
/// [`info::volume_query`]); a name that does not fit is cut (STATUS_BUFFER_OVERFLOW).
pub fn query_volume_information_file(
    _call: &mut NtCall,
    handle: Handle,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
) -> NtResult {
    let class = VolumeClass::try_from(class)?;
    if (length as usize) < class.min_size() {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    io_status.probe(8)?;
    information.probe(length)?;
    file_object(handle.raw())?;
    let facts = if class == VolumeClass::Device {
        Volume {
            serial: 0,
            label: [b' '; 11],
            sectors_per_cluster: 0,
            clusters: 0,
            free_clusters: 0,
        }
    } else {
        volume_facts()?
    };
    let mut out = [0u8; 64];
    let room = (length as usize).min(out.len());
    let (code, written) = match info::volume_query(class, &facts, &mut out[..room]) {
        Ok(written) => (STATUS_SUCCESS, written),
        Err(written) => (STATUS_BUFFER_OVERFLOW, written),
    };
    information.write(&out[..written])?;
    complete(io_status, code, written as u32);
    if code == STATUS_SUCCESS {
        Ok(code)
    } else {
        Err(code)
    }
}

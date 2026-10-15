//! A simulated IDE channel with one master disk, for the host tests: the command-block register
//! file, the INTRQ line, and the PIO data-in state machine as the hardware contract describes them.
//!
//! INTRQ: a command write deasserts it, a status-register read acknowledges it, an alternate-status
//! read leaves it alone, and `nIEN` keeps a completion from asserting it. A data-in command
//! asserts it when each sector's data is ready; draining a sector's last word starts the next
//! sector, and the final drain asserts nothing. A data-port read with DRQ clear returns 0. While
//! BUSY or DRQ is set, register and command writes are ignored. The shared test helpers (a channel
//! over the simulator, the expected sector contents, the access-log views) are at the end.

use super::channel::Channel;
use super::latch::{Completion, Latch};
use super::regs::*;
use super::taskfile::decode_count;
use crate::hw::portio::Io;

/// One logged port access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Out(u16, u8),
    Read(u16, u8),
    Word(u16),
}

pub struct SimChannel {
    /// The disk's contents; `None` is an empty master position.
    pub disk: Option<Vec<u8>>,
    pub status: u8,
    pub error: u8,
    pub count: u8,
    pub lba: [u8; 3],
    pub device: u8,
    pub control: u8,
    /// The INTRQ line as the device drives it (before `nIEN`).
    pub intrq: bool,
    /// How many times a completion asserted INTRQ.
    pub raised: u32,
    /// Alternate-status reads a sector's data stays BUSY before it is ready; 0 is immediate.
    pub busy_reads: u32,
    /// Assert INTRQ after the final sector's drain as well (a device that interrupts at
    /// completion): the driver must still end with the line acknowledged.
    pub interrupt_after_last: bool,
    pub log: Vec<Access>,
    buffer: Vec<u8>,
    position: usize,
    next_lba: u64,
    remaining: u32,
    busy_left: u32,
}

impl SimChannel {
    /// A channel whose master is a disk of `sectors` sectors, sector `n` filled with the byte
    /// pattern `pattern(n, offset)`.
    pub fn with_disk(sectors: u32) -> Self {
        let mut disk = vec![0u8; sectors as usize * SECTOR_SIZE];
        for (index, byte) in disk.iter_mut().enumerate() {
            *byte = pattern((index / SECTOR_SIZE) as u32, index % SECTOR_SIZE);
        }
        Self::new(Some(disk))
    }

    /// A channel with nothing on the master position: every register reads 0.
    pub fn empty() -> Self {
        Self::new(None)
    }

    fn new(disk: Option<Vec<u8>>) -> Self {
        SimChannel {
            disk,
            status: DRDY | SEEK,
            error: 0,
            count: 0,
            lba: [0; 3],
            device: 0,
            // Power-on: interrupts masked until the driver clears nIEN.
            control: CONTROL_NIEN,
            intrq: false,
            raised: 0,
            busy_reads: 0,
            interrupt_after_last: false,
            log: Vec::new(),
            buffer: Vec::new(),
            position: 0,
            next_lba: 0,
            remaining: 0,
            busy_left: 0,
        }
    }

    fn sectors(&self) -> u64 {
        self.disk
            .as_ref()
            .map_or(0, |disk| (disk.len() / SECTOR_SIZE) as u64)
    }

    /// The INTRQ the controller sees: the device's line, gated by `nIEN`.
    pub fn line(&self) -> bool {
        self.intrq && self.control & CONTROL_NIEN == 0
    }

    /// Let a pending BUSY phase finish at once (the passage of time the host has no clock for).
    pub fn settle_busy(&mut self) {
        if self.status & BUSY != 0 {
            self.busy_left = 0;
            self.data_ready();
        }
    }

    /// The command writes in the log, in order.
    pub fn commands(&self) -> Vec<u8> {
        self.log
            .iter()
            .filter_map(|access| match *access {
                Access::Out(port, byte) if port == PRIMARY_BASE + COMMAND => Some(byte),
                _ => None,
            })
            .collect()
    }

    fn raise(&mut self) {
        self.intrq = true;
        self.raised += 1;
    }

    fn execute(&mut self, command: u8) {
        self.intrq = false;
        self.error = 0;
        match command {
            IDENTIFY_DEVICE => {
                self.buffer = identify_block(self.sectors() as u32).to_vec();
                self.position = 0;
                self.remaining = 0;
                self.status = DRDY | SEEK | DRQ;
                self.raise();
            }
            READ_SECTORS if self.device & 0x40 != 0 => {
                let lba = (self.lba[0] as u64)
                    | (self.lba[1] as u64) << 8
                    | (self.lba[2] as u64) << 16
                    | ((self.device & 0x0F) as u64) << 24;
                let count = decode_count(self.count);
                if lba + count as u64 > self.sectors() {
                    self.abort();
                    return;
                }
                self.next_lba = lba;
                self.remaining = count;
                self.start_sector();
            }
            _ => self.abort(),
        }
    }

    fn abort(&mut self) {
        self.error = ABRT;
        self.status = DRDY | SEEK | ERR;
        self.raise();
    }

    /// Fetch the next sector: BUSY for the configured reads, then data ready.
    fn start_sector(&mut self) {
        self.status = DRDY | SEEK | BUSY;
        self.busy_left = self.busy_reads;
        if self.busy_left == 0 {
            self.data_ready();
        }
    }

    fn data_ready(&mut self) {
        let start = self.next_lba as usize * SECTOR_SIZE;
        self.buffer = self.disk.as_ref().unwrap()[start..start + SECTOR_SIZE].to_vec();
        self.position = 0;
        self.next_lba += 1;
        self.remaining -= 1;
        self.status = DRDY | SEEK | DRQ;
        self.raise();
    }

    fn drained(&mut self) {
        self.status = DRDY | SEEK;
        if self.remaining > 0 {
            self.start_sector();
        } else if self.interrupt_after_last {
            self.raise();
        }
    }
}

impl Io for SimChannel {
    fn out(&mut self, port: u16, byte: u8) {
        self.log.push(Access::Out(port, byte));
        if self.disk.is_none() {
            return;
        }
        if port == PRIMARY_CONTROL {
            self.control = byte;
            return;
        }
        if self.status & (BUSY | DRQ) != 0 {
            return;
        }
        match port - PRIMARY_BASE {
            SECTOR_COUNT => self.count = byte,
            LBA_LOW => self.lba[0] = byte,
            LBA_MID => self.lba[1] = byte,
            LBA_HIGH => self.lba[2] = byte,
            DEVICE => self.device = byte,
            COMMAND => self.execute(byte),
            _ => {}
        }
    }

    fn read(&mut self, port: u16) -> u8 {
        let value = if self.disk.is_none() {
            0
        } else if port == PRIMARY_CONTROL {
            if self.busy_left > 0 {
                self.busy_left -= 1;
                let status = self.status;
                if self.busy_left == 0 {
                    self.data_ready();
                }
                status
            } else {
                self.status
            }
        } else {
            match port - PRIMARY_BASE {
                ERROR => self.error,
                SECTOR_COUNT => self.count,
                STATUS => {
                    self.intrq = false;
                    self.status
                }
                _ => 0,
            }
        };
        self.log.push(Access::Read(port, value));
        value
    }

    fn read_word(&mut self, port: u16) -> u16 {
        self.log.push(Access::Word(port));
        if port != PRIMARY_BASE + DATA || self.status & DRQ == 0 {
            return 0;
        }
        let word = u16::from_le_bytes([self.buffer[self.position], self.buffer[self.position + 1]]);
        self.position += 2;
        if self.position == SECTOR_SIZE {
            self.drained();
        }
        word
    }
}

/// The byte at `offset` of sector `lba` on a simulated disk: distinct per sector and per offset.
pub fn pattern(lba: u32, offset: usize) -> u8 {
    (lba.wrapping_mul(31) as usize ^ offset.wrapping_mul(7)) as u8
}

/// The IDENTIFY block a disk of `sectors` sectors reports: LBA supported, the LBA28 count, a
/// 16-sector multiple setting.
pub fn identify_block(sectors: u32) -> [u8; SECTOR_SIZE] {
    let mut block = [0u8; SECTOR_SIZE];
    let mut put = |index: usize, word: u16| {
        block[2 * index..2 * index + 2].copy_from_slice(&word.to_le_bytes());
    };
    put(47, 0x8000 | 16);
    put(49, (1 << 11) | (1 << 9) | (1 << 8));
    put(60, sectors as u16);
    put(61, (sectors >> 16) as u16);
    block
}

/// The host's completion: deliver the channel's interrupt the way the kernel would — the service
/// routine's acknowledging read, then the deferred completion — or report that none is coming.
pub struct Deliver {
    /// Completions delivered.
    pub delivered: u32,
}

impl Completion<SimChannel> for Deliver {
    fn wait(&mut self, io: &mut SimChannel, latch: &Latch) -> bool {
        io.settle_busy();
        if !io.line() {
            return false;
        }
        if latch.service(io, PRIMARY_BASE) {
            self.delivered += 1;
        }
        latch.fired()
    }
}

// --- Shared test helpers ----------------------------------------------------------------------

/// The simulated disk's size in sectors.
pub const DISK: u32 = 4096;

/// A channel over `sim` at the primary channel's ports.
pub fn sim_channel(sim: SimChannel) -> Channel<SimChannel> {
    Channel::new(sim, PRIMARY_BASE, PRIMARY_CONTROL)
}

/// A channel with the interrupt enabled and a disk of `DISK` sectors.
pub fn ready() -> Channel<SimChannel> {
    let mut channel = sim_channel(SimChannel::with_disk(DISK));
    channel.enable_interrupt();
    channel
}

/// A channel whose device has `nIEN` set: it never interrupts.
pub fn channel_with_nien() -> Channel<SimChannel> {
    let mut channel = sim_channel(SimChannel::with_disk(DISK));
    channel.io().out(PRIMARY_CONTROL, CONTROL_NIEN);
    channel
}

/// The contents a read of `sectors` sectors from `lba` must return.
pub fn expected(lba: u32, sectors: u32) -> Vec<u8> {
    (lba..lba + sectors)
        .flat_map(|sector| (0..SECTOR_SIZE).map(move |offset| pattern(sector, offset)))
        .collect()
}

/// The port writes in the log, in order.
pub fn writes(channel: &mut Channel<SimChannel>) -> Vec<(u16, u8)> {
    channel
        .io()
        .log
        .iter()
        .filter_map(|access| match *access {
            Access::Out(port, byte) => Some((port, byte)),
            _ => None,
        })
        .collect()
}

/// How many times the status register (not the alternate status) was read.
pub fn status_reads(channel: &mut Channel<SimChannel>) -> usize {
    channel
        .io()
        .log
        .iter()
        .filter(|access| matches!(access, Access::Read(port, _) if *port == PRIMARY_BASE + STATUS))
        .count()
}

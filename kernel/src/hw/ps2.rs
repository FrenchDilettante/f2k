//! The 8042 keyboard controller: the PS/2 keyboard behind IRQ 1.
//!
//! The firmware leaves the controller running; bring-up only drains whatever is pending and makes
//! sure the configuration byte has the keyboard's interrupt on, its clock enabled, and translation
//! to scancode set 1 on. From then on every byte the keyboard sends raises IRQ 1.
//!
//! The interrupt object claims the vector at the [`KEYBOARD`] level. Its service routine reads the
//! byte (which acknowledges the controller), keeps it in a small ring, and defers the rest to a DPC;
//! the DPC hands the bytes to the console, which decodes them into key events. Bytes from the
//! auxiliary (mouse) port are read and dropped.
//!
//! [`KEYBOARD`]: crate::interrupt::irql::KEYBOARD

use crate::hw::portio::Io;

/// The keyboard's interrupt: ISA IRQ 1, vector 0x31 after the controller remap.
pub const VECTOR: u8 = crate::hw::pic::MASTER_VECTOR_BASE + 1;

/// The data port (scancodes in, data bytes out) and the status/command port.
const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;

/// Status bits: a byte waits in the output buffer; the input buffer is still full; the waiting byte
/// came from the auxiliary port.
const STATUS_OUTPUT_FULL: u8 = 0x01;
const STATUS_INPUT_FULL: u8 = 0x02;
const STATUS_AUX: u8 = 0x20;

/// Controller commands: read and write the configuration byte.
const READ_CONFIG: u8 = 0x20;
const WRITE_CONFIG: u8 = 0x60;

/// Configuration bits: the keyboard's interrupt, the keyboard clock disable, translation to set 1.
const CONFIG_KEYBOARD_INTERRUPT: u8 = 0x01;
const CONFIG_KEYBOARD_DISABLED: u8 = 0x10;
const CONFIG_TRANSLATE: u8 = 0x40;

/// How many status polls a controller handshake waits before giving up.
const POLLS: u32 = 100_000;

/// How many stale bytes bring-up drains at most.
const DRAIN_LIMIT: u32 = 16;

/// The controller did not answer a handshake (no controller, or a wedged one).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NoController;

/// Wait until the controller can take a byte.
fn wait_input_empty<IoT: Io>(io: &mut IoT) -> Result<(), NoController> {
    for _ in 0..POLLS {
        if io.read(STATUS) & STATUS_INPUT_FULL == 0 {
            return Ok(());
        }
    }
    Err(NoController)
}

/// Wait until the controller has a byte for us.
fn wait_output_full<IoT: Io>(io: &mut IoT) -> Result<(), NoController> {
    for _ in 0..POLLS {
        if io.read(STATUS) & STATUS_OUTPUT_FULL != 0 {
            return Ok(());
        }
    }
    Err(NoController)
}

/// Bring the controller to the state the driver expects (see the module doc): drain pending bytes,
/// then rewrite the configuration byte with the keyboard interrupt, the keyboard clock and
/// translation on, everything else as found. Returns the configuration written.
pub fn configure<IoT: Io>(io: &mut IoT) -> Result<u8, NoController> {
    for _ in 0..DRAIN_LIMIT {
        if io.read(STATUS) & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        io.read(DATA);
    }
    wait_input_empty(io)?;
    io.out(COMMAND, READ_CONFIG);
    wait_output_full(io)?;
    let config =
        (io.read(DATA) | CONFIG_KEYBOARD_INTERRUPT | CONFIG_TRANSLATE) & !CONFIG_KEYBOARD_DISABLED;
    wait_input_empty(io)?;
    io.out(COMMAND, WRITE_CONFIG);
    wait_input_empty(io)?;
    io.out(DATA, config);
    Ok(config)
}

/// Take the waiting byte if it is the keyboard's; a byte from the auxiliary port is read (so the
/// controller moves on) and dropped.
pub fn read_scancode<IoT: Io>(io: &mut IoT) -> Option<u8> {
    let status = io.read(STATUS);
    if status & STATUS_OUTPUT_FULL == 0 {
        return None;
    }
    let byte = io.read(DATA);
    (status & STATUS_AUX == 0).then_some(byte)
}

#[cfg(target_arch = "x86")]
mod target {
    use core::ptr::addr_of_mut;

    use super::*;
    use crate::console::input::Ring;
    use crate::hw::portio::Ports;
    use crate::interrupt::dpc::{self, Dpc};
    use crate::interrupt::irql;
    use crate::interrupt::InterruptObject;
    use crate::serial_println;

    /// Raw scancodes between the service routine and the DPC.
    static mut SCANCODES: Ring<u8, 32> = Ring::new(0);
    static mut OBJECT: InterruptObject = InterruptObject::zeroed();
    static mut DPC: Dpc = Dpc::new(drain_routine, 0);

    /// The service routine: runs claimed at the keyboard level. Reading the byte acknowledges the
    /// controller; the decoding is deferred to the DPC.
    fn service(_object: &InterruptObject, _context: usize) -> bool {
        if let Some(byte) = read_scancode(&mut Ports) {
            // SAFETY: single CPU; the DPC pops with interrupts masked, so this push never
            // interleaves with a pop.
            unsafe { (*addr_of_mut!(SCANCODES)).push(byte) };
            // SAFETY: the DPC is a static the queue links through; the enqueue is single-flight.
            unsafe { dpc::enqueue(&mut *addr_of_mut!(DPC), 0, 0) };
        }
        true
    }

    /// Take the oldest raw scancode, with interrupts masked against the service routine.
    fn take_scancode() -> Option<u8> {
        let flags: u32;
        // SAFETY: saving EFLAGS and clearing IF touches no memory the compiler tracks.
        unsafe { core::arch::asm!("pushfd", "pop {}", "cli", out(reg) flags) };
        // SAFETY: interrupts are masked on the only CPU: the service routine cannot run.
        let byte = unsafe { (*addr_of_mut!(SCANCODES)).pop() };
        // SAFETY: restores the flags saved above.
        unsafe { core::arch::asm!("push {}", "popfd", in(reg) flags) };
        byte
    }

    /// The DPC: hand every waiting scancode to the console.
    fn drain_routine(_dpc: &Dpc, _context: usize, _argument1: usize, _argument2: usize) {
        while let Some(byte) = take_scancode() {
            crate::console::keyboard_byte(byte);
        }
    }

    /// Bring the keyboard up: configure the controller and connect IRQ 1. Runs after the interrupt
    /// core; reports the outcome on COM1. A missing controller is reported and leaves the console
    /// without input.
    pub fn init() {
        // SAFETY: boot context; sole access to the driver statics.
        unsafe {
            let config = match configure(&mut Ports) {
                Ok(config) => config,
                Err(NoController) => {
                    serial_println!("F2K: keyboard: no 8042 controller answered");
                    return;
                }
            };
            let object = &mut *addr_of_mut!(OBJECT);
            crate::interrupt::initialize(
                object,
                service,
                0,
                VECTOR,
                irql::KEYBOARD,
                irql::KEYBOARD,
                false,
                false,
            );
            assert!(
                crate::interrupt::connect(object),
                "connecting the keyboard interrupt failed"
            );
            serial_println!(
                "F2K: keyboard: 8042 configured (config {:#04x}), IRQ 1 connected",
                config
            );
        }
    }
}

#[cfg(target_arch = "x86")]
pub use target::init;

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// An 8042: an output buffer (bytes with their aux flag), the configuration byte, and the
    /// pending command, logging every write.
    struct Controller {
        output: VecDeque<(u8, bool)>,
        config: u8,
        pending: Option<u8>,
        writes: Vec<(u16, u8)>,
        /// Answer nothing: the input buffer never empties.
        wedged: bool,
    }

    impl Controller {
        fn new(config: u8) -> Self {
            Self {
                output: VecDeque::new(),
                config,
                pending: None,
                writes: Vec::new(),
                wedged: false,
            }
        }
    }

    impl Io for Controller {
        fn out(&mut self, port: u16, byte: u8) {
            self.writes.push((port, byte));
            match (port, self.pending.take()) {
                (COMMAND, None) if byte == READ_CONFIG => {
                    self.output.push_back((self.config, false))
                }
                (COMMAND, None) if byte == WRITE_CONFIG => self.pending = Some(WRITE_CONFIG),
                (DATA, Some(WRITE_CONFIG)) => self.config = byte,
                other => panic!("unexpected controller write {other:?}"),
            }
        }
        fn read(&mut self, port: u16) -> u8 {
            match port {
                STATUS => {
                    let mut status = if self.wedged { STATUS_INPUT_FULL } else { 0 };
                    if let Some(&(_, aux)) = self.output.front() {
                        status |= STATUS_OUTPUT_FULL | if aux { STATUS_AUX } else { 0 };
                    }
                    status
                }
                DATA => self.output.pop_front().map_or(0, |(byte, _)| byte),
                _ => panic!("unexpected port {port:#x}"),
            }
        }
        fn read_word(&mut self, _port: u16) -> u16 {
            unreachable!("the controller is byte-wide")
        }
    }

    #[test]
    fn configure_turns_on_the_interrupt_and_translation() {
        // As a firmware might leave it: system flag set, keyboard clock disabled, IRQ 1 off.
        let mut controller = Controller::new(0x14);
        assert_eq!(configure(&mut controller), Ok(0x45));
        assert_eq!(controller.config, 0x45);
        assert_eq!(
            controller.writes,
            vec![
                (COMMAND, READ_CONFIG),
                (COMMAND, WRITE_CONFIG),
                (DATA, 0x45)
            ]
        );
    }

    #[test]
    fn configure_keeps_the_other_bits() {
        // Mouse interrupt and mouse clock bits stay as found.
        let mut controller = Controller::new(0x67);
        assert_eq!(configure(&mut controller), Ok(0x67));
    }

    #[test]
    fn configure_drains_stale_bytes_first() {
        let mut controller = Controller::new(0x45);
        controller.output.extend([(0xFA, false), (0x08, true)]);
        assert_eq!(configure(&mut controller), Ok(0x45));
        assert!(controller.output.is_empty());
    }

    #[test]
    fn a_wedged_controller_is_reported() {
        let mut controller = Controller::new(0x45);
        controller.wedged = true;
        assert_eq!(configure(&mut controller), Err(NoController));
    }

    #[test]
    fn scancodes_come_from_the_keyboard_only() {
        let mut controller = Controller::new(0x45);
        assert_eq!(read_scancode(&mut controller), None);
        controller
            .output
            .extend([(0x23, false), (0x08, true), (0xA3, false)]);
        assert_eq!(read_scancode(&mut controller), Some(0x23));
        // The mouse byte is consumed, not returned.
        assert_eq!(read_scancode(&mut controller), None);
        assert_eq!(read_scancode(&mut controller), Some(0xA3));
        assert!(controller.output.is_empty());
    }
}

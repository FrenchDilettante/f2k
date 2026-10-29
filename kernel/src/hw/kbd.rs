//! The PS/2 keyboard behind the i8042 keyboard controller: IRQ 1, and the bytes the console's
//! key-event producer decodes.
//!
//! The controller's registers: data at port 0x60, status at port 0x64 (read), its own commands to
//! port 0x64 (write). Bytes written to the data port once the keyboard interface is enabled go to
//! the keyboard, which acknowledges each command with 0xFA (0xFE asks for it again). The controller
//! is left translating (configuration bit 6): what the keyboard sends reaches the data port as the
//! original PC/XT-compatible scan codes, which is what the producer (`rtl::console::input`)
//! decodes. The keyboard's own typematic repeats are taken as they come.
//!
//! The interrupt object claims vector 0x31 at the [`KEYBOARD`] level. Its service routine reads the
//! one waiting byte (the read is what ends IRQ 1), puts it in a byte ring, and defers the rest to a
//! DPC: several bytes can arrive before the DPC runs, so the ring holds them in order, a byte that
//! finds it full lost and counted. The DPC takes them out in order. The keyboard's replies to the
//! driver's own commands come back through the same interrupt, between key bytes, so the driver's
//! command state machine ([`Controller::receive`]) claims those first; every other byte is key
//! data, fed to the console's producer (`csr::key_byte`), which appends the records it completes to
//! the console's input buffer and asks for the lights a toggle key's make changes. The lights are
//! the one command the driver sends after bring-up: 0xED, then its argument, each acknowledged; a
//! request that arrives while an exchange is under way is dropped (the lights converge on the next
//! toggle). The service routine reaches only the ports and the ring; the rest of the driver's state
//! (the command state, the losses already reported) is its device extension's, which the DPC owns
//! at the dispatch level, the console's own level too.
//!
//! Bring-up ([`Controller::bring_up`], run once at boot, polled, before the interrupt is
//! connected): the keyboard interface disabled and stale bytes drained, the configuration byte
//! read and written back with the keyboard interrupt enabled (translation and the mouse's bits as
//! found), the interface enabled, the keyboard reset (0xFF: 0xFA, then 0xAA once its self-test
//! passes) and its lights set to the producer's boot toggles. A missing or silent keyboard is a
//! normal outcome, not a failure.
//!
//! [`KEYBOARD`]: crate::interrupt::irql::KEYBOARD

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering::SeqCst};

use crate::hw::portio::Io;

#[cfg(test)]
mod sim;

/// The controller's data port: the waiting byte (read), the keyboard's bytes (write).
pub const DATA: u16 = 0x60;
/// The controller's status (read) and command (write) port.
pub const STATUS: u16 = 0x64;
pub const COMMAND: u16 = 0x64;

/// Status: a byte waits at the data port (reading it clears the bit).
pub const OUTPUT_FULL: u8 = 1 << 0;
/// Status: the controller has not taken the last byte written yet.
pub const INPUT_FULL: u8 = 1 << 1;

/// Controller commands: read the configuration byte (its reply at the data port), write it (the
/// byte next written to the data port), disable and enable the keyboard interface.
pub const READ_CONFIGURATION: u8 = 0x20;
pub const WRITE_CONFIGURATION: u8 = 0x60;
pub const DISABLE_KEYBOARD: u8 = 0xAD;
pub const ENABLE_KEYBOARD: u8 = 0xAE;

/// The configuration byte: the keyboard interrupt (IRQ 1), the mouse interrupt (left as found),
/// scan-code translation (left as found: on).
pub const KEYBOARD_INTERRUPT: u8 = 1 << 0;
#[cfg_attr(not(test), allow(dead_code))]
pub const MOUSE_INTERRUPT: u8 = 1 << 1;
pub const TRANSLATION: u8 = 1 << 6;

/// Keyboard commands: set the lights (one argument byte follows), reset.
pub const SET_LIGHTS: u8 = 0xED;
pub const RESET: u8 = 0xFF;
/// The keyboard's replies: acknowledged, send the last byte again, self-test passed.
pub const ACK: u8 = 0xFA;
pub const RESEND: u8 = 0xFE;
pub const SELF_TEST_PASSED: u8 = 0xAA;

/// The lights argument's bits.
pub const SCROLL_LOCK_LIGHT: u8 = 1 << 0;
pub const NUM_LOCK_LIGHT: u8 = 1 << 1;
pub const CAPS_LOCK_LIGHT: u8 = 1 << 2;

/// IRQ 1's vector.
pub const VECTOR: u8 = crate::hw::pic::MASTER_VECTOR_BASE + 1;

/// How many status reads a wait for the controller to take a byte makes before giving up.
const INPUT_POLLS: u32 = 100_000;
/// How many stale bytes a drain reads at most.
const DRAIN_BYTES: usize = 32;
/// How many times a byte the keyboard asks for again is sent before the exchange is abandoned.
const RESENDS: u8 = 3;

/// The lights argument showing the producer's toggles.
pub fn lights(toggles: u8) -> u8 {
    use rtl::console::layout::{CAPS_LOCK, NUM_LOCK, SCROLL_LOCK};
    [
        (CAPS_LOCK, CAPS_LOCK_LIGHT),
        (NUM_LOCK, NUM_LOCK_LIGHT),
        (SCROLL_LOCK, SCROLL_LOCK_LIGHT),
    ]
    .iter()
    .filter(|&&(toggle, _)| toggles & toggle != 0)
    .fold(0, |argument, &(_, light)| argument | light)
}

/// The ring the service routine fills and the DPC empties: the bytes in arrival order. One
/// processor, but the routine runs between any two of the DPC's instructions, so the indexes are
/// atomics; each side writes only its own.
pub struct ByteRing {
    bytes: [AtomicU8; Self::CAPACITY],
    /// Bytes taken (the DPC's) and bytes put (the service routine's), both counting up.
    taken: AtomicU32,
    put: AtomicU32,
    lost: AtomicU32,
}

impl ByteRing {
    pub const CAPACITY: usize = 64;

    pub const fn new() -> Self {
        ByteRing {
            bytes: [const { AtomicU8::new(0) }; Self::CAPACITY],
            taken: AtomicU32::new(0),
            put: AtomicU32::new(0),
            lost: AtomicU32::new(0),
        }
    }

    /// The service routine's side: keep `byte`; false (and counted) when the ring is full.
    pub fn push(&self, byte: u8) -> bool {
        let put = self.put.load(SeqCst);
        if put.wrapping_sub(self.taken.load(SeqCst)) as usize == Self::CAPACITY {
            self.lost.fetch_add(1, SeqCst);
            return false;
        }
        self.bytes[put as usize % Self::CAPACITY].store(byte, SeqCst);
        self.put.store(put.wrapping_add(1), SeqCst);
        true
    }

    /// The DPC's side: the oldest byte, if any.
    pub fn pop(&self) -> Option<u8> {
        let taken = self.taken.load(SeqCst);
        if taken == self.put.load(SeqCst) {
            return None;
        }
        let byte = self.bytes[taken as usize % Self::CAPACITY].load(SeqCst);
        self.taken.store(taken.wrapping_add(1), SeqCst);
        Some(byte)
    }

    /// Bytes lost to a full ring so far.
    pub fn lost(&self) -> u32 {
        self.lost.load(SeqCst)
    }
}

/// The service routine's body: the waiting byte, if the controller has one (a stale interrupt
/// finds none).
pub fn service<IoT: Io>(io: &mut IoT) -> Option<u8> {
    (io.read(STATUS) & OUTPUT_FULL != 0).then(|| io.read(DATA))
}

/// The lights exchange, as far as it has gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exchange {
    Idle,
    /// 0xED sent, its acknowledgment awaited.
    Command {
        argument: u8,
        resends: u8,
    },
    /// The argument sent, its acknowledgment awaited.
    Argument {
        argument: u8,
        resends: u8,
    },
}

/// What a byte from the keyboard was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// The keyboard's reply to the driver's own command, consumed.
    Reply,
    /// Key data, for the producer.
    Key(u8),
}

/// How bring-up found the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyboard {
    /// Reset, its self-test passed, its lights set.
    Ready,
    /// Nothing answered the reset.
    Silent,
    /// The reset answered with something else: the byte it sent.
    Failed(u8),
}

/// What bring-up found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BringUp {
    /// The configuration byte as found.
    pub configuration: u8,
    pub keyboard: Keyboard,
}

impl BringUp {
    /// Whether the controller translates the keyboard's scan codes.
    pub fn translation(&self) -> bool {
        self.configuration & TRANSLATION != 0
    }
}

/// The controller answered none of bring-up's commands: no i8042.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoController;

/// The controller and the driver's command state.
pub struct Controller<IoT: Io> {
    io: IoT,
    exchange: Exchange,
    /// Lights requests dropped because an exchange was under way.
    dropped: u32,
}

impl<IoT: Io> Controller<IoT> {
    pub const fn new(io: IoT) -> Self {
        Controller {
            io,
            exchange: Exchange::Idle,
            dropped: 0,
        }
    }

    /// The port space (the host tests' simulation).
    #[cfg(test)]
    pub fn io(&mut self) -> &mut IoT {
        &mut self.io
    }

    /// The lights exchange's state.
    #[cfg(test)]
    pub fn exchange(&self) -> Exchange {
        self.exchange
    }

    /// Lights requests dropped mid-exchange so far.
    #[cfg(test)]
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Wait until the controller can take a byte; false if it never could.
    fn ready(&mut self) -> bool {
        (0..INPUT_POLLS).any(|_| self.io.read(STATUS) & INPUT_FULL == 0)
    }

    /// A controller command.
    fn command(&mut self, command: u8) -> bool {
        let ready = self.ready();
        if ready {
            self.io.out(COMMAND, command);
        }
        ready
    }

    /// A byte to the data port: the keyboard's, or a controller command's argument.
    fn write(&mut self, byte: u8) -> bool {
        let ready = self.ready();
        if ready {
            self.io.out(DATA, byte);
        }
        ready
    }

    /// The next byte at the data port, polled until `expired` says the wait is over (it is asked
    /// with each empty poll's number, 0 the wait's first).
    fn poll(&mut self, expired: &mut impl FnMut(u32) -> bool) -> Option<u8> {
        let mut attempt = 0u32;
        loop {
            if let Some(byte) = service(&mut self.io) {
                return Some(byte);
            }
            if expired(attempt) {
                return None;
            }
            attempt = attempt.wrapping_add(1);
        }
    }

    /// Read and discard what waits at the data port.
    fn drain(&mut self) {
        for _ in 0..DRAIN_BYTES {
            if service(&mut self.io).is_none() {
                break;
            }
        }
    }

    /// Send a keyboard command byte by polling: its acknowledgment awaited, a resend request
    /// honoured. False when the keyboard never acknowledged it.
    fn polled_send(&mut self, byte: u8, expired: &mut impl FnMut(u32) -> bool) -> bool {
        for _ in 0..=RESENDS {
            if !self.write(byte) {
                return false;
            }
            match self.poll(expired) {
                Some(ACK) => return true,
                Some(RESEND) => continue,
                _ => return false,
            }
        }
        false
    }

    /// Bring the controller and keyboard up, polled (see the module's description); `expired`
    /// bounds each wait for the keyboard's answer. `toggles` is the producer's boot state, shown on
    /// the lights.
    pub fn bring_up(
        &mut self,
        toggles: u8,
        expired: &mut impl FnMut(u32) -> bool,
    ) -> Result<BringUp, NoController> {
        if !self.command(DISABLE_KEYBOARD) {
            return Err(NoController);
        }
        self.drain();
        if !self.command(READ_CONFIGURATION) {
            return Err(NoController);
        }
        let configuration = self.poll(expired).ok_or(NoController)?;
        if !(self.command(WRITE_CONFIGURATION) && self.write(configuration | KEYBOARD_INTERRUPT)) {
            return Err(NoController);
        }
        if !self.command(ENABLE_KEYBOARD) {
            return Err(NoController);
        }
        let keyboard = if !self.polled_send(RESET, expired) {
            Keyboard::Silent
        } else {
            match self.poll(expired) {
                Some(SELF_TEST_PASSED) => {
                    if self.polled_send(SET_LIGHTS, expired) {
                        self.polled_send(lights(toggles), expired);
                    }
                    Keyboard::Ready
                }
                Some(other) => Keyboard::Failed(other),
                None => Keyboard::Silent,
            }
        };
        self.drain();
        self.exchange = Exchange::Idle;
        Ok(BringUp {
            configuration,
            keyboard,
        })
    }

    /// Show `toggles` on the lights: the exchange starts with 0xED, unless one is under way, when
    /// the request is dropped. False when nothing was sent.
    pub fn set_lights(&mut self, toggles: u8) -> bool {
        if self.exchange != Exchange::Idle {
            self.dropped += 1;
            return false;
        }
        let argument = lights(toggles);
        let sent = self.write(SET_LIGHTS);
        if sent {
            self.exchange = Exchange::Command {
                argument,
                resends: 0,
            };
        }
        sent
    }

    /// Show the toggles `request` asks for, if it asks (see [`Controller::set_lights`]).
    pub fn show(&mut self, request: LightsRequest) {
        if let Some(toggles) = request.0 {
            self.set_lights(toggles);
        }
    }

    /// Classify a byte from the keyboard: the reply the exchange under way awaits is consumed (and
    /// the exchange moves on); anything else is key data.
    pub fn receive(&mut self, byte: u8) -> Received {
        let (next, resend) = match (self.exchange, byte) {
            (Exchange::Command { argument, .. }, ACK) => {
                self.write(argument);
                (
                    Exchange::Argument {
                        argument,
                        resends: 0,
                    },
                    None,
                )
            }
            (Exchange::Argument { .. }, ACK) => (Exchange::Idle, None),
            (Exchange::Command { argument, resends }, RESEND) => (
                Exchange::Command {
                    argument,
                    resends: resends + 1,
                },
                Some((SET_LIGHTS, resends)),
            ),
            (Exchange::Argument { argument, resends }, RESEND) => (
                Exchange::Argument {
                    argument,
                    resends: resends + 1,
                },
                Some((argument, resends)),
            ),
            _ => return Received::Key(byte),
        };
        self.exchange = next;
        if let Some((again, resends)) = resend {
            // A keyboard that keeps asking has the exchange abandoned: the next toggle tries anew.
            if resends >= RESENDS || !self.write(again) {
                self.exchange = Exchange::Idle;
            }
        }
        Received::Reply
    }
}

/// The lights a key byte asks for, as the producer reaches them: kept while the producer runs,
/// then shown through the driver ([`Controller::show`]) once the console is no longer borrowed (the
/// console and the driver's command state are both the dispatch level's, reached one at a time).
/// A byte completes at most one key, so it asks at most once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LightsRequest(Option<u8>);

impl rtl::console::input::Lights for LightsRequest {
    fn set(&mut self, toggles: u8) {
        self.0 = Some(toggles);
    }
}

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::hw::portio::Ports;
    use crate::interrupt::dpc::{self, Dpc};
    use crate::interrupt::InterruptObject;
    use crate::level::{self, At, Dispatch, Keyboard as KeyboardLevel, LevelCell};
    use crate::serial_println;

    /// How long bring-up waits for each of the keyboard's answers: 50 ticks, about half a second
    /// (a real keyboard's self-test takes a few hundred milliseconds).
    const ANSWER_TICKS: u64 = 50;

    /// The bytes the service routine reads, for the DPC: the one thing the two share.
    static RING: ByteRing = ByteRing::new();

    /// The keyboard's device extension, as Windows 2000's port driver keeps one: the driver's state
    /// past the service routine, which reaches only the ports and the ring. Once bring-up is over
    /// only the DPC touches it, so it is the dispatch level's.
    struct KbdExtension {
        /// The controller and the lights exchange under way.
        controller: Controller<Ports>,
        /// The ring's lost count the DPC last reported.
        reported_lost: u32,
    }

    static EXTENSION: LevelCell<Dispatch, KbdExtension> = LevelCell::new(KbdExtension {
        controller: Controller::new(Ports),
        reported_lost: 0,
    });
    /// The keyboard's interrupt: IRQ 1, served at the keyboard's level.
    static OBJECT: InterruptObject = InterruptObject::at_keyboard(service, 0, VECTOR, false, false);
    static DPC: Dpc = Dpc::new(input_routine, 0);

    /// The service routine: runs claimed at the keyboard level. The one byte read ends the
    /// interrupt; everything else is the DPC's.
    fn service(keyboard: &mut At<KeyboardLevel>, _context: usize) -> bool {
        if let Some(byte) = super::service(&mut Ports) {
            RING.push(byte);
            dpc::enqueue_at(keyboard, &DPC, 0, 0);
        }
        true
    }

    /// The DPC: the ring's bytes in order, the keyboard's replies to the driver claimed, the rest
    /// fed to the console's producer.
    fn input_routine(dispatch: &mut At<Dispatch>, _: &Dpc, _context: usize, _: usize, _: usize) {
        while let Some(byte) = RING.pop() {
            let received = EXTENSION.get(dispatch).controller.receive(byte);
            #[cfg(feature = "kbd-smoke")]
            serial_println!(
                "F2K: kbd: byte {:#04x}{}",
                byte,
                if received == Received::Reply {
                    " (reply)"
                } else {
                    ""
                }
            );
            if let Received::Key(byte) = received {
                let mut lights = LightsRequest::default();
                crate::csr::key_byte(dispatch, byte, &mut lights);
                EXTENSION.get(dispatch).controller.show(lights);
            }
        }
        let lost = RING.lost();
        let reported = &mut EXTENSION.get(dispatch).reported_lost;
        if lost != *reported {
            serial_println!(
                "F2K: kbd: {} byte(s) lost to a full ring",
                lost.wrapping_sub(*reported)
            );
            *reported = lost;
        }
    }

    /// Bring the keyboard up and connect its interrupt; reports the outcome on COM1. Runs after
    /// the interrupt core (bring-up's waits read the tick), before the first user process.
    pub fn init() {
        let mut until = 0;
        let mut expired = |attempt: u32| {
            let now = crate::interrupt::clock::ticks();
            if attempt == 0 {
                until = now + ANSWER_TICKS;
            }
            now >= until
        };
        // Bring-up polls on a controller of its own, at the boot's level rather than the
        // extension's: its waits read the tick, and the deferred work the tick queues meanwhile
        // runs as it always has.
        let mut controller = Controller::new(Ports);
        let Ok(found) = controller.bring_up(rtl::console::input::BOOT_TOGGLES, &mut expired) else {
            serial_println!("F2K: kbd: no i8042 controller answered");
            return;
        };
        // The controller, brought up, is the DPC's from here.
        level::raised::<Dispatch, _>(|dispatch| EXTENSION.get(dispatch).controller = controller);
        assert!(
            crate::interrupt::connect(&OBJECT),
            "connecting the keyboard interrupt failed"
        );
        let translation = if found.translation() { "on" } else { "off" };
        match found.keyboard {
            Keyboard::Ready => {
                serial_println!(
                    "F2K: kbd: keyboard ready on IRQ 1 (translation {})",
                    translation
                );
            }
            Keyboard::Silent => {
                serial_println!(
                    "F2K: kbd: no keyboard answered the reset (IRQ 1 connected, translation {})",
                    translation
                );
            }
            Keyboard::Failed(byte) => {
                serial_println!(
                    "F2K: kbd: the keyboard's self-test answered {:#04x} (IRQ 1 connected, \
                     translation {})",
                    byte,
                    translation
                );
            }
        }
    }
}

#[cfg(target_arch = "x86")]
pub use target::init;

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use rtl::console::input::{KeyEventRecord, CAPSLOCK_ON};
    use rtl::console::layout::{CAPS_LOCK, NUM_LOCK, SCROLL_LOCK, VK_CAPITAL};
    use rtl::console::Console;

    use super::sim::{SimController, SimKeyboard};
    use super::*;

    /// A wait that gives up after a few empty polls.
    fn bounded(attempt: u32) -> bool {
        attempt >= 8
    }

    fn fresh() -> Controller<SimController> {
        Controller::new(SimController::new())
    }

    /// The service routine's byte, the keyboard's replies claimed, the rest through the console's
    /// producer, until the controller has nothing waiting: the records the producer completed.
    fn pump(
        controller: &mut Controller<SimController>,
        console: &mut Console,
    ) -> Vec<KeyEventRecord> {
        let mut records = Vec::new();
        while let Some(byte) = service(controller.io()) {
            if let Received::Key(byte) = controller.receive(byte) {
                let mut lights = LightsRequest::default();
                console.key_byte(byte, &mut lights, &mut |_, record| records.push(record));
                controller.show(lights);
            }
        }
        records
    }

    /// Bring-up: the interface disabled, stale bytes drained, the configuration read and written
    /// back with the keyboard interrupt (translation and the mouse as found), the interface
    /// enabled, then the keyboard reset and its lights set — the boot's toggles.
    #[test]
    fn bring_up_resets_the_keyboard_and_enables_its_interrupt() {
        let mut controller = fresh();
        controller.io().type_bytes(&[0x1E, 0x9E]);
        let found = controller.bring_up(0, &mut bounded).unwrap();
        assert_eq!(
            found,
            BringUp {
                configuration: TRANSLATION | MOUSE_INTERRUPT | 0x04 | 1 << 4,
                keyboard: Keyboard::Ready,
            }
        );
        assert!(found.translation());
        let sim = controller.io();
        assert_eq!(
            sim.commands(),
            [
                DISABLE_KEYBOARD,
                READ_CONFIGURATION,
                WRITE_CONFIGURATION,
                ENABLE_KEYBOARD
            ]
        );
        assert_eq!(
            sim.configuration,
            TRANSLATION | MOUSE_INTERRUPT | 0x04 | KEYBOARD_INTERRUPT,
            "the interrupt on, the rest as found"
        );
        let keyboard = sim.keyboard.as_ref().unwrap();
        assert_eq!(keyboard.taken, [RESET, SET_LIGHTS, 0]);
        assert_eq!(keyboard.lights, 0);
        assert!(sim.output.is_empty(), "nothing left waiting");
        assert_eq!(controller.exchange(), Exchange::Idle);
    }

    /// The lights bring-up sets are the toggles it is handed.
    #[test]
    fn bring_up_shows_the_boot_toggles() {
        let mut controller = fresh();
        controller.bring_up(NUM_LOCK, &mut bounded).unwrap();
        let keyboard = controller.io().keyboard.as_ref().unwrap();
        assert_eq!(keyboard.lights, NUM_LOCK_LIGHT);
        assert_eq!(lights(CAPS_LOCK | NUM_LOCK | SCROLL_LOCK), 0x07);
        assert_eq!(lights(CAPS_LOCK), CAPS_LOCK_LIGHT);
        assert_eq!(lights(SCROLL_LOCK), SCROLL_LOCK_LIGHT);
    }

    /// A missing keyboard, one whose self-test fails, and a keyboard that asks for its reset again
    /// are normal outcomes; a missing controller is the only failure.
    #[test]
    fn bring_up_reports_what_it_found() {
        let mut controller = fresh();
        controller.io().keyboard = None;
        assert_eq!(
            controller.bring_up(0, &mut bounded).unwrap().keyboard,
            Keyboard::Silent
        );
        let mut controller = fresh();
        controller.io().keyboard.as_mut().unwrap().self_test = 0xFC;
        assert_eq!(
            controller.bring_up(0, &mut bounded).unwrap().keyboard,
            Keyboard::Failed(0xFC)
        );
        let mut controller = fresh();
        controller.io().keyboard.as_mut().unwrap().resends = 2;
        assert_eq!(
            controller.bring_up(0, &mut bounded).unwrap().keyboard,
            Keyboard::Ready
        );
        assert_eq!(
            controller.io().keyboard.as_ref().unwrap().taken,
            [RESET, SET_LIGHTS, 0]
        );
        let mut controller = fresh();
        controller.io().present = false;
        assert_eq!(controller.bring_up(0, &mut bounded), Err(NoController));
    }

    /// The service routine reads the waiting byte, and nothing when none waits.
    #[test]
    fn the_service_routine_reads_the_waiting_byte() {
        let mut sim = SimController::new();
        assert_eq!(service(&mut sim), None);
        sim.type_bytes(&[0x1E]);
        assert_eq!(service(&mut sim), Some(0x1E));
        assert_eq!(service(&mut sim), None);
    }

    /// The ring keeps its bytes in order; a byte that finds it full is lost and counted.
    #[test]
    fn the_ring_keeps_order_and_counts_losses() {
        let ring = ByteRing::new();
        assert_eq!(ring.pop(), None);
        for byte in 0..ByteRing::CAPACITY as u8 {
            assert!(ring.push(byte));
        }
        assert!(!ring.push(0xEE));
        assert_eq!(ring.lost(), 1);
        assert_eq!(ring.pop(), Some(0));
        assert!(ring.push(0xEF));
        let rest: Vec<u8> = core::iter::from_fn(|| ring.pop()).collect();
        assert_eq!(rest.len(), ByteRing::CAPACITY);
        assert_eq!((rest[0], rest[ByteRing::CAPACITY - 1]), (1, 0xEF));
    }

    /// The lights exchange: 0xED, its acknowledgment, the argument, its acknowledgment — the
    /// replies claimed, key bytes in between passed on, a request mid-exchange dropped, a resend
    /// honoured; once idle, an acknowledgment is key data like any byte.
    #[test]
    fn the_lights_exchange_claims_its_replies() {
        let mut controller = Controller::new(SimController::new());
        assert!(controller.set_lights(CAPS_LOCK));
        assert_eq!(controller.io().writes, [(DATA, SET_LIGHTS)]);
        assert_eq!(controller.receive(0x1E), Received::Key(0x1E));
        assert!(!controller.set_lights(0), "mid-exchange: dropped");
        assert_eq!(controller.dropped(), 1);
        assert_eq!(controller.receive(RESEND), Received::Reply);
        assert_eq!(controller.receive(ACK), Received::Reply);
        assert_eq!(controller.receive(ACK), Received::Reply);
        assert_eq!(controller.exchange(), Exchange::Idle);
        assert_eq!(
            controller.io().writes,
            [
                (DATA, SET_LIGHTS),
                (DATA, SET_LIGHTS),
                (DATA, CAPS_LOCK_LIGHT)
            ]
        );
        assert_eq!(controller.receive(ACK), Received::Key(ACK));
        // A keyboard that keeps asking has the exchange abandoned.
        assert!(controller.set_lights(0));
        for _ in 0..RESENDS {
            assert_eq!(controller.receive(RESEND), Received::Reply);
        }
        assert_ne!(controller.exchange(), Exchange::Idle);
        assert_eq!(controller.receive(RESEND), Received::Reply);
        assert_eq!(controller.exchange(), Exchange::Idle);
    }

    /// End to end over the simulated controller: Caps Lock's make sets the lights through the
    /// exchange, whose replies never reach the producer, and the next letter is a capital.
    #[test]
    fn caps_lock_lights_the_keyboard_and_capitalizes() {
        let mut controller = fresh();
        controller.bring_up(0, &mut bounded).unwrap();
        let mut console = Console::new();
        controller.io().type_bytes(&[0x3A, 0xBA]);
        let records = pump(&mut controller, &mut console);
        assert_eq!(
            records
                .iter()
                .map(|r| (r.key_down, r.virtual_key_code, r.control_key_state))
                .collect::<Vec<_>>(),
            [
                (1, VK_CAPITAL.into(), CAPSLOCK_ON),
                (0, VK_CAPITAL.into(), CAPSLOCK_ON)
            ]
        );
        assert_eq!(
            controller.io().keyboard.as_ref().unwrap().lights,
            CAPS_LOCK_LIGHT
        );
        controller.io().type_bytes(&[0x1E, 0x9E]);
        let records = pump(&mut controller, &mut console);
        assert_eq!(records[0].char, u16::from(b'A'));
        assert_eq!(console.input.count(), 4);
        let _ = SimKeyboard::new();
    }
}

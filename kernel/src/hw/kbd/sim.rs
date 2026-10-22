//! A simulated i8042 controller with a keyboard behind it, for the host tests: the status, data
//! and command ports, the configuration byte, and the keyboard's answers as the hardware contract
//! describes them.
//!
//! The controller queues its answers and the keyboard's bytes at the data port in order; the
//! status port shows a byte waiting while the queue holds one and never shows the controller busy.
//! An absent controller reads 0xFF on every port (busy for ever). The keyboard acknowledges each
//! byte it is sent with 0xFA — the reset with 0xFA then its self-test's answer, the lights command
//! with 0xFA then the argument's 0xFA — unless it is told to ask for some bytes again (0xFE), and
//! it answers nothing while the interface is disabled. Every write is logged.

use std::collections::VecDeque;
use std::vec::Vec;

use super::*;

/// The keyboard behind the simulated controller.
pub struct SimKeyboard {
    /// The lights its last lights command set.
    pub lights: u8,
    /// How many of the next bytes it is sent it asks for again.
    pub resends: u8,
    /// Its self-test's answer to a reset.
    pub self_test: u8,
    /// The bytes it took, in order.
    pub taken: Vec<u8>,
    awaiting_lights: bool,
}

impl SimKeyboard {
    pub fn new() -> Self {
        SimKeyboard {
            lights: 0xFF,
            resends: 0,
            self_test: SELF_TEST_PASSED,
            taken: Vec::new(),
            awaiting_lights: false,
        }
    }
}

pub struct SimController {
    pub present: bool,
    pub configuration: u8,
    pub keyboard: Option<SimKeyboard>,
    /// The bytes waiting at the data port.
    pub output: VecDeque<u8>,
    /// Every write: (port, byte).
    pub writes: Vec<(u16, u8)>,
    interface_enabled: bool,
    awaiting_configuration: bool,
    last: u8,
}

impl SimController {
    /// A controller as firmware leaves it (translating, the mouse's interrupt on, the keyboard's
    /// off), a keyboard behind it.
    pub fn new() -> Self {
        SimController {
            present: true,
            configuration: TRANSLATION | MOUSE_INTERRUPT | 0x04,
            keyboard: Some(SimKeyboard::new()),
            output: VecDeque::new(),
            writes: Vec::new(),
            interface_enabled: true,
            awaiting_configuration: false,
            last: 0,
        }
    }

    /// The keyboard sends `bytes` (keys pressed and released).
    pub fn type_bytes(&mut self, bytes: &[u8]) {
        self.output.extend(bytes);
    }

    /// The controller commands written, in order.
    pub fn commands(&self) -> Vec<u8> {
        self.writes
            .iter()
            .filter(|&&(port, _)| port == COMMAND)
            .map(|&(_, byte)| byte)
            .collect()
    }

    fn keyboard_takes(&mut self, byte: u8) {
        if !self.interface_enabled {
            return;
        }
        let Some(keyboard) = self.keyboard.as_mut() else {
            return;
        };
        if keyboard.resends > 0 {
            keyboard.resends -= 1;
            self.output.push_back(RESEND);
            return;
        }
        keyboard.taken.push(byte);
        self.output.push_back(ACK);
        if keyboard.awaiting_lights {
            keyboard.awaiting_lights = false;
            keyboard.lights = byte;
            return;
        }
        match byte {
            RESET => {
                let answer = keyboard.self_test;
                self.output.push_back(answer);
            }
            SET_LIGHTS => keyboard.awaiting_lights = true,
            _ => {}
        }
    }
}

impl Io for SimController {
    fn out(&mut self, port: u16, byte: u8) {
        self.writes.push((port, byte));
        if !self.present {
            return;
        }
        match (port, byte) {
            (COMMAND, READ_CONFIGURATION) => self.output.push_back(self.configuration),
            (COMMAND, WRITE_CONFIGURATION) => self.awaiting_configuration = true,
            (COMMAND, DISABLE_KEYBOARD) => {
                self.interface_enabled = false;
                self.configuration |= 1 << 4;
            }
            (COMMAND, ENABLE_KEYBOARD) => {
                self.interface_enabled = true;
                self.configuration &= !(1 << 4);
            }
            (DATA, _) if self.awaiting_configuration => {
                self.awaiting_configuration = false;
                self.configuration = byte;
            }
            (DATA, _) => self.keyboard_takes(byte),
            _ => {}
        }
    }

    fn read(&mut self, port: u16) -> u8 {
        if !self.present {
            return 0xFF;
        }
        match port {
            STATUS => {
                if self.output.is_empty() {
                    0
                } else {
                    OUTPUT_FULL
                }
            }
            DATA => {
                if let Some(byte) = self.output.pop_front() {
                    self.last = byte;
                }
                self.last
            }
            _ => 0xFF,
        }
    }

    fn read_word(&mut self, _port: u16) -> u16 {
        unimplemented!("the controller has no word ports")
    }
}

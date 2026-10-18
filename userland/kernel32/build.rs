//! kernel32.dll's build: its stubs and .def from the export specs (see build-support/stubs.rs).
include!("../build-support/stubs.rs");

fn main() {
    build_dll("kernel32", 0x7C4E_0000, &[]);
}

// Boot-related code and data

// Include the limine header for limine boot protocol support
// We use a static variable to ensure this section is included in the binary
// The section must be writable so Limine can write response pointers
#[cfg(target_arch = "x86")]
#[used]
#[link_section = ".limine_requests"]
static mut LIMINE_HEADER: [u8; 136] = *include_bytes!("limine_header.bin");

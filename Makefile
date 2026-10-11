# F2K Makefile
# Windows 2000-compatible OS in Rust

# Architecture
ARCH ?= x86
TARGET ?= x86-f2k
# Build options (target spec, build-std, linker) live in .cargo/config.toml,
# so cargo and rust-analyzer use the same settings as make.
KERNEL_ELF ?= $(BUILD_DIR)/$(TARGET)/debug/f2k-kernel

# Directories
BOOT_DIR ?= boot
KERNEL_DIR ?= kernel
BUILD_DIR ?= target
SCRIPTS_DIR ?= scripts

# Tools
OBJCOPY ?= x86_64-elf-objcopy
NASM ?= nasm
DD ?= dd

# QEMU settings
QEMU ?= qemu-system-i386
QEMU_FLAGS ?= -m 256M -nographic -no-reboot -no-shutdown -net none

# Disk image settings
DISK_IMG ?= $(BUILD_DIR)/$(TARGET)/debug/f2k-disk.img
ISO_IMG ?= $(BUILD_DIR)/$(TARGET)/debug/f2k.iso
# 64MB disk image (131072 * 512 bytes): large enough for a spec-compliant FAT32 partition
DISK_SIZE ?= 131072

# Limine bootloader settings
LIMINE_DIR ?= $(BOOT_DIR)/limine
LIMINE_BIN ?= $(LIMINE_DIR)/limine
LIMINE_CD_BIN ?= $(LIMINE_DIR)/limine-bios-cd.bin
LIMINE_SYS ?= $(LIMINE_DIR)/limine-bios.sys
LIMINE_CONF ?= $(BOOT_DIR)/limine.conf

.PHONY: help
help:
	@echo "F2K Build System"
	@echo "================"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build everything and create bootable disk"
	@echo "  kernel       - Build the kernel only"
	@echo "  qemu         - Build the kernel and boot it directly in QEMU (Multiboot)"
	@echo "  test         - Run the boot smoke test"
	@echo "  test-disk    - Run the boot smoke test on the disk image"
	@echo "  kernel-bin   - Convert kernel to raw binary"
	@echo "  disk         - Create Limine-bootable hard disk image (needs mtools)"
	@echo "  limine       - Download/setup limine bootloader (if needed)"
	@echo "  iso          - Create bootable ISO with limine"
	@echo "  qemu_iso     - Create ISO and run in QEMU"
	@echo "  run          - Build and run in QEMU (raw disk)"
	@echo "  clean        - Clean build artifacts"
	@echo "  clobber      - Remove all build artifacts"
	@echo ""
	@echo "Environment:"
	@echo "  ARCH=x86             - Target architecture (default: x86)"
	@echo "  TARGET=x86-f2k       - Rust target (default: x86-f2k)"
	@echo "  DISK_IMG=...         - Disk image path"

.PHONY: all
all: disk

.PHONY: kernel
kernel:
	@echo "Building F2K kernel..."
	cd $(KERNEL_DIR) && cargo build
	@echo "Kernel built: $(KERNEL_ELF)"

.PHONY: qemu
qemu: kernel
	@echo "Booting F2K in QEMU (Multiboot via -kernel). Exit with Ctrl-A X."
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF)

.PHONY: kernel-bin
kernel-bin:
	@echo "Converting kernel to raw binary..."
	$(OBJCOPY) -O binary --only-section=.text --only-section=.rodata \
		$(BUILD_DIR)/$(TARGET)/debug/f2k-kernel \
		$(BUILD_DIR)/$(TARGET)/debug/f2k-kernel.raw
	@echo "Raw kernel: $(BUILD_DIR)/$(TARGET)/debug/f2k-kernel.raw"

.PHONY: disk
disk: kernel limine
	@echo "Creating Limine-bootable disk image..."
	rm -f $(DISK_IMG)
	$(DD) if=/dev/zero of=$(DISK_IMG) bs=512 count=$(DISK_SIZE)
	# MBR with one active FAT32 partition at 1 MiB; Limine's stage 2 goes in the gap before it
	python3 $(SCRIPTS_DIR)/create_partition_table.py $(DISK_IMG) $(DISK_SIZE)
	mformat -F -i $(DISK_IMG)@@1M -v F2K ::
	mmd -i $(DISK_IMG)@@1M ::/boot ::/boot/limine
	mcopy -i $(DISK_IMG)@@1M $(KERNEL_ELF) ::/f2k-kernel
	mcopy -i $(DISK_IMG)@@1M $(LIMINE_SYS) $(LIMINE_CONF) ::/boot/limine/
	$(LIMINE_BIN) bios-install $(DISK_IMG)
	@echo "Disk image created: $(DISK_IMG)"

.PHONY: run
run: disk
	@echo "Booting $(DISK_IMG) in QEMU. Exit with Ctrl-A X."
	$(QEMU) $(QEMU_FLAGS) -drive file=$(DISK_IMG),format=raw,if=ide

.PHONY: release
release:
	@echo "Building F2K kernel (release mode)..."
	cd $(KERNEL_DIR) && cargo build --release
	@echo "Kernel built: $(BUILD_DIR)/$(TARGET)/release/f2k-kernel"

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	cd $(KERNEL_DIR) && cargo clean

.PHONY: clobber
clobber: clean
	@echo "Removing target directory..."
	-rm -rf $(BUILD_DIR)

.PHONY: test test-boot
test: test-boot

# Boot smoke test: boots the kernel in QEMU and checks the banner on COM1
test-boot: kernel
	@scripts/test-boot.sh $(KERNEL_ELF)

.PHONY: test-disk
test-disk: disk
	@scripts/test-boot.sh $(DISK_IMG)

.PHONY: run-tests
run-tests:
	@echo "Running host unit tests..."
	cd $(KERNEL_DIR) && cargo test

.PHONY: check
check:
	@echo "Checking code..."
	cd $(KERNEL_DIR) && cargo check
	cd $(KERNEL_DIR) && cargo clippy

# =============================================================================
# Limine Bootloader Targets
# =============================================================================

ISO_DIR ?= $(BUILD_DIR)/$(TARGET)/debug/iso

.PHONY: limine
limine:
	@echo "Setting up limine bootloader..."
	@mkdir -p $(LIMINE_DIR)
	@if [ ! -f $(LIMINE_BIN) ]; then \
		echo "Downloading limine binary release..." && \
		curl -sL -o /tmp/limine.tar.xz https://github.com/Limine-Bootloader/Limine/releases/download/v12.9.3/limine-binary.tar.xz && \
		tar xJf /tmp/limine.tar.xz -C /tmp && \
		$(MAKE) -C /tmp/limine-binary limine && \
		cp /tmp/limine-binary/limine $(LIMINE_DIR)/ && \
		cp /tmp/limine-binary/limine-bios.sys $(LIMINE_DIR)/ && \
		cp /tmp/limine-binary/limine-bios-cd.bin $(LIMINE_DIR)/ && \
		chmod +x $(LIMINE_BIN) && \
		rm -rf /tmp/limine-binary /tmp/limine.tar.xz ; \
	fi
	@echo "Limine bootloader ready in $(LIMINE_DIR)/"

.PHONY: iso
iso: kernel limine
	@echo "Creating limine bootable ISO..."
	# Create ISO directory structure
	rm -rf $(ISO_DIR)
	mkdir -p $(ISO_DIR)/boot/limine
	cp $(LIMINE_CD_BIN) $(ISO_DIR)/
	cp $(LIMINE_SYS) $(ISO_DIR)/boot/limine/
	# The kernel is a 32-bit Multiboot 1 ELF (Limine's own protocol is 64-bit only)
	cp $(KERNEL_ELF) $(ISO_DIR)/f2k-kernel
	cp $(LIMINE_CONF) $(ISO_DIR)/boot/limine/
	# Create ISO with xorriso
	@echo "Creating ISO image..."
	@if ! command -v xorriso >/dev/null 2>&1; then \
		echo "ERROR: xorriso not found. Install with: brew install xorriso" && \
		false; \
	fi
	xorriso -as mkisofs \
		-R -r -J \
		-b limine-bios-cd.bin \
		-no-emul-boot \
		-boot-load-size 4 \
		-boot-info-table \
		$(ISO_DIR) -o $(ISO_IMG)
	# Install limine bootloader on the ISO image
	@echo "Installing limine bootloader on ISO image..."
	$(LIMINE_BIN) bios-install --force $(ISO_IMG)
	@echo "ISO created: $(ISO_IMG)"

.PHONY: qemu_iso
qemu_iso: iso
	@echo "Starting F2K ISO in QEMU..."
	$(QEMU) $(QEMU_FLAGS) -cdrom $(ISO_IMG) -boot d

# F2K Makefile
# Windows 2000-compatible OS in Rust

# Architecture
ARCH ?= x86
TARGET ?= x86-f2k
# Host triple for unit tests: .cargo/config.toml defaults cargo to the
# kernel target, so host tests (run-tests) override it back to the host
# (detected from the toolchain; override on the command line if needed).
RUST_HOST_TARGET ?= $(shell rustc -vV | sed -n 's/^host: //p')
# Build options (target spec, build-std, linker) live in .cargo/config.toml,
# so cargo and rust-analyzer use the same settings as make.
KERNEL_ELF ?= $(BUILD_DIR)/$(TARGET)/debug/f2k-kernel
# Cargo features for kernel builds (comma-separated, no spaces). The
# on-target suite passes them per case; manual builds accept them too
# (e.g. `make disk CARGO_FEATURES=run-ret0`).
CARGO_FEATURES ?=
FEATURE_FLAGS = $(if $(CARGO_FEATURES),--features $(CARGO_FEATURES),)

# Directories
BOOT_DIR ?= boot
KERNEL_DIR ?= kernel
BUILD_DIR ?= target
SCRIPTS_DIR ?= scripts

# Tools
# The on-target suite runner needs PyYAML: prefer the repository's .venv
# (where it is installed) over the system interpreter.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
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
# The corpus fixtures the disk carries in its root directory (tests/<name>/<name>.exe, stored as
# NAME.EXE), after HELLO.EXE: the boots load their images from the volume by these paths.
DISK_FIXTURES ?= exit0 ret0 pingpong sleep spin suspend respawn bsscheck crash fileio

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
	@echo "  qemu         - Build the disk and boot the kernel directly in QEMU (Multiboot, disk attached)"
	@echo "  test         - Run the on-target QEMU test suite (kernel path)"
	@echo "  test-disk    - Run the on-target QEMU test suite (disk path)"
	@echo "  run-tests    - Run host unit tests (cargo test --lib)"
	@echo "  check        - cargo check + clippy"
	@echo "  fmt          - Format all Rust sources (rustfmt)"
	@echo "  fmt-check    - Fail if any Rust source is not formatted"
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
	cd $(KERNEL_DIR) && cargo build $(FEATURE_FLAGS)
	@echo "Kernel built: $(KERNEL_ELF)"

.PHONY: qemu
qemu: disk
	@echo "Booting F2K in QEMU (Multiboot via -kernel, the disk attached). Exit with Ctrl-A X."
	$(QEMU) $(QEMU_FLAGS) -kernel $(KERNEL_ELF) -drive file=$(DISK_IMG),format=raw,if=ide

.PHONY: kernel-bin
kernel-bin:
	@echo "Converting kernel to raw binary..."
	$(OBJCOPY) -O binary \
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
	# The disk-smoke checksum fixture goes in first: the first file into a
	# fresh volume gets cluster 3 (LBA 4067), the sector the diagnostic
	# reads. It must stay ahead of every other copy and the mmd below (a
	# directory would take the cluster).
	mcopy -i $(DISK_IMG)@@1M tests/hello/hello.exe ::/HELLO.EXE
	mmd -i $(DISK_IMG)@@1M ::/boot ::/boot/limine
	mcopy -i $(DISK_IMG)@@1M $(KERNEL_ELF) ::/f2k-kernel
	mcopy -i $(DISK_IMG)@@1M $(LIMINE_SYS) $(LIMINE_CONF) ::/boot/limine/
	# The corpus the boots run, by 8.3 name: the loader reads every image from
	# the volume by path. The root's entries stay within its one sector.
	for fixture in $(DISK_FIXTURES); do \
		mcopy -i $(DISK_IMG)@@1M tests/$$fixture/$$fixture.exe \
			::/$$(echo $$fixture | tr a-z A-Z).EXE || exit 1; \
	done
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

# On-target QEMU suite: scripts/qemu-tests.yaml describes the cases
# (kernel features to build with, image to boot, expected COM1
# strings); scripts/run-qemu-tests.py builds and runs them. New cases
# are data, not new Makefile targets.
.PHONY: test test-disk
test: kernel
	@$(PYTHON) scripts/run-qemu-tests.py scripts/qemu-tests.yaml --image kernel

test-disk: disk
	@$(PYTHON) scripts/run-qemu-tests.py scripts/qemu-tests.yaml --image disk

.PHONY: run-tests
run-tests:
	@echo "Running host unit tests..."
	# CARGO_UNSTABLE_BUILD_STD=std: the workspace config builds core from
	# source for the kernel; for host tests that collides with the host's
	# prebuilt std, so build std (and its deps) from source instead.
	cd $(KERNEL_DIR) && CARGO_UNSTABLE_BUILD_STD=std cargo test --lib --target $(RUST_HOST_TARGET)

.PHONY: check
check:
	@echo "Checking code..."
	cd $(KERNEL_DIR) && cargo check
	cd $(KERNEL_DIR) && cargo clippy

# Formatting: settings live in rustfmt.toml at the workspace root.
.PHONY: fmt fmt-check
fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

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
qemu_iso: iso disk
	@echo "Starting F2K ISO in QEMU (the disk attached for the volume)..."
	$(QEMU) $(QEMU_FLAGS) -cdrom $(ISO_IMG) -boot d -drive file=$(DISK_IMG),format=raw,if=ide

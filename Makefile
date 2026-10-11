# F2K Makefile
# Windows 2000-compatible OS in Rust

# Architecture
ARCH ?= x86
TARGET ?= x86-f2k
LIMINE_TARGET ?= x86-f2k-limine

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
LIMINE_DISK_IMG ?= $(BUILD_DIR)/$(LIMINE_TARGET)/debug/f2k-limine-disk.img
ISO_IMG ?= $(BUILD_DIR)/$(LIMINE_TARGET)/debug/f2k.iso
DISK_SIZE ?= 20480  # 10MB disk image (20480 * 512 = 10485760 bytes) - VirtualBox recognizes this as HDD

# Limine bootloader settings
LIMINE_DIR ?= $(BOOT_DIR)/limine
LIMINE_BIN ?= $(LIMINE_DIR)/limine
LIMINE_CD_BIN ?= $(LIMINE_DIR)/limine-bios-cd.bin
LIMINE_SYS ?= $(LIMINE_DIR)/limine-bios.sys
LIMINE_HEADER_O ?= $(LIMINE_DIR)/limine_header.o
LIMINE_HEADER_ASM ?= $(KERNEL_DIR)/src/boot/limine_header.asm

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
	@echo "  kernel-bin   - Convert kernel to raw binary"
	@echo "  disk         - Create bootable disk image with kernel"
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
	cd $(KERNEL_DIR) && cargo +nightly build --target $(TARGET) -Zbuild-std=core,alloc,compiler_builtins -Zunstable-options
	@echo "Kernel built: $(BUILD_DIR)/$(TARGET)/debug/f2k-kernel"

.PHONY: kernel-limine
kernel-limine: compile-limine-header
	@echo "Building F2K kernel with Limine support..."
	cd $(KERNEL_DIR) && cargo +nightly build --target $(LIMINE_TARGET) -Zbuild-std=core,alloc,compiler_builtins -Zunstable-options
	@echo "Kernel built with Limine: $(BUILD_DIR)/$(LIMINE_TARGET)/debug/f2k-kernel"
	# Verify limine header is present
	@echo "Checking for limine header in kernel..."
	@if ! x86_64-elf-readelf -S $(BUILD_DIR)/$(LIMINE_TARGET)/debug/f2k-kernel | grep -q '.limine_requests'; then \
		echo "WARNING: .limine_requests section not found in kernel binary"; \
		echo "This is expected if the limine_header.asm is not being compiled into the kernel"; \
	fi

.PHONY: compile-limine-header
compile-limine-header:
	@echo "Compiling Limine header..."
	@mkdir -p $(LIMINE_DIR)
	@if [ ! -f $(LIMINE_HEADER_O) ] || [ $(LIMINE_HEADER_ASM) -nt $(LIMINE_HEADER_O) ]; then \
		if ! command -v $(NASM) >/dev/null 2>&1; then \
			echo "ERROR: NASM not found. Install with: brew install nasm"; \
			false; \
		fi; \
		$(NASM) -f elf32 $(LIMINE_HEADER_ASM) -o $(LIMINE_HEADER_O) && \
		echo "Limine header compiled: $(LIMINE_HEADER_O)"; \
	else \
		echo "Limine header up to date: $(LIMINE_HEADER_O)"; \
	fi

.PHONY: kernel-bin
kernel-bin:
	@echo "Converting kernel to raw binary..."
	$(OBJCOPY) -O binary --only-section=.text --only-section=.rodata \
		$(BUILD_DIR)/$(TARGET)/debug/f2k-kernel \
		$(BUILD_DIR)/$(TARGET)/debug/f2k-kernel.raw
	@echo "Raw kernel: $(BUILD_DIR)/$(TARGET)/debug/f2k-kernel.raw"

.PHONY: disk
disk: kernel kernel-bin
	@echo "Creating bootable disk image..."
	# Create empty disk image
	$(DD) if=/dev/zero of=$(DISK_IMG) bs=512 count=$(DISK_SIZE)
	# Write boot sector
	$(DD) if=$(BOOT_DIR)/boot_final.bin of=$(DISK_IMG) conv=notrunc
	# Write kernel at sector 1 (loaded at 0x100000 by bootloader)
	$(DD) if=$(BUILD_DIR)/$(TARGET)/debug/f2k-kernel.raw of=$(DISK_IMG) bs=512 seek=1 conv=notrunc
	@echo "Disk image created: $(DISK_IMG)"
	@echo "NOTE: Kernel entry point (_start) is at 0x100000"

.PHONY: limine-disk
limine-disk: kernel-limine
	@echo "Creating Limine-bootable disk image..."
	@scripts/create_limine_disk.sh

.PHONY: run-limine
run-limine: limine-disk
	@echo "Starting F2K with Limine in QEMU..."
	$(QEMU) $(QEMU_FLAGS) -hda $(LIMINE_DISK_IMG) -boot a

.PHONY: run
run: disk
	@echo "Starting F2K..."
	@echo "Note: QEMU 11.x on macOS has issues booting raw disk images."
	@echo "Disk image created: $(DISK_IMG)"
	@echo ""
	@echo "To run in VirtualBox (recommended for macOS):"
	@echo "  VBoxManage createvm --name F2K --ostype Linux24 --register"
	@echo "  VBoxManage storagectl F2K --name 'SATA' --add sata --bootable on"
	@echo "  VBoxManage storageattach F2K --storagectl SATA --port 0 --device 0 --type hdd --medium $(DISK_IMG)"
	@echo "  VBoxManage modifyvm F2K --memory 256"
	@echo "  VBoxManage startvm F2K"
	@echo ""
	@echo "To run in QEMU (may require older version < 8.0):"
	@echo "  $(QEMU) -m 256M -nographic -hda $(DISK_IMG) -boot a -net none"
	@echo ""
	@echo "For QEMU 11.x, try with explicit format:"
	@echo "  $(QEMU) -m 256M -nographic -drive file=$(DISK_IMG),format=raw,if=ide,file.locking=off -boot a -net none"
	@echo ""
	$(QEMU) $(QEMU_FLAGS) -hda $(DISK_IMG)

.PHONY: release
release:
	@echo "Building F2K kernel (release mode)..."
	cd $(KERNEL_DIR) && cargo +nightly build --target $(TARGET) --release -Zbuild-std=core,alloc,compiler_builtins -Zunstable-options
	@echo "Kernel built: $(BUILD_DIR)/$(TARGET)/release/f2k-kernel"

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	cd $(KERNEL_DIR) && cargo clean

.PHONY: clobber
clobber: clean
	@echo "Removing target directory..."
	-rm -rf $(BUILD_DIR)

.PHONY: test
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

ISO_DIR ?= $(BUILD_DIR)/$(LIMINE_TARGET)/debug/iso

.PHONY: limine
limine: compile-limine-header
	@echo "Setting up limine bootloader..."
	@mkdir -p $(LIMINE_DIR)
	@if [ ! -f $(LIMINE_BIN) ]; then \
		echo "Downloading limine binary release..." && \
		curl -sL -o /tmp/limine.tar.xz https://github.com/Limine-Bootloader/Limine/releases/download/v12.9.3/limine-binary.tar.xz && \
		tar xJf /tmp/limine.tar.xz -C /tmp && \
		cp /tmp/limine-binary/limine $(LIMINE_DIR)/ && \
		cp /tmp/limine-binary/limine-bios.sys $(LIMINE_DIR)/ && \
		cp /tmp/limine-binary/limine-bios-cd.bin $(LIMINE_DIR)/ && \
		chmod +x $(LIMINE_BIN) && \
		rm -rf /tmp/limine-binary /tmp/limine.tar.xz ; \
	fi
	@echo "Limine bootloader ready in $(LIMINE_DIR)/"

.PHONY: iso
iso: kernel-limine limine
	@echo "Creating limine bootable ISO..."
	# Create ISO directory structure
	rm -rf $(ISO_DIR)
	mkdir -p $(ISO_DIR)/boot/limine
	# Copy limine files to multiple locations (Limine looks in several places)
	cp $(LIMINE_CD_BIN) $(ISO_DIR)/
	cp $(LIMINE_SYS) $(ISO_DIR)/
	cp $(LIMINE_SYS) $(ISO_DIR)/boot/limine/
	# Create flat kernel binary with Limine header at the start
	@echo "Creating flat kernel binary..."
	@scripts/create_flat_kernel.sh
	# Copy kernel ELF to ISO (Limine can parse ELF headers to find entry point)
	cp $(BUILD_DIR)/$(LIMINE_TARGET)/debug/f2k-kernel $(ISO_DIR)/f2k-kernel
	chmod +x $(ISO_DIR)/f2k-kernel
	# Create limine.cfg with correct syntax (Limine uses 'key: value' format, not 'KEY=value')
	# Note: Some versions of Limine look for limine.cfg instead of limine.conf
	@echo "Creating limine.cfg..."
	@printf '/F2K - Fenêtre 2000\n    protocol: limine\n    path: /f2k-kernel\n    drive: 0x80\n    stack_size: 16384\n' > $(ISO_DIR)/limine.cfg
	cp $(ISO_DIR)/limine.cfg $(ISO_DIR)/limine.conf
	cp $(ISO_DIR)/limine.cfg $(ISO_DIR)/boot/limine/limine.cfg
	cp $(ISO_DIR)/limine.cfg $(ISO_DIR)/boot/limine/limine.conf
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

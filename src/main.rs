// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

#![feature(stmt_expr_attributes)]
#![feature(sync_unsafe_cell)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(
    all(not(test), not(feature = "integration_tests")),
    feature(alloc_error_handler)
)]
#![cfg_attr(test, allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "log-serial"), allow(unused_variables, unused_imports))]
#![cfg_attr(target_arch = "riscv64", feature(riscv_ext_intrinsics))]

#[cfg(all(not(test), not(feature = "integration_tests")))]
use core::panic::PanicInfo;

use log::{error, info, trace, warn};
#[cfg(all(
    not(test),
    not(feature = "integration_tests"),
    target_arch = "x86_64",
    feature = "log-panic"
))]
use x86_64::instructions::hlt;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::layout::code_range;

#[macro_use]
mod serial;

#[macro_use]
mod common;

mod arch;
mod block;
mod boot;
mod bootinfo;
mod bzimage;
#[cfg(target_arch = "x86_64")]
mod cmos;
#[cfg(target_arch = "x86_64")]
mod coreboot;
mod delay;
mod efi;
mod fat;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
mod fdt;
#[cfg(all(test, feature = "integration_tests"))]
mod integration;
mod layout;
mod loader;
mod logger;
mod mem;
mod part;
mod pci;
mod pe;
#[cfg(all(
    target_arch = "x86_64",
    not(feature = "coreboot"),
    not(feature = "td-shim")
))]
mod pvh;
mod rtc;
#[cfg(target_arch = "riscv64")]
mod rtc_goldfish;
#[cfg(target_arch = "aarch64")]
mod rtc_pl031;
#[cfg(all(target_arch = "x86_64", feature = "td-shim"))]
mod tdshim;
#[cfg(target_arch = "riscv64")]
mod uart_mmio;
#[cfg(target_arch = "aarch64")]
mod uart_pl011;
mod virtio;

#[cfg(all(not(test), not(feature = "integration_tests"), feature = "log-panic"))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    loop {
        #[cfg(target_arch = "x86_64")]
        hlt()
    }
}

#[cfg(all(
    not(test),
    not(feature = "integration_tests"),
    not(feature = "log-panic")
))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_BLOCK_DEVICE_ID: u16 = 0x1042;

#[allow(dead_code)]
#[derive(Debug)]
enum Error {
    Virtio(virtio::Error),
    Partition(part::Error),
    Fat(fat::Error),
    Loader(loader::Error),
    Pe(pe::Error),
    ImageTooLarge,
}

// Lets `pe::Loader` read an in-memory kernel image (already placed there by
// the VMM, e.g. cloud-hypervisor's `--kernel`) the same way it reads a file
// from the FAT filesystem.
#[cfg(feature = "td-shim")]
struct MemoryFileReader {
    base: u64,
    size: u64,
    position: u64,
}

#[cfg(feature = "td-shim")]
impl fat::Read for MemoryFileReader {
    fn read(&mut self, data: &mut [u8]) -> Result<u32, fat::Error> {
        if self.position + data.len() as u64 > self.size {
            return Err(fat::Error::EndOfFile);
        }
        let src = unsafe {
            core::slice::from_raw_parts((self.base + self.position) as *const u8, data.len())
        };
        data.copy_from_slice(src);
        self.position += data.len() as u64;
        Ok(data.len() as u32)
    }

    fn seek(&mut self, offset: u32) -> Result<(), fat::Error> {
        if offset as u64 > self.size {
            return Err(fat::Error::InvalidOffset);
        }
        self.position = offset as u64;
        Ok(())
    }

    fn get_size(&self) -> u32 {
        self.size as u32
    }
}

// Converts an ASCII/UTF-8 NUL-terminated-or-not command line into a NUL
// terminated UTF-16 buffer suitable for EFI_LOADED_IMAGE_PROTOCOL's
// LoadOptions, which is how a Linux kernel's EFI stub receives its command
// line when launched directly (as opposed to via a bootloader).
#[cfg(feature = "td-shim")]
fn cmdline_to_load_options(cmdline: &[u8], buf: &mut [u16]) -> (*mut core::ffi::c_void, u32) {
    let len = cmdline.len().min(buf.len() - 1);
    for (i, &b) in cmdline[..len].iter().enumerate() {
        buf[i] = b as u16;
    }
    buf[len] = 0;
    (
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        ((len + 1) * size_of::<u16>()) as u32,
    )
}

// Boots a kernel the VMM placed directly in memory (e.g. cloud-hypervisor's
// `--kernel`/`--cmdline`) via its own EFI stub, instead of searching the
// disk for a bootloader. This still gives the kernel full EFI boot/runtime
// services, same as the usual disk-based boot path below, just without
// going through GRUB/shim first.
#[cfg(feature = "td-shim")]
fn boot_external_kernel(
    device: &block::VirtioBlockDevice,
    f: &fat::Filesystem,
    info: &dyn bootinfo::Info,
    kernel_addr: u64,
    cmdline: &[u8],
) -> Result<(), Error> {
    info!("Booting VMM-supplied kernel directly via its EFI stub");

    let mut reader = MemoryFileReader {
        base: kernel_addr,
        size: tdshim::KERNEL_PAYLOAD_SIZE,
        position: 0,
    };
    let mut l = pe::Loader::new(&mut reader);

    // Relocate/load the kernel's own PE image just past the end of the
    // reserved region its raw (compressed) bytes are being read from above,
    // rather than at the usual `kernel_load_addr()` (used by the on-disk
    // bootloader path below): that address can overlap this source region
    // for a sufficiently large kernel, corrupting it mid-copy.
    let load_addr_hint = kernel_addr + tdshim::KERNEL_PAYLOAD_SIZE;
    let (entry_addr, load_addr, size) = match l.load(load_addr_hint) {
        Ok(load_info) => load_info,
        Err(err) => {
            error!("Error loading kernel EFI stub: {err:?}");
            return Err(Error::Pe(err));
        }
    };
    info!("Kernel EFI stub loaded");

    let mut load_options_buf = [0u16; 512];
    let load_options = cmdline_to_load_options(cmdline, &mut load_options_buf);

    efi::efi_exec(
        entry_addr,
        load_addr,
        size,
        info,
        f,
        device,
        Some(load_options),
    );
    Ok(())
}

fn boot_from_device(
    device: &mut block::VirtioBlockDevice,
    info: &dyn bootinfo::Info,
) -> Result<(), Error> {
    if let Err(err) = device.init() {
        error!("Error configuring block device: {err:?}");
        return Err(Error::Virtio(err));
    }
    info!(
        "Virtio block device configured. Capacity: {} sectors",
        device.get_capacity()
    );

    let (start, end) = match part::find_efi_partition(device) {
        Ok(p) => p,
        Err(err) => {
            error!("Failed to find EFI partition: {err:?}");
            return Err(Error::Partition(err));
        }
    };
    info!("Found EFI partition");

    let mut f = fat::Filesystem::new(device, start, end);
    if let Err(err) = f.init() {
        error!("Failed to create filesystem: {err:?}");
        return Err(Error::Fat(err));
    }
    info!("Filesystem ready");

    #[cfg(feature = "td-shim")]
    if let Some((kernel_addr, cmdline)) = info.kernel_payload() {
        return boot_external_kernel(device, &f, info, kernel_addr, cmdline);
    }

    match loader::load_default_entry(&f, info) {
        Ok(mut kernel) => {
            info!("Jumping to kernel");
            kernel.boot();
            return Ok(());
        }
        Err(err) => {
            warn!("Error loading default entry: {err:?}");
            // Fall through to EFI boot
        }
    }

    info!("Using EFI boot.");

    let mut file = match f.open(efi::EFI_BOOT_PATH) {
        Ok(file) => file,
        Err(err) => {
            error!("Failed to load default EFI binary: {err:?}");
            return Err(Error::Fat(err));
        }
    };
    info!("Found bootloader: {}", efi::EFI_BOOT_PATH);

    let mut l = pe::Loader::new(&mut file);

    let (entry_addr, load_addr, size) = match l.load(info.kernel_load_addr()) {
        Ok(load_info) => load_info,
        Err(err) => {
            error!("Error loading executable: {err:?}");
            return Err(Error::Pe(err));
        }
    };

    #[cfg(target_arch = "aarch64")]
    if code_range().start < (info.kernel_load_addr() + size) as usize {
        error!("Error Boot Image is too large");
        return Err(Error::ImageTooLarge);
    }

    info!("Executable loaded");
    efi::efi_exec(entry_addr, load_addr, size, info, &f, device, None);
    Ok(())
}

#[cfg(all(target_arch = "x86_64", not(feature = "td-shim")))]
#[no_mangle]
pub extern "C" fn rust64_start(#[cfg(not(feature = "coreboot"))] pvh_info: &pvh::StartInfo) -> ! {
    serial::init();
    logger::init();

    arch::x86_64::sse::enable_sse();
    arch::x86_64::paging::setup();
    arch::x86_64::vmx::enable_feature_control();

    #[cfg(feature = "coreboot")]
    let info = &coreboot::StartInfo::default();

    #[cfg(not(feature = "coreboot"))]
    let info = pvh_info;

    main(info)
}

// Entry point used when loaded as an "executable" payload by td-shim
// (https://github.com/confidential-containers/td-shim). Unlike the PVH/
// coreboot paths above, td-shim jumps here directly in 64-bit long mode with
// paging already enabled, passing the HOB list address in RDI and this
// image's own load address in RSI (see tdshim.rs). There is no stack set up
// for us, so the first thing we do is switch to our own.
#[cfg(all(target_arch = "x86_64", feature = "td-shim"))]
#[no_mangle]
pub extern "C" fn _start(hob_address: u64, _payload_address: u64) -> ! {
    let new_sp = arch::x86_64::layout::stack_range().end as u64;
    unsafe {
        core::arch::asm!(
            "mov rsp, {sp}",
            "mov rdi, {hob}",
            "jmp {entry}",
            sp = in(reg) new_sp,
            hob = in(reg) hob_address,
            entry = sym tdshim_start,
            options(noreturn),
        );
    }
}

#[cfg(all(target_arch = "x86_64", feature = "td-shim"))]
extern "C" fn tdshim_start(hob_address: u64) -> ! {
    serial::init();
    logger::init();

    arch::x86_64::sse::enable_sse();
    arch::x86_64::paging::setup();

    // td-shim's own temporary IDT (installed before jumping here) halts
    // fatally on any exception, including #VE; GRUB/shim do raw port I/O
    // we can't patch, so install a real handler that emulates it via
    // TDVMCALL instead of just trapping.
    td_exception::setup_exception_handlers();

    // Safety: td-shim passes a valid HOB list address in RDI.
    let info = unsafe { tdshim::StartInfo::new(hob_address) };

    main(&info)
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn rust64_start(x0: *const u8) -> ! {
    arch::aarch64::simd::setup_simd();
    arch::aarch64::paging::setup();

    // Use atomic operation before MMU enabled may cause exception, see https://www.ipshop.xyz/5909.html
    serial::PORT.borrow_mut().init();
    logger::init();

    let info = fdt::StartInfo::new(
        x0,
        Some(arch::aarch64::layout::map::dram::ACPI_START as u64),
        arch::aarch64::layout::map::dram::KERNEL_START as u64,
        &crate::arch::aarch64::layout::MEM_LAYOUT[..],
        None,
    );

    if let Some((base, length)) = info.find_compatible_region(&["pci-host-ecam-generic"]) {
        pci::init(base as u64, length as u64);
    }

    main(&info)
}

#[cfg(target_arch = "riscv64")]
#[no_mangle]
pub extern "C" fn rust64_start(a0: u64, a1: *const u8) -> ! {
    use crate::bootinfo::{EntryType, Info, MemoryEntry};

    serial::PORT.borrow_mut().init();
    logger::init();

    info!("Starting on RV64 0x{:x} 0x{:x}", a0, a1 as u64,);

    let info = fdt::StartInfo::new(
        a1,
        None,
        0x8040_0000,
        &crate::arch::riscv64::layout::MEM_LAYOUT[..],
        Some(MemoryEntry {
            addr: 0x4000_0000,
            size: 2 << 20,
            entry_type: EntryType::Reserved,
        }),
    );

    for i in 0..info.num_entries() {
        let region = info.entry(i);
        info!(
            "Memory region {}MiB@0x{:x}",
            region.size / 1024 / 1024,
            region.addr
        );
    }

    if let Some((base, length)) = info.find_compatible_region(&["pci-host-ecam-generic"]) {
        pci::init(base as u64, length as u64);
    }

    main(&info);
}

fn main(info: &dyn bootinfo::Info) -> ! {
    info!("Booting with {}", info.name());

    pci::print_bus();

    let mut next_address = info.pci_bar_memory().map(|m| m.addr);
    let max_address = info.pci_bar_memory().map(|m| m.addr + m.size);

    pci::with_devices(
        VIRTIO_PCI_VENDOR_ID,
        VIRTIO_PCI_BLOCK_DEVICE_ID,
        |mut pci_device| {
            trace!("main: calling pci_device.init");
            pci_device.init();
            trace!("main: pci_device.init done, calling allocate_bars");

            next_address = pci_device.allocate_bars(next_address);
            trace!("main: allocate_bars done, next_address={:x?}", next_address);
            if next_address > max_address {
                panic!("PCI BAR allocation space exceeded")
            }

            let mut pci_transport = pci::VirtioPciTransport::new(pci_device);
            let mut device = block::VirtioBlockDevice::new(&mut pci_transport);
            trace!("main: calling boot_from_device");
            boot_from_device(&mut device, info).is_ok()
        },
    );

    panic!("Unable to boot from any virtio-blk device")
}

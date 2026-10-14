// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 The Rust Hypervisor Firmware Authors

//! Boot support for running as an "executable" payload loaded by td-shim
//! (<https://github.com/confidential-containers/td-shim>).
//!
//! td-shim jumps straight to the ELF entry point in 64-bit long mode, with
//! paging and a minimal IDT already installed, passing the physical address
//! of the UEFI-PI Hand-Off Block (HOB) list in the first argument and the
//! payload's own load address in the second (see
//! `boot_builtin_payload()`/`ExecutablePayloadType::Elf` in td-shim's
//! `td-shim/src/bin/td-shim/main.rs`).
//!
//! This module only parses the two HOB entries this firmware needs -- the
//! E820 memory map and the ACPI tables -- directly against td-shim's HOB
//! format (documented in `doc/tdshim_spec.md` of the td-shim repository), so
//! that this crate does not need to depend on td-shim's own crates.

use core::{cell::SyncUnsafeCell, mem::size_of};

use crate::{
    bootinfo::{EntryType, Info, MemoryEntry},
    layout::MemoryDescriptor,
};

const HOB_TYPE_HANDOFF: u16 = 0x0001;
const HOB_TYPE_GUID_EXTENSION: u16 = 0x0004;
const HOB_TYPE_END_OF_HOB_LIST: u16 = 0xffff;

// td-shim's "E820 Memory Map GUID Extension HOB", see
// doc/tdshim_spec.md#e820-memory-map-guid-extension-hob.
const TD_E820_TABLE_HOB_GUID: [u8; 16] = [
    0xea, 0x72, 0x80, 0x8f, 0x86, 0x34, 0x47, 0x4b, 0x86, 0xa7, 0x23, 0x53, 0xb8, 0x8a, 0x87, 0x73,
];

// td-shim's "ACPI GUID Extension HOB", see
// doc/tdshim_spec.md#acpi-guid-extension-hob.
const TD_ACPI_TABLE_HOB_GUID: [u8; 16] = [
    0x70, 0x58, 0x0c, 0x6a, 0xed, 0xd4, 0xf4, 0x44, 0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0x0c, 0x8d,
];

// td-shim's "TD Payload Info GUID Extension HOB", see
// doc/tdshim_spec.md#td-payload-info-guid-extension-hob. Only present when
// the VMM supplied a kernel directly (e.g. cloud-hypervisor's `--kernel`)
// and td-shim's image was built with its "kernel-payload-via-executable"
// feature (see td-shim-tools' "kernel-payload-section" metadata feature).
const TD_PAYLOAD_INFO_HOB_GUID: [u8; 16] = [
    0x12, 0xa4, 0x6f, 0xb9, 0x1f, 0x46, 0xe3, 0x4b, 0x8c, 0x0d, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0,
];

// Image type values used in `PayloadInfo::image_type`; matches
// td-shim-interface's `TdPayloadInfoHobType`.
const TD_PAYLOAD_INFO_TYPE_BZIMAGE: u32 = 1;
const TD_PAYLOAD_INFO_TYPE_RAW_VMLINUX: u32 = 2;

// Fixed physical addresses the VMM copies an externally-supplied kernel
// (image bytes) and its command line into, when td-shim's image declares the
// corresponding metadata sections (see td-layout/src/runtime/exec.rs's
// KERNEL_PAYLOAD_BASE/KERNEL_PAYLOAD_PARAMETER_BASE, generated from
// devtools/td-layout-config/config_memory_exec.json -- these two repos must
// agree on these addresses). We use this fixed base directly rather than the
// HOB's own `entry_point` field: as of this writing QEMU's
// tdvf_hob_add_payload_info() (hw/i386/tdvf-hob.c) always sets it to 0.
const KERNEL_PAYLOAD_PARAMETER_BASE: u64 = 0x820000;
const KERNEL_PAYLOAD_PARAMETER_SIZE: usize = 0x1000;
const KERNEL_PAYLOAD_BASE: u64 = KERNEL_PAYLOAD_PARAMETER_BASE + KERNEL_PAYLOAD_PARAMETER_SIZE as u64;
pub(crate) const KERNEL_PAYLOAD_SIZE: u64 = 0x2000000;

// Maximum number of ACPI tables we can reference from the XSDT we build.
const MAX_ACPI_TABLES: usize = 20;

#[derive(Clone, Copy)]
#[repr(C)]
struct HobHeader {
    r#type: u16,
    length: u16,
    reserved: u32,
}

// Hand-Off Information Table (PHIT), always the first HOB in the list.
#[derive(Clone, Copy)]
#[repr(C)]
struct HandoffInfoTable {
    header: HobHeader,
    version: u32,
    boot_mode: u32,
    efi_memory_top: u64,
    efi_memory_bottom: u64,
    efi_free_memory_top: u64,
    efi_free_memory_bottom: u64,
    efi_end_of_hob_list: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct GuidExtensionHeader {
    header: HobHeader,
    name: [u8; 16],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct PayloadInfo {
    image_type: u32,
    _reserved: u32,
    entry_point: u64,
}

#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
struct TdE820Entry {
    addr: u64,
    size: u64,
    entry_type: u32,
}

impl From<TdE820Entry> for MemoryEntry {
    fn from(e: TdE820Entry) -> Self {
        // td-shim's E820Type has two extra variants ("Pmem" == 7 and
        // "Unaccepted" == 8, used with the lazy-accept feature) that this
        // firmware's bootinfo::EntryType has no slot for; treat them as
        // reserved rather than panicking in EntryType::from().
        let entry_type = match e.entry_type {
            7 | 8 => 2, // Reserved
            t => t,
        };
        MemoryEntry {
            addr: e.addr,
            size: e.size,
            entry_type: EntryType::from(entry_type),
        }
    }
}

#[inline]
unsafe fn read<T: Copy>(addr: u64) -> T {
    core::ptr::read_unaligned(addr as *const T)
}

#[inline]
fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) }
}

// HOBs are always aligned to the next 8-byte boundary after the header.
fn align_hob_length(length: u16) -> u64 {
    (length as u64 + 7) / 8 * 8
}

fn checksum(data: &[u8]) -> u8 {
    0u8.wrapping_sub(data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)))
}

#[repr(C, packed)]
#[derive(Default)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_addr: u32,
    length: u32,
    xsdt_addr: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

impl Rsdp {
    const fn empty() -> Rsdp {
        Rsdp {
            signature: [0; 8],
            checksum: 0,
            oem_id: [0; 6],
            revision: 0,
            rsdt_addr: 0,
            length: 0,
            xsdt_addr: 0,
            extended_checksum: 0,
            reserved: [0; 3],
        }
    }

    fn new(xsdt_addr: u64) -> Rsdp {
        let mut rsdp = Rsdp {
            signature: *b"RSD PTR ",
            oem_id: *b"RHFWTD",
            revision: 2, // ACPI 2.0+, so the extended (XSDT) fields are valid
            length: size_of::<Rsdp>() as u32,
            xsdt_addr,
            ..Rsdp::empty()
        };
        // The first 20 bytes (the ACPI 1.0 part) and the whole structure each
        // need to sum to zero, mod 256.
        rsdp.checksum = checksum(&as_bytes(&rsdp)[0..20]);
        rsdp.extended_checksum = checksum(as_bytes(&rsdp));
        rsdp
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GenericSdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

impl GenericSdtHeader {
    const fn new(signature: &[u8; 4], length: u32) -> GenericSdtHeader {
        GenericSdtHeader {
            signature: *signature,
            length,
            revision: 1,
            checksum: 0,
            oem_id: *b"RHFWTD",
            oem_table_id: u64::from_le_bytes(*b"HVISORFW"),
            oem_revision: 1,
            creator_id: u32::from_le_bytes(*b"RHFW"),
            creator_revision: 1,
        }
    }
}

#[repr(C, packed)]
struct Xsdt {
    header: GenericSdtHeader,
    tables: [u64; MAX_ACPI_TABLES],
}

impl Xsdt {
    const fn empty() -> Xsdt {
        Xsdt {
            header: GenericSdtHeader::new(b"XSDT", size_of::<GenericSdtHeader>() as u32),
            tables: [0; MAX_ACPI_TABLES],
        }
    }

    fn add_table(&mut self, addr: u64) -> Result<(), ()> {
        let num_tables =
            (self.header.length as usize - size_of::<GenericSdtHeader>()) / size_of::<u64>();
        if num_tables >= MAX_ACPI_TABLES {
            return Err(());
        }
        self.tables[num_tables] = addr;
        self.header.length += size_of::<u64>() as u32;
        Ok(())
    }

    fn checksum(&mut self) {
        self.header.checksum = 0;
        let length = self.header.length as usize;
        self.header.checksum = checksum(&as_bytes(self)[..length]);
    }
}

struct AcpiTables {
    rsdp: Rsdp,
    xsdt: Xsdt,
}

impl AcpiTables {
    const fn empty() -> AcpiTables {
        AcpiTables {
            rsdp: Rsdp::empty(),
            xsdt: Xsdt::empty(),
        }
    }
}

// The RSDP/XSDT we hand back to the loaded kernel/bootloader need a stable
// address, so they are built in-place in this static rather than as fields
// of `StartInfo` (which is free to be moved around on the stack).
static ACPI_TABLES: SyncUnsafeCell<AcpiTables> = SyncUnsafeCell::new(AcpiTables::empty());

// Returns the physical address just past the last HOB (the end of the list).
unsafe fn hob_list_end(hob_address: u64) -> u64 {
    let phit: HandoffInfoTable = read(hob_address);
    assert_eq!(
        phit.header.r#type, HOB_TYPE_HANDOFF,
        "td-shim HOB list does not start with a PHIT HOB"
    );
    phit.efi_end_of_hob_list
}

// Finds the E820 memory map GUID-extension HOB, if any, and returns it as a
// slice pointing directly into the (identity-mapped) HOB list memory.
unsafe fn find_e820_table(hob_address: u64, hob_end: u64) -> &'static [TdE820Entry] {
    let mut offset = hob_address;
    while offset < hob_end {
        let header: HobHeader = read(offset);
        if header.r#type == HOB_TYPE_END_OF_HOB_LIST {
            break;
        }
        if header.r#type == HOB_TYPE_GUID_EXTENSION {
            let ext: GuidExtensionHeader = read(offset);
            if ext.name == TD_E820_TABLE_HOB_GUID {
                let data_addr = offset + size_of::<GuidExtensionHeader>() as u64;
                let data_len = header.length as usize - size_of::<GuidExtensionHeader>();
                return core::slice::from_raw_parts(
                    data_addr as *const TdE820Entry,
                    data_len / size_of::<TdE820Entry>(),
                );
            }
        }
        offset += align_hob_length(header.length);
    }
    &[]
}

// FADT field offsets (ACPI 6.x, table 5.9).
const FADT_FIRMWARE_CTRL_OFFSET: usize = 36;
const FADT_DSDT_OFFSET: usize = 40;
const FADT_X_FIRMWARE_CTRL_OFFSET: usize = 132;
const FADT_X_DSDT_OFFSET: usize = 140;

// The VMM hands over its FADT with the DSDT/FACS pointers unset, since it
// cannot know where the tables will end up; link them to where they live in
// the HOB list, as td-shim does itself (see `AcpiTables::finish()` in
// td-shim/src/bin/td-shim/acpi.rs) when it builds the RSDP.
unsafe fn link_fadt(fadt_addr: u64, dsdt_addr: Option<u64>, facs_addr: Option<u64>) {
    let header: GenericSdtHeader = read(fadt_addr);
    let fadt = core::slice::from_raw_parts_mut(fadt_addr as *mut u8, header.length as usize);

    let mut set_pointer = |addr: Option<u64>, offset: usize, x_offset: usize| {
        let Some(addr) = addr else { return };
        if fadt.len() >= offset + 4 {
            let addr32 = u32::try_from(addr).unwrap_or(0);
            fadt[offset..offset + 4].copy_from_slice(&addr32.to_le_bytes());
        }
        if fadt.len() >= x_offset + 8 {
            fadt[x_offset..x_offset + 8].copy_from_slice(&addr.to_le_bytes());
        }
    };
    set_pointer(dsdt_addr, FADT_DSDT_OFFSET, FADT_X_DSDT_OFFSET);
    set_pointer(
        facs_addr,
        FADT_FIRMWARE_CTRL_OFFSET,
        FADT_X_FIRMWARE_CTRL_OFFSET,
    );

    fadt[9] = 0;
    fadt[9] = checksum(fadt);
}

// Collects every ACPI GUID-extension HOB into a freshly built XSDT/RSDP pair
// (each ACPI table is referenced in place, not copied) and returns the
// physical address of the RSDP, if at least one ACPI table was found.
unsafe fn build_acpi_tables(hob_address: u64, hob_end: u64) -> Option<u64> {
    let tables = &mut *ACPI_TABLES.get();
    tables.xsdt = Xsdt::empty();

    let mut fadt_addr = None;
    let mut dsdt_addr = None;
    let mut facs_addr = None;
    let mut other_tables = [0u64; MAX_ACPI_TABLES];
    let mut num_other_tables = 0usize;

    let mut offset = hob_address;
    while offset < hob_end {
        let header: HobHeader = read(offset);
        if header.r#type == HOB_TYPE_END_OF_HOB_LIST {
            break;
        }
        if header.r#type == HOB_TYPE_GUID_EXTENSION {
            let ext: GuidExtensionHeader = read(offset);
            if ext.name == TD_ACPI_TABLE_HOB_GUID {
                let table_addr = offset + size_of::<GuidExtensionHeader>() as u64;
                // DSDT and FACS are referenced from the FADT, never from the XSDT.
                match &read::<[u8; 4]>(table_addr) {
                    b"FACP" => fadt_addr = fadt_addr.or(Some(table_addr)),
                    b"DSDT" => dsdt_addr = dsdt_addr.or(Some(table_addr)),
                    b"FACS" => facs_addr = facs_addr.or(Some(table_addr)),
                    _ if num_other_tables < MAX_ACPI_TABLES => {
                        other_tables[num_other_tables] = table_addr;
                        num_other_tables += 1;
                    }
                    _ => {}
                }
            }
        }
        offset += align_hob_length(header.length);
    }

    // The FADT should always be the first table in the XSDT.
    if let Some(fadt_addr) = fadt_addr {
        link_fadt(fadt_addr, dsdt_addr, facs_addr);
        let _ = tables.xsdt.add_table(fadt_addr);
    }
    for &table_addr in &other_tables[..num_other_tables] {
        let _ = tables.xsdt.add_table(table_addr);
    }

    if fadt_addr.is_none() && num_other_tables == 0 {
        return None;
    }

    tables.xsdt.checksum();
    let xsdt_addr = &tables.xsdt as *const Xsdt as u64;
    tables.rsdp = Rsdp::new(xsdt_addr);
    Some(&tables.rsdp as *const Rsdp as u64)
}

// Finds the externally-supplied kernel's address (if the VMM was given one,
// e.g. cloud-hypervisor's `--kernel`, and this image was built with
// td-shim's "kernel-payload-via-executable" feature so td-shim defers to
// us instead of raw-booting it itself), and the physical address of its
// (fixed-location) command line, which the VMM writes there as a plain
// NUL-terminated string regardless of whether a kernel HOB is present.
unsafe fn find_kernel_payload(hob_address: u64, hob_end: u64) -> Option<(u64, &'static [u8])> {
    let mut offset = hob_address;
    while offset < hob_end {
        let header: HobHeader = read(offset);
        if header.r#type == HOB_TYPE_END_OF_HOB_LIST {
            break;
        }
        if header.r#type == HOB_TYPE_GUID_EXTENSION {
            let ext: GuidExtensionHeader = read(offset);
            if ext.name == TD_PAYLOAD_INFO_HOB_GUID {
                let data_addr = offset + size_of::<GuidExtensionHeader>() as u64;
                let info: PayloadInfo = read(data_addr);
                if info.image_type != TD_PAYLOAD_INFO_TYPE_BZIMAGE
                    && info.image_type != TD_PAYLOAD_INFO_TYPE_RAW_VMLINUX
                {
                    return None;
                }
                let cmdline_bytes = core::slice::from_raw_parts(
                    KERNEL_PAYLOAD_PARAMETER_BASE as *const u8,
                    KERNEL_PAYLOAD_PARAMETER_SIZE,
                );
                let cmdline_len = cmdline_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(cmdline_bytes.len());
                return Some((KERNEL_PAYLOAD_BASE, &cmdline_bytes[..cmdline_len]));
            }
        }
        offset += align_hob_length(header.length);
    }
    None
}

pub struct StartInfo {
    e820_table: &'static [TdE820Entry],
    rsdp_addr: Option<u64>,
    kernel_payload: Option<(u64, &'static [u8])>,
}

impl StartInfo {
    /// Parses the td-shim HOB list at `hob_address` (as passed in RDI to the
    /// payload entry point).
    ///
    /// # Safety
    /// `hob_address` must point to a valid, well-formed td-shim HOB list that
    /// stays mapped and unmodified for the remaining lifetime of the
    /// firmware.
    pub unsafe fn new(hob_address: u64) -> StartInfo {
        let hob_end = hob_list_end(hob_address);
        StartInfo {
            e820_table: find_e820_table(hob_address, hob_end),
            rsdp_addr: build_acpi_tables(hob_address, hob_end),
            kernel_payload: find_kernel_payload(hob_address, hob_end),
        }
    }
}

impl Info for StartInfo {
    fn name(&self) -> &str {
        "td-shim"
    }

    fn rsdp_addr(&self) -> Option<u64> {
        self.rsdp_addr
    }

    fn cmdline(&self) -> &[u8] {
        &[]
    }

    fn kernel_payload(&self) -> Option<(u64, &'static [u8])> {
        self.kernel_payload
    }

    fn num_entries(&self) -> usize {
        self.e820_table.len()
    }

    fn entry(&self, idx: usize) -> MemoryEntry {
        self.e820_table[idx].into()
    }

    fn kernel_load_addr(&self) -> u64 {
        crate::arch::x86_64::layout::KERNEL_START
    }

    fn memory_layout(&self) -> &'static [MemoryDescriptor] {
        &crate::arch::x86_64::layout::MEM_LAYOUT[..]
    }

    fn pci_bar_memory(&self) -> Option<MemoryEntry> {
        // td-shim's HOB doesn't describe the PCI MMIO hole (it's not backed
        // RAM, so it has no e820 entry); unlike cloud-hypervisor, QEMU
        // doesn't pre-assign BAR addresses itself, so without this,
        // allocate_bars() has nowhere to place unassigned BARs. Use the
        // standard low PCI MMIO window SeaBIOS/OVMF use for QEMU's q35
        // chipset: right above the default 256 MiB PCIe MMCONFIG area at
        // 0xb0000000, and below the fixed IOAPIC at 0xfec00000.
        const PCI_MMIO_BASE: u64 = 0xc000_0000;
        const PCI_MMIO_END: u64 = 0xfec0_0000;
        Some(MemoryEntry {
            addr: PCI_MMIO_BASE,
            size: PCI_MMIO_END - PCI_MMIO_BASE,
            entry_type: EntryType::Reserved,
        })
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Google LLC

use core::cell::SyncUnsafeCell;
use log::info;
use x86_64::{
    registers::control::Cr3,
    structures::paging::{PageSize, PageTable, PageTableFlags, PhysFrame, Size2MiB},
    PhysAddr,
};

// Amount of memory we identity map in setup(), max 512 GiB.
const ADDRESS_SPACE_GIB: usize = 4;
const TABLE: PageTable = PageTable::new();

// Put the Page Tables in static muts to make linking easier
#[no_mangle]
static L4_TABLE: SyncUnsafeCell<PageTable> = SyncUnsafeCell::new(PageTable::new());
#[no_mangle]
static L3_TABLE: SyncUnsafeCell<PageTable> = SyncUnsafeCell::new(PageTable::new());
#[no_mangle]
static L2_TABLES: SyncUnsafeCell<[PageTable; ADDRESS_SPACE_GIB]> =
    SyncUnsafeCell::new([TABLE; ADDRESS_SPACE_GIB]);

pub fn setup() {
    // SAFETY: This function is idempontent and only writes to static memory and
    // CR3. Thus, it is safe to run multiple times or on multiple threads.
    let (l4, l3, l2s) = unsafe {
        (
            &mut *L4_TABLE.get(),
            &mut *L3_TABLE.get(),
            &mut *L2_TABLES.get(),
        )
    };
    info!("Setting up {ADDRESS_SPACE_GIB} GiB identity mapping");
    let pt_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    // Setup Identity map using L2 huge pages
    let mut next_addr = PhysAddr::new(0);
    for l2 in l2s.iter_mut() {
        for l2e in l2.iter_mut() {
            l2e.set_addr(next_addr, pt_flags | PageTableFlags::HUGE_PAGE);
            next_addr += Size2MiB::SIZE;
        }
    }

    // Point L3 at L2s
    for (i, l2) in l2s.iter().enumerate() {
        l3[i].set_addr(phys_addr(l2), pt_flags);
    }

    // Point L4 at L3
    l4[0].set_addr(phys_addr(l3), pt_flags);

    // Point Cr3 at L4
    let (cr3_frame, cr3_flags) = Cr3::read();
    let l4_frame = PhysFrame::from_start_address(phys_addr(l4)).unwrap();
    if cr3_frame != l4_frame {
        unsafe { Cr3::write(l4_frame, cr3_flags) };
    }
    info!("Page tables setup");
}

// Map a virtual address to a PhysAddr (assumes identity mapping)
fn phys_addr<T>(virt_addr: *const T) -> PhysAddr {
    PhysAddr::new(virt_addr as u64)
}

// TDX guests must mark DMA-visible memory (e.g. virtio rings/buffers) as
// "shared" so the host-side device backend can access it; private memory is
// encrypted and invisible to the host. This splits our 2 MiB identity-mapped
// huge pages down to 4 KiB granularity as needed to flip that bit precisely.
#[cfg(feature = "td-shim")]
mod shared {
    use super::{phys_addr, L2_TABLES};
    use x86_64::{
        structures::paging::{
            page_table::PageTableEntry, PageSize, PageTable, PageTableFlags, Size1GiB, Size2MiB,
            Size4KiB,
        },
        PhysAddr,
    };

    // At most one 2 MiB region needs splitting for our (sub-page-sized)
    // shared virtio I/O buffer; keep a small margin regardless.
    const MAX_SPLITS: usize = 2;
    const EMPTY_TABLE: PageTable = PageTable::new();
    static SPLIT_TABLES: core::cell::SyncUnsafeCell<[PageTable; MAX_SPLITS]> =
        core::cell::SyncUnsafeCell::new([EMPTY_TABLE; MAX_SPLITS]);
    static mut SPLIT_COUNT: usize = 0;

    fn l2_entry(addr: u64) -> &'static mut PageTableEntry {
        // SAFETY: `paging::setup()` has already run, and this is boot-time,
        // single-threaded code.
        let l2s = unsafe { &mut *L2_TABLES.get() };
        let gib = (addr / Size1GiB::SIZE) as usize;
        let index = ((addr % Size1GiB::SIZE) / Size2MiB::SIZE) as usize;
        &mut l2s[gib][index]
    }

    // Splits the 2 MiB mapping covering `addr` into a 4 KiB-granularity page
    // table (if not done already) and returns it.
    fn split_2mib(addr: u64) -> &'static mut PageTable {
        let region_base = addr & !(Size2MiB::SIZE - 1);
        let entry = l2_entry(region_base);

        if !entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // SAFETY: only ever points at one of our own SPLIT_TABLES entries.
            return unsafe { &mut *(entry.addr().as_u64() as *mut PageTable) };
        }

        let flags = entry.flags() & !PageTableFlags::HUGE_PAGE;
        let frame_base = entry.addr().as_u64();

        // SAFETY: boot-time only, single-threaded.
        let table = unsafe {
            let index = SPLIT_COUNT;
            assert!(index < MAX_SPLITS, "Out of page-table split slots");
            SPLIT_COUNT = index + 1;
            &mut (*SPLIT_TABLES.get())[index]
        };
        for (i, l1e) in table.iter_mut().enumerate() {
            l1e.set_addr(
                PhysAddr::new(frame_base + (i as u64) * Size4KiB::SIZE),
                flags,
            );
        }

        entry.set_addr(phys_addr(table), flags);
        table
    }

    fn toggle_shared_bit(addr: u64, length: usize, shared: bool) {
        assert_eq!(addr % Size4KiB::SIZE, 0, "address must be 4 KiB aligned");
        assert_eq!(
            length as u64 % Size4KiB::SIZE,
            0,
            "length must be 4 KiB aligned"
        );

        let shared_mask =
            tdx_tdcall::tdx::td_shared_mask().expect("Failed to get the TD shared GPA mask");

        let mut page = addr;
        let end = addr + length as u64;
        while page < end {
            let table = split_2mib(page);
            let index = ((page % Size2MiB::SIZE) / Size4KiB::SIZE) as usize;
            let entry = &mut table[index];
            let flags = entry.flags();
            let phys = entry.addr().as_u64() & !shared_mask;
            let new_phys = if shared { phys | shared_mask } else { phys };
            entry.set_addr(PhysAddr::new(new_phys), flags);
            page += Size4KiB::SIZE;
        }

        x86_64::instructions::tlb::flush_all();
    }

    /// Marks `[addr, addr + length)` as TDX shared (unencrypted) memory.
    /// `addr` and `length` must be 4 KiB aligned.
    pub fn set_shared_bit(addr: u64, length: usize) {
        toggle_shared_bit(addr, length, true)
    }
}

#[cfg(feature = "td-shim")]
pub use shared::set_shared_bit;

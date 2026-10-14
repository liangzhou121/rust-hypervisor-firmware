// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

use core::cell::RefCell;

use log::trace;

use crate::virtio::{Error as VirtioError, VirtioTransport};

const QUEUE_SIZE: usize = 16;

#[repr(C)]
#[repr(align(16))]
#[derive(Default)]
/// A virtio qeueue entry descriptor
struct Desc {
    addr: u64,
    length: u32,
    flags: u16,
    next: u16,
}

impl Desc {
    const fn new() -> Self {
        Self {
            addr: 0,
            length: 0,
            flags: 0,
            next: 0,
        }
    }
}

#[repr(C)]
#[repr(align(2))]
#[derive(Default)]
/// The virtio available ring
struct AvailRing {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE],
}

impl AvailRing {
    const fn new() -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: [0; QUEUE_SIZE],
        }
    }
}

#[repr(C)]
#[repr(align(4))]
#[derive(Default)]
/// The virtio used ring
struct UsedRing {
    flags: u16,
    idx: u16,
    ring: [UsedElem; QUEUE_SIZE],
}

impl UsedRing {
    const fn new() -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: [UsedElem::new(); QUEUE_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
/// A single element in the used ring
struct UsedElem {
    id: u32,
    len: u32,
}

impl UsedElem {
    const fn new() -> Self {
        Self { id: 0, len: 0 }
    }
}

#[cfg(not(feature = "td-shim"))]
type DeviceState = DriverState;
#[cfg(feature = "td-shim")]
type DeviceState = &'static mut DriverState;

#[repr(C)]
#[repr(align(64))]
/// Device driver for virtio block over any transport
pub struct VirtioBlockDevice<'a> {
    transport: &'a mut dyn VirtioTransport,
    state: RefCell<DeviceState>,
    read_only: bool,
}

#[repr(C)]
#[repr(align(64))]
#[derive(Default)]
struct DriverState {
    descriptors: [Desc; QUEUE_SIZE],
    avail: AvailRing,
    used: UsedRing,
    next_head: usize,
}

impl DriverState {
    const fn new() -> Self {
        Self {
            descriptors: [const { Desc::new() }; QUEUE_SIZE],
            avail: AvailRing::new(),
            used: UsedRing::new(),
            next_head: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BlockIO,
    NoDataBuf,
    InvalidDataBufSize,

    BlockNotSupported,
}

#[repr(C)]
/// Header used for virtio block requests
struct BlockRequestHeader {
    request: u32,
    reserved: u32,
    sector: u64,
}

impl BlockRequestHeader {
    const fn new() -> Self {
        Self {
            request: 0,
            reserved: 0,
            sector: 0,
        }
    }
}

#[repr(C)]
/// Footer used for virtio block requests
struct BlockRequestFooter {
    status: u8,
}

impl BlockRequestFooter {
    const fn new() -> Self {
        Self { status: 0 }
    }
}

// The virtio-blk backend runs in the host (VMM), which under TDX can only
// access shared, not private/encrypted, guest memory. Stage the queue
// (descriptors/avail/used rings) and per-request header/footer/data in a
// dedicated, page-aligned region that gets marked TDX-shared once, instead of
// using regular private memory for virtio DMA.
#[cfg(feature = "td-shim")]
#[repr(C, align(4096))]
struct SharedBlockIo {
    state: DriverState,
    header: BlockRequestHeader,
    footer: BlockRequestFooter,
    bounce: SectorBuf,
}

#[cfg(feature = "td-shim")]
impl SharedBlockIo {
    const fn new() -> Self {
        Self {
            state: DriverState::new(),
            header: BlockRequestHeader::new(),
            footer: BlockRequestFooter::new(),
            bounce: SectorBuf::new(),
        }
    }
}

#[cfg(feature = "td-shim")]
static SHARED_BLOCK_IO: core::cell::SyncUnsafeCell<SharedBlockIo> =
    core::cell::SyncUnsafeCell::new(SharedBlockIo::new());

// These each project out a single, disjoint field of `SHARED_BLOCK_IO`
// through a raw pointer, so holding several of them at once (e.g. `state` for
// the lifetime of the device, `header`/`footer`/`bounce` only within a single
// `request()` call) never creates overlapping `&mut` references.
#[cfg(feature = "td-shim")]
fn shared_state() -> &'static mut DriverState {
    unsafe { &mut *core::ptr::addr_of_mut!((*SHARED_BLOCK_IO.get()).state) }
}

#[cfg(feature = "td-shim")]
fn shared_header() -> &'static mut BlockRequestHeader {
    unsafe { &mut *core::ptr::addr_of_mut!((*SHARED_BLOCK_IO.get()).header) }
}

#[cfg(feature = "td-shim")]
fn shared_footer() -> &'static mut BlockRequestFooter {
    unsafe { &mut *core::ptr::addr_of_mut!((*SHARED_BLOCK_IO.get()).footer) }
}

#[cfg(feature = "td-shim")]
fn shared_bounce() -> &'static mut SectorBuf {
    unsafe { &mut *core::ptr::addr_of_mut!((*SHARED_BLOCK_IO.get()).bounce) }
}

/// Marks the virtio request staging area as TDX shared memory. Must be
/// called once before any virtio request is made; safe to call more than
/// once.
#[cfg(feature = "td-shim")]
fn init_shared_memory() {
    const PAGE_SIZE: usize = 0x1000;

    let addr = SHARED_BLOCK_IO.get() as u64;
    let len = (core::mem::size_of::<SharedBlockIo>() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    trace!("init_shared_memory: addr=0x{:x} len=0x{:x}", addr, len);
    crate::arch::x86_64::paging::set_shared_bit(addr, len);
    trace!("init_shared_memory: shared bit set, calling tdvmcall_mapgpa");
    if tdx_tdcall::tdx::tdvmcall_mapgpa(true, addr, len).is_err() {
        panic!("Failed to map virtio shared I/O region as TDX shared memory");
    }
    trace!("init_shared_memory: done");
}

const SECTOR_SIZE: usize = 512;

#[repr(C)]
pub struct SectorBuf([u8; SECTOR_SIZE]);

impl SectorBuf {
    pub const fn new() -> Self {
        Self([0_u8; SECTOR_SIZE])
    }

    #[inline]
    pub const fn len() -> usize {
        SECTOR_SIZE
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

pub trait SectorRead {
    /// Read a single sector (512 bytes) from the block device. `data` must be
    /// exactly 512 bytes long.
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), Error>;
}

pub trait SectorWrite {
    /// Write a single sector (512 bytes) from the block device. `data` must be
    /// exactly 512 bytes long.
    fn write(&self, sector: u64, data: &mut [u8]) -> Result<(), Error>;
    fn flush(&self) -> Result<(), Error>;
}

#[derive(PartialEq, Eq, Copy, Clone)]
enum RequestType {
    Read = 0,
    Write = 1,
    Flush = 4,
}

impl<'a> VirtioBlockDevice<'a> {
    pub fn new(transport: &'a mut dyn VirtioTransport) -> VirtioBlockDevice<'a> {
        VirtioBlockDevice {
            transport,
            #[cfg(not(feature = "td-shim"))]
            state: RefCell::new(DriverState::default()),
            #[cfg(feature = "td-shim")]
            state: RefCell::new(shared_state()),
            read_only: false,
        }
    }

    pub fn init(&mut self) -> Result<(), VirtioError> {
        const VIRTIO_SUBSYSTEM_BLOCK: u32 = 0x2;
        const VIRTIO_F_VERSION_1: u64 = 1 << 32;
        const VIRTIO_BLK_F_RO: u64 = 1 << 5;
        // QEMU requires this to be acknowledged for devices configured with
        // iommu_platform=on (always the case for virtio under TDX, so that
        // the device knows DMA buffers must go through shared/bounce-buffer
        // memory, see init_shared_memory()) -- without it, the device
        // refuses to set VIRTIO_STATUS_FEATURES_OK below.
        const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;

        const VIRTIO_STATUS_RESET: u32 = 0;
        const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
        const VIRTIO_STATUS_DRIVER: u32 = 2;
        const VIRTIO_STATUS_FEATURES_OK: u32 = 8;
        const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
        const VIRTIO_STATUS_FAILED: u32 = 128;

        // DIAGNOSTIC: temporarily disabled to test whether the MapGPA call
        // itself is corrupting QEMU's virtqueue region cache even when the
        // shared alias isn't subsequently used for device-facing addresses.
        #[cfg(feature = "td-shim")]
        init_shared_memory();

        // Initialise the transport
        trace!("VirtioBlockDevice::init: calling transport.init");
        self.transport.init(VIRTIO_SUBSYSTEM_BLOCK)?;
        trace!("VirtioBlockDevice::init: transport.init done");

        // Reset device
        self.transport.set_status(VIRTIO_STATUS_RESET);

        // Acknowledge
        self.transport.add_status(VIRTIO_STATUS_ACKNOWLEDGE);

        // And advertise driver
        self.transport.add_status(VIRTIO_STATUS_DRIVER);

        // Request device features
        trace!("VirtioBlockDevice::init: calling get_features");
        let device_features = self.transport.get_features();
        trace!("VirtioBlockDevice::init: device_features=0x{:x}", device_features);

        if device_features & VIRTIO_F_VERSION_1 != VIRTIO_F_VERSION_1 {
            self.transport.add_status(VIRTIO_STATUS_FAILED);
            return Err(VirtioError::LegacyOnly);
        }

        // Detect if device is read-only
        self.read_only = (device_features & VIRTIO_BLK_F_RO) == VIRTIO_BLK_F_RO;

        // Don't support any advanced features for now
        let supported_features = VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_RO | VIRTIO_F_ACCESS_PLATFORM;

        // Report driver features
        self.transport
            .set_features(device_features & supported_features);

        self.transport.add_status(VIRTIO_STATUS_FEATURES_OK);
        if self.transport.get_status() & VIRTIO_STATUS_FEATURES_OK != VIRTIO_STATUS_FEATURES_OK {
            self.transport.add_status(VIRTIO_STATUS_FAILED);
            return Err(VirtioError::FeatureNegotiationFailed);
        }

        // Program queues
        self.transport.set_queue(0);

        trace!("VirtioBlockDevice::init: calling get_queue_max_size");
        let max_queue = self.transport.get_queue_max_size();
        trace!("VirtioBlockDevice::init: max_queue={}", max_queue);

        // Hardcoded queue size to QUEUE_SIZE at the moment
        if max_queue < QUEUE_SIZE as u16 {
            self.transport.add_status(VIRTIO_STATUS_FAILED);
            return Err(VirtioError::QueueTooSmall);
        }
        self.transport.set_queue_size(QUEUE_SIZE as u16);

        // Update all queue parts
        let state = self.state.borrow_mut();
        let addr = state.descriptors.as_ptr() as u64;
        trace!("VirtioBlockDevice::init: set_descriptors_address addr=0x{:x}", addr);
        self.transport.set_descriptors_address(addr);

        let addr = (&state.avail as *const _) as u64;
        trace!("VirtioBlockDevice::init: set_avail_ring addr=0x{:x}", addr);
        self.transport.set_avail_ring(addr);

        let addr = (&state.used as *const _) as u64;
        trace!("VirtioBlockDevice::init: set_used_ring addr=0x{:x}", addr);
        self.transport.set_used_ring(addr);

        // Confirm queue
        trace!("VirtioBlockDevice::init: set_queue_enable");
        self.transport.set_queue_enable();

        // Report driver ready
        trace!("VirtioBlockDevice::init: add_status DRIVER_OK");
        self.transport.add_status(VIRTIO_STATUS_DRIVER_OK);

        Ok(())
    }

    // Number of sectors that this device holds
    pub fn get_capacity(&self) -> u64 {
        u64::from(self.transport.read_device_config(0))
            | u64::from(self.transport.read_device_config(4)) << 32
    }

    fn request(
        &self,
        sector: u64,
        data: Option<&mut [u8]>,
        request: RequestType,
    ) -> Result<(), Error> {
        const VIRTQ_DESC_F_NEXT: u16 = 1;
        const VIRTQ_DESC_F_WRITE: u16 = 2;

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        if request != RequestType::Flush {
            match &data {
                None => return Err(Error::NoDataBuf),
                Some(d) if d.len() != SectorBuf::len() => {
                    return Err(Error::InvalidDataBufSize);
                }
                Some(_) => {}
            }
        }

        // The virtio-blk backend runs in the host and, under TDX, can only
        // access shared (not private/encrypted) guest memory; stage the
        // header/footer/data through SHARED_BLOCK_IO instead of using the
        // caller's own buffers directly.
        #[cfg(not(feature = "td-shim"))]
        let header = BlockRequestHeader {
            request: request as u32,
            reserved: 0,
            sector,
        };
        #[cfg(not(feature = "td-shim"))]
        let footer = BlockRequestFooter { status: 0 };
        #[cfg(not(feature = "td-shim"))]
        let header_addr = (&header as *const BlockRequestHeader) as u64;
        #[cfg(not(feature = "td-shim"))]
        let footer_addr = (&footer as *const BlockRequestFooter) as u64;
        #[cfg(not(feature = "td-shim"))]
        let data_addr = data.as_ref().map_or(0, |d| d.as_ptr() as u64);

        #[cfg(feature = "td-shim")]
        let header = shared_header();
        #[cfg(feature = "td-shim")]
        let footer = shared_footer();
        #[cfg(feature = "td-shim")]
        {
            header.request = request as u32;
            header.reserved = 0;
            header.sector = sector;
            footer.status = 0;
            if request == RequestType::Write {
                shared_bounce()
                    .as_mut_bytes()
                    .copy_from_slice(data.as_deref().expect("data checked above"));
            }
        }
        #[cfg(feature = "td-shim")]
        let header_addr = (header as *const BlockRequestHeader) as u64;
        #[cfg(feature = "td-shim")]
        let footer_addr = (footer as *const BlockRequestFooter) as u64;
        #[cfg(feature = "td-shim")]
        let data_addr = shared_bounce().as_mut_bytes().as_ptr() as u64;

        let mut state = self.state.borrow_mut();

        let next_head = state.next_head;
        let d = &mut state.descriptors[next_head];
        let next_desc = (next_head + 1) % QUEUE_SIZE;
        d.addr = header_addr;
        d.length = core::mem::size_of::<BlockRequestHeader>() as u32;
        d.flags = VIRTQ_DESC_F_NEXT;
        d.next = next_desc as u16;

        let d = &mut state.descriptors[next_desc];
        let next_desc = (next_desc + 1) % QUEUE_SIZE;
        if request != RequestType::Flush {
            d.addr = data_addr;
            d.length = SectorBuf::len() as u32;
        }

        d.flags = VIRTQ_DESC_F_NEXT
            | if request == RequestType::Read {
                VIRTQ_DESC_F_WRITE
            } else {
                0
            };
        d.next = next_desc as u16;

        let d = &mut state.descriptors[next_desc];
        d.addr = footer_addr;
        d.length = core::mem::size_of::<BlockRequestFooter>() as u32;
        d.flags = VIRTQ_DESC_F_WRITE;
        d.next = 0;

        // Update ring to point to head of chain. Fence. Then update idx
        let avail_index = state.avail.idx;
        state.avail.ring[(avail_index % QUEUE_SIZE as u16) as usize] = state.next_head as u16;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        state.avail.idx = state.avail.idx.wrapping_add(1);

        // Next free descriptor to use
        state.next_head = (next_desc + 1) % QUEUE_SIZE;

        // Notify queue has been updated
        self.transport.notify_queue(0);

        trace!(
            "VirtioBlockDevice::request: notified, header_addr=0x{:x} footer_addr=0x{:x} data_addr=0x{:x} avail.idx={}",
            header_addr, footer_addr, data_addr, state.avail.idx
        );

        // Check for the completion of the request
        let mut spins: u64 = 0;
        while unsafe { core::ptr::read_volatile(&state.used.idx) } != state.avail.idx {
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            spins += 1;
            if spins % 5_000_000 == 0 {
                trace!(
                    "VirtioBlockDevice::request: still waiting, used.idx={} avail.idx={} spins={}",
                    unsafe { core::ptr::read_volatile(&state.used.idx) },
                    state.avail.idx,
                    spins
                );
            }
        }
        trace!("VirtioBlockDevice::request: completed after {} spins", spins);

        let status = footer.status;

        #[cfg(feature = "td-shim")]
        if request == RequestType::Read && status == VIRTIO_BLK_S_OK {
            data.expect("data checked above")
                .copy_from_slice(shared_bounce().as_bytes());
        }

        match status {
            VIRTIO_BLK_S_OK => Ok(()),
            VIRTIO_BLK_S_IOERR => Err(Error::BlockIO),
            VIRTIO_BLK_S_UNSUPP => Err(Error::BlockNotSupported),
            _ => Err(Error::BlockNotSupported),
        }
    }
}

impl<'a> SectorRead for VirtioBlockDevice<'a> {
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), Error> {
        self.request(sector, Some(data), RequestType::Read)
    }
}

impl<'a> SectorWrite for VirtioBlockDevice<'a> {
    fn write(&self, sector: u64, data: &mut [u8]) -> Result<(), Error> {
        if self.read_only {
            return Err(Error::BlockNotSupported);
        }
        self.request(sector, Some(data), RequestType::Write)
    }

    fn flush(&self) -> Result<(), Error> {
        if self.read_only {
            return Err(Error::BlockNotSupported);
        }
        self.request(0, None, RequestType::Flush)
    }
}

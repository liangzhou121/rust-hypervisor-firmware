// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 Intel Corporation

//! Minimal x2APIC periodic timer, used only under td-shim.
//!
//! GRUB and the Linux kernel both fall back to busy-polling the legacy PIT
//! (port 0x42/0x43) for calibration/delay purposes in several places. Cloud
//! Hypervisor's PIT model doesn't answer channel-0 counter readback on this
//! platform, and that fallback polling is normally bounded by a background
//! timer tick (e.g. jiffies) rather than the PIT read succeeding. Without
//! any timer interrupt at all, that bound never advances and the poll loops
//! forever. Real firmware (e.g. OVMF's LocalApicTimerDxe) always has a
//! periodic LAPIC timer running from early boot for exactly this reason, so
//! mirror that here: just get *a* periodic interrupt ticking before handing
//! control to the loaded image, we don't need a full timer/event driver.
//!
//! x2APIC MSR reads/writes already transparently route through td_exception's
//! existing #VE MSR_READ/MSR_WRITE -> TDVMCALL forwarding, so this needs no
//! special TDX handling of its own.

use core::arch::asm;

const X2APIC_SIVR: u32 = 0x80f;
const X2APIC_LVT_TIMER: u32 = 0x832;
const X2APIC_TIMER_DIVIDE: u32 = 0x83e;
const X2APIC_TIMER_INITIAL_COUNT: u32 = 0x838;

const APIC_SOFTWARE_ENABLE: u64 = 1 << 8;
const SPURIOUS_VECTOR: u64 = 0xff;

const TIMER_VECTOR: u8 = 0x30;
const TIMER_PERIODIC: u64 = 1 << 17;
const TIMER_DIVIDE_BY_16: u64 = 0x3;
// Arbitrary tick rate; this only needs to be "fast enough" to keep a
// background tick counter moving for other code's timeout logic, not
// precisely calibrated.
const TIMER_INITIAL_COUNT: u64 = 0x10000;

unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi);
}

fn timer_tick(_stack: &mut td_exception::interrupt::InterruptStack) {
    // EOI is already sent by the generic dispatcher for vectors > 31;
    // nothing else needs to happen here.
}

/// Enable x2APIC mode and start a periodic timer on `TIMER_VECTOR`, then
/// unmask interrupts. Must be called after `setup_exception_handlers()`.
pub fn setup_periodic_timer() {
    unsafe {
        // TDX guests always run with x2APIC already enabled by the TDX
        // module; attempting to rewrite IA32_APIC_BASE ourselves is both
        // unnecessary and gets rejected by the host (VmcallOperandInvalid),
        // so only touch the guest-local APIC configuration registers.
        wrmsr(X2APIC_SIVR, APIC_SOFTWARE_ENABLE | SPURIOUS_VECTOR);
        wrmsr(X2APIC_TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
        wrmsr(X2APIC_LVT_TIMER, TIMER_PERIODIC | u64::from(TIMER_VECTOR));
        wrmsr(X2APIC_TIMER_INITIAL_COUNT, TIMER_INITIAL_COUNT);
    }

    let _ = td_exception::interrupt::register_interrupt_callback(
        TIMER_VECTOR as usize,
        td_exception::interrupt::InterruptCallback::new(timer_tick),
    );

    unsafe { asm!("sti") };
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

// Only needed for the 16/32-bit PVH/coreboot trampoline; td-shim jumps
// straight into 64-bit `_start` (see src/tdshim.rs).
#[cfg(feature = "td-shim")]
pub mod apic;
#[cfg(all(not(test), not(feature = "td-shim")))]
pub mod asm;
pub mod gdt;
pub mod layout;
pub mod paging;
pub mod sse;
pub mod vmx;

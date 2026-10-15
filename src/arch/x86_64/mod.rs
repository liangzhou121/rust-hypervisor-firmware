// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

#[cfg(all(not(test), not(feature = "td-shim")))]
pub mod asm;
pub mod gdt;
pub mod layout;
pub mod paging;
pub mod sse;
pub mod vmx;

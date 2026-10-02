// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Key derivation, hierarchy, lifecycle and destruction for a device that may be taken from its
//! owner.
//!
//! Pure logic: no filesystem, no network, no clock, no platform API.
//!
//! What is guaranteed, what is not, and which properties are proven:
//! <https://github.com/wisper-dev/lethewis>.

#![deny(missing_docs, unused_crate_dependencies)]
#![no_std]

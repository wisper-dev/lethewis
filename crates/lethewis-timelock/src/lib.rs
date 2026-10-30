// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! A time lock on the drand network quicknet, which signs one round every three seconds. This
//! version checks the signature of a round and converts between rounds and times. No network and no
//! clock: the caller brings the signature and the time.

#![deny(missing_docs, unused_crate_dependencies)]
#![no_std]
// Line coverage is judged on proof code only, so Kani counts it nowhere else.
#![cfg_attr(kani, feature(coverage_attribute), coverage(off))]

// Under Kani the hash is a model, so it goes unused there.
#[cfg(kani)]
use sha2 as _;

mod curve;
mod error;
mod network;

pub use error::Error;
pub use network::{Network, QUICKNET, SIGNATURE_LEN};

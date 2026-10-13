// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! A proof with every outcome Kani reports.

#[cfg(kani)]
mod proofs {
    /// A cover reached and one never reached, an assertion that holds and one that fails, an
    /// overflow, an assertion and a region that nothing reaches, and a check that CBMC places in
    /// a file other than its function's.
    #[kani::proof]
    fn every_outcome() {
        let value: u8 = kani::any();
        kani::cover!(value == 7, "reached");
        kani::cover!(value == 7 && value == 8, "never reached");
        kani::assert(value <= u8::MAX, "holds");
        kani::assert(value != 9, "fails");
        let _ = value + 100;
        let _ = value.is_multiple_of(kani::any());
        if value > 200 && value < 100 {
            kani::assert(false, "never run");
        }
    }
}

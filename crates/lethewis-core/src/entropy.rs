// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// A source of cryptographically secure random bytes, provided by the platform.
///
/// The bytes go into keys, words and nonces hedged with the key of the epoch, as RFC 8937 has it,
/// so that within one `Slots` a broken source alone does not make them predictable, and into the
/// salt of password parameters as they are. An implementation writes them straight into `dest` and
/// keeps no copy of what it wrote, including in a buffer of its own.
///
/// A call asks the source before any step on a secret but hedging nonces and salts drawn before,
/// which wipes its stack, so a panic of `fill` leaves none of the call's secrets behind.
pub trait Entropy {
    /// Fills `dest` entirely with random bytes.
    ///
    /// # Errors
    ///
    /// [`EntropyError`] if the source cannot supply them. `dest` may then hold anything.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError>;
}

/// The source of random bytes failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyError;

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("random source failed")
    }
}

impl core::error::Error for EntropyError {}

/// What the proofs know of the order of a call: the steps it has taken on a secret.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicU8, Ordering};

    /// The derivations, but for the hedges of nonces and salts, the calls of X-Wing other than its
    /// self-test, and the encryptions and decryptions run so far.
    static STEPS: AtomicU8 = AtomicU8::new(0);

    pub(crate) fn step() {
        STEPS.store(
            STEPS.load(Ordering::Relaxed).saturating_add(1),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn steps() -> u8 {
        STEPS.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::EntropyError;

    #[test]
    fn display_names_the_failure() {
        assert_eq!(EntropyError.to_string(), "random source failed");
    }
}

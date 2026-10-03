// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// A source of cryptographically secure random bytes, provided by the platform.
///
/// The bytes become key material. An implementation writes them straight into `dest` and keeps no
/// copy of what it wrote, including in a buffer of its own.
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

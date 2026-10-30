// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// Why a round's signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Round 0, which no network signs: rounds start at 1.
    InvalidRound,
    /// The signature is not a point of G1 in canonical compressed form, is the identity, or is not
    /// the network's signature of the round.
    SignatureRejected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRound => "round 0 is never signed",
            Self::SignatureRejected => "signature rejected",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::Error;

    #[test]
    fn display_names_the_failure() {
        assert_eq!(Error::InvalidRound.to_string(), "round 0 is never signed");
        assert_eq!(Error::SignatureRejected.to_string(), "signature rejected");
    }
}

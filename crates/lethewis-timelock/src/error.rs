// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// Why a lock was not made or opened, or a round's signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Round 0, which no network signs: rounds start at 1.
    InvalidRound,
    /// The signature is not a point of G1 in canonical compressed form, is the identity, or is not
    /// the network's signature of the round.
    SignatureRejected,
    /// The time a key is locked until is not after now, is more than 365 days after now, or now
    /// is before the network's first round.
    InvalidTime,
    /// The random bytes give no scalar within the tries taken in constant time, which happens with
    /// probability below 2^-54. Other random bytes lock the key.
    RandomUnusable,
    /// The bytes are not a lock as this library writes it.
    LockMalformed,
    /// The lock is for another network.
    OtherNetwork,
    /// The lock does not open with the signature of its round: it was changed after it was made.
    LockRejected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRound => "round 0 is never signed",
            Self::SignatureRejected => "signature rejected",
            Self::InvalidTime => "time out of range",
            Self::RandomUnusable => "random bytes unusable",
            Self::LockMalformed => "lock malformed",
            Self::OtherNetwork => "lock for another network",
            Self::LockRejected => "lock rejected",
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
        for (error, text) in [
            (Error::InvalidRound, "round 0 is never signed"),
            (Error::SignatureRejected, "signature rejected"),
            (Error::InvalidTime, "time out of range"),
            (Error::RandomUnusable, "random bytes unusable"),
            (Error::LockMalformed, "lock malformed"),
            (Error::OtherNetwork, "lock for another network"),
            (Error::LockRejected, "lock rejected"),
        ] {
            assert_eq!(error.to_string(), text);
        }
    }
}

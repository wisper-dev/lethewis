// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

/// The Android keystore as this library uses it: HMAC-SHA256 keys under names.
pub trait Keystore {
    /// The API level of the system.
    fn api_level(&self) -> u32;

    /// Whether a key is held under `alias`. The system reports a keystore that fails here as
    /// holding no key.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`].
    fn contains(&mut self, alias: &str) -> Result<bool, Failure>;

    /// Creates an HMAC-SHA256 key under `alias`, in the secure element if `strong_box`, and usable
    /// only while the device is unlocked if `unlocked`. Returns where it is held.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`]. A key made before the failure may be left under `alias`.
    fn generate(&mut self, alias: &str, strong_box: bool, unlocked: bool)
    -> Result<Level, Failure>;

    /// Writes into `out` the HMAC-SHA256 of `data` under the key `alias`.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`], and then leaves `out` as it was.
    fn mac(&mut self, alias: &str, data: &[u8], out: &mut [u8; 32]) -> Result<(), Failure>;

    /// Deletes the key `alias`; a key that is not there is not a failure.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`].
    fn delete(&mut self, alias: &str) -> Result<(), Failure>;
}

/// Where the keystore holds a key, as the system reports it at creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// A secure element of its own.
    StrongBox,
    /// The isolated part of the processor.
    TrustedEnvironment,
    /// Secure hardware the system does not name.
    UnknownSecure,
    /// Software of the operating system.
    Software,
    /// The system does not say.
    Unknown,
}

impl Level {
    /// Whether the key is held in hardware the operating system cannot read.
    #[must_use]
    pub const fn secure(self) -> bool {
        matches!(
            self,
            Self::StrongBox | Self::TrustedEnvironment | Self::UnknownSecure
        )
    }
}

/// Why the keystore refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Worth asking again later: the chip was busy, or the reason is not known. The system tells
    /// few lasting failures apart, so a damaged key may come as this too.
    Transient,
    /// The device has to be unlocked first.
    Locked,
    /// No key under the name, or the system made it unusable. Below API 31 a keystore service that
    /// is not running reads as this too.
    Absent,
    /// The stored form of the key is damaged.
    Corrupted,
    /// The secure element cannot hold the key.
    StrongBoxUnavailable,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transient => "the keystore failed for now",
            Self::Locked => "the device is locked",
            Self::Absent => "the key is not there",
            Self::Corrupted => "the key is damaged",
            Self::StrongBoxUnavailable => "the secure element cannot hold the key",
        })
    }
}

impl std::error::Error for Failure {}

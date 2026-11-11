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

    /// Creates an HMAC-SHA256 key under `alias` that enrolling a fingerprint, or dropping the
    /// secure lock screen, makes unusable for good; in the secure element if `strong_box`. Using it
    /// would need the owner to authenticate, so this library only asks after it.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`]: [`Failure::Refused`] where the system refuses such a key on this
    /// device, which [`Keystore::watchable`] explains. A key made before a failure may be left
    /// under `alias`.
    fn generate_watched(&mut self, alias: &str, strong_box: bool) -> Result<Level, Failure>;

    /// What the device says of a key [`Keystore::generate_watched`] would make. Only the making
    /// decides: this explains a refusal.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`]: [`Failure::Unknown`] also where the app gave no context through
    /// `Wiper.start`, or lacks the permission to ask the sensor.
    fn watchable(&mut self) -> Result<Watchable, Failure>;

    /// What the keystore says of the key `alias`, without asking the owner to authenticate.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`].
    fn watched(&mut self, alias: &str) -> Result<Watched, Failure>;

    /// Writes into `out` the HMAC-SHA256 of `data` under the key `alias`.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`], and then leaves `out` as it was.
    fn mac(&mut self, alias: &str, data: &[u8], out: &mut [u8; 32]) -> Result<(), Failure>;

    /// The names of the keys held that begin with `prefix`. The system reports a keystore that
    /// fails here as holding none, or fewer.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`].
    fn aliases(&mut self, prefix: &str) -> Result<Vec<String>, Failure>;

    /// Deletes the key `alias`; a key that is not there is not a failure.
    ///
    /// # Errors
    ///
    /// The keystore's [`Failure`].
    fn delete(&mut self, alias: &str) -> Result<(), Failure>;
}

/// What the keystore says of a key whose loss tells of a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watched {
    /// It is there, and usable once the owner authenticates.
    Kept,
    /// It is gone, or the system made it unusable for good.
    Gone,
}

/// What the device says of a key that a new biometric, or dropping the secure lock screen, makes
/// unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watchable {
    /// Such a key can be made.
    Ready,
    /// There is no secure lock screen, which enrolling a biometric needs first.
    NoLockScreen,
    /// No biometric strong enough is enrolled; enrolling one makes the device ready.
    NothingEnrolled,
    /// The sensor cannot be used now; any other answer of the device reads so as well.
    NotNow,
    /// The device has no sensor strong enough.
    Never,
}

impl fmt::Display for Watchable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ready => "such a key can be made",
            Self::NoLockScreen => "there is no secure lock screen",
            Self::NothingEnrolled => "no biometric strong enough is enrolled",
            Self::NotNow => "the sensor cannot be used now",
            Self::Never => "the device has no sensor strong enough",
        })
    }
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

/// Why the keystore refused. Only the system's own word that a key is gone reads as
/// [`Failure::Absent`]; below API 31, where that word is unclear, only once the keystore shows it
/// works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// From API 33, a failure the system marks as passing, or the keystore's internal error, a
    /// service that died among them.
    Transient,
    /// The device has to be unlocked first.
    Locked,
    /// No key under the name, or the system made it unusable. From API 31 also a key whose stored
    /// details lost their algorithm, which the system reports alike.
    Absent,
    /// The stored form of the key is damaged.
    Corrupted,
    /// The secure element cannot hold the key.
    StrongBoxUnavailable,
    /// The system refuses a key that a new biometric makes unusable on this device as it is.
    Refused,
    /// The keystore, or the bridge to it, failed without saying whether it lasts. Below API 33 most
    /// failures come as this, a damaged key among them; below API 31 so does a missing key while
    /// the keystore cannot make one.
    Unknown,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transient => "the keystore failed for now",
            Self::Locked => "the device is locked",
            Self::Absent => "the key is not there",
            Self::Corrupted => "the key is damaged",
            Self::StrongBoxUnavailable => "the secure element cannot hold the key",
            Self::Refused => "the system refuses such a key on this device",
            Self::Unknown => "the keystore failed for a reason it does not give",
        })
    }
}

impl std::error::Error for Failure {}

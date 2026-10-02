// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::fmt;

use zeroize::Zeroize;

/// Length of a key, in bytes.
pub const KEY_LEN: usize = 32;

/// Key material in a fixed buffer. It cannot be copied, cloned, compared or printed, and it is
/// wiped when dropped. It lives in a slot and is never moved out of it.
pub(crate) struct Key {
    bytes: [u8; KEY_LEN],
}

impl Key {
    pub(crate) const fn empty() -> Self {
        Self {
            bytes: [0; KEY_LEN],
        }
    }

    /// Takes the bytes of `source` and wipes `source`.
    pub(crate) fn load(&mut self, source: &mut [u8; KEY_LEN]) {
        self.bytes.copy_from_slice(source.as_slice());
        source.zeroize();
    }

    pub(crate) fn wipe(&mut self) {
        self.bytes.zeroize();
    }

    #[cfg(test)]
    pub(crate) const fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::{fmt, hash::Hash};
    use std::format;

    use super::{KEY_LEN, Key};

    assert_not_impl!(Key: Clone, PartialEq, Hash, Default, fmt::Display);

    fn loaded() -> Key {
        let mut key = Key::empty();
        key.load(&mut [7; KEY_LEN]);
        key
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(Key::empty().bytes(), &[0; KEY_LEN]);
    }

    #[test]
    fn load_takes_the_bytes_and_wipes_the_source() {
        let mut key = Key::empty();
        let mut source = [7; KEY_LEN];
        key.load(&mut source);
        assert_eq!(key.bytes(), &[7; KEY_LEN]);
        assert_eq!(source, [0; KEY_LEN]);
    }

    #[test]
    fn wipe_zeroes_the_key() {
        let mut key = loaded();
        key.wipe();
        assert_eq!(key.bytes(), &[0; KEY_LEN]);
    }

    #[test]
    fn debug_shows_no_bytes() {
        assert_eq!(format!("{:?}", loaded()), "Key(..)");
    }
}

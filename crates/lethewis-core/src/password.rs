// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(kani))]
use argon2::{Algorithm, Argon2, Params, Version};

use crate::entropy::{Entropy, EntropyError};
use crate::error::Error;
use crate::key::KeyLength;
use crate::record::Purpose;
use crate::slots::{Handle, Slots};

/// The size of [`PasswordParams`] as bytes: the version, the memory, the passes and the salt.
pub const PASSWORD_PARAMS_LEN: usize = 25;
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// The least memory and passes are the second option RFC 9106 recommends, the most memory its
/// first.
const MIN_MEMORY: u32 = 1 << 16;
const MAX_MEMORY: u32 = 1 << 21;
const MIN_PASSES: u32 = 3;
/// The most memory times passes, in KiB.
const MAX_WORK: u64 = 1 << 23;
/// How many bytes of stack a derivation from a password is followed by a wipe of: at least twice
/// what it uses, as a test measures in each build. Without optimisation it uses far more.
#[cfg(all(not(kani), not(lethewis_unoptimised)))]
const STACK_WIPE: usize = 32_768;
#[cfg(all(not(kani), lethewis_unoptimised))]
const STACK_WIPE: usize = 196_608;

const _: () = assert!(1 + 4 + 4 + SALT_LEN == PASSWORD_PARAMS_LEN);

/// A block of the working memory of a derivation from a password, 1 KiB.
#[cfg(not(kani))]
pub use argon2::Block as MemoryBlock;

/// A block of the working memory of a derivation from a password. Under Kani the derivation is a
/// model that never reads its memory, so a block holds nothing.
#[cfg(kani)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryBlock;

/// How a key is derived from a password: Argon2id, version 0x13, in one lane, over `memory` KiB
/// for `passes` passes, with a salt of 16 bytes. Memory runs from 64 MiB to 2 GiB, passes from 3,
/// and memory times passes up to 8 GiB; no parameters out of these bounds are made or read. A
/// 32-bit target cannot hold 2 GiB of working memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordParams {
    memory: u32,
    passes: u32,
    salt: [u8; SALT_LEN],
}

impl PasswordParams {
    /// Parameters of `memory` KiB and `passes` passes, with a new salt from `entropy`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParams`] if `memory` or `passes` is out of bounds, and `entropy` is then not
    /// asked, and [`Error::EntropyFailed`] if `entropy` fails.
    pub fn new(
        memory: u32,
        passes: u32,
        entropy: &mut (impl Entropy + ?Sized),
    ) -> Result<Self, Error> {
        if !within(memory, passes) {
            return Err(Error::InvalidParams);
        }
        let mut salt = [0; SALT_LEN];
        entropy
            .fill(&mut salt)
            .map_err(|EntropyError| Error::EntropyFailed)?;
        Ok(Self {
            memory,
            passes,
            salt,
        })
    }

    /// Reads the parameters [`Self::to_bytes`] wrote.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParams`] if `bytes` are not parameters this version of the library writes.
    pub fn from_bytes(bytes: &[u8; PASSWORD_PARAMS_LEN]) -> Result<Self, Error> {
        let (&version, rest) = bytes.split_first().ok_or(Error::InvalidParams)?;
        let (memory, rest) = rest.split_first_chunk::<4>().ok_or(Error::InvalidParams)?;
        let (passes, salt) = rest.split_first_chunk::<4>().ok_or(Error::InvalidParams)?;
        let salt = salt.first_chunk::<SALT_LEN>().ok_or(Error::InvalidParams)?;
        let (memory, passes) = (u32::from_le_bytes(*memory), u32::from_le_bytes(*passes));
        if version != VERSION || !within(memory, passes) {
            return Err(Error::InvalidParams);
        }
        Ok(Self {
            memory,
            passes,
            salt: *salt,
        })
    }

    /// The parameters as bytes, to keep beside the records the key wraps.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PASSWORD_PARAMS_LEN] {
        let mut bytes = [0; PASSWORD_PARAMS_LEN];
        if let Some((version, rest)) = bytes.split_first_mut()
            && let Some((memory, rest)) = rest.split_first_chunk_mut::<4>()
            && let Some((passes, salt)) = rest.split_first_chunk_mut::<4>()
        {
            *version = VERSION;
            *memory = self.memory.to_le_bytes();
            *passes = self.passes.to_le_bytes();
            salt.copy_from_slice(&self.salt);
        }
        bytes
    }

    /// How many blocks of working memory a derivation with these parameters takes: one per KiB.
    #[must_use]
    pub fn memory_blocks(&self) -> usize {
        usize::try_from(self.memory).unwrap_or(usize::MAX)
    }
}

/// Whether a password of `length` bytes is taken: not empty, and at most 2^32 - 1 bytes, the most
/// Argon2id takes.
fn password_fits(length: usize) -> bool {
    length != 0 && u32::try_from(length).is_ok()
}

fn within(memory: u32, passes: u32) -> bool {
    (MIN_MEMORY..=MAX_MEMORY).contains(&memory)
        && passes >= MIN_PASSES
        && u64::from(memory)
            .checked_mul(u64::from(passes))
            .is_some_and(|work| work <= MAX_WORK)
}

impl<'a> Slots<'a> {
    /// Derives a 32-byte key for `purpose` from `password` with `params` into a free slot, as a set
    /// of one whose key is the primary, and wipes `password`. The key is written straight into the
    /// slot. `memory` is the working memory, of at least [`PasswordParams::memory_blocks`] blocks;
    /// the blocks the derivation used are wiped after it, whether it succeeded or not.
    ///
    /// `password` is taken as the bytes it is. Text is to be normalised to NFC first, as RFC 8265
    /// has it for passwords: otherwise the same password typed another way derives another key.
    ///
    /// Needs 33 KiB of stack, or 196 KiB when this crate is built without optimisation or with
    /// `--cfg lethewis_unoptimised`: the derivation is followed by a wipe of 32 KiB, or 192 KiB,
    /// below it. A build that optimises this crate but not the hash code it calls has to set that
    /// flag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPassword`] if `password` is empty or longer than 2^32 - 1 bytes,
    /// [`Error::NotEnoughMemory`] if `memory` holds fewer blocks than `params` take,
    /// [`Error::NoFreeSlot`] if no slot is free, [`Error::DerivationFailed`] if the key or its
    /// identifier cannot be derived, and [`Error::DuplicateKey`] if these slots hold the key
    /// already. `password` is then left as it was, and no slot changes.
    ///
    /// # Panics
    ///
    /// Only if Argon2id panics. The panic passes through after the slot and the blocks of working
    /// memory used are wiped; the stack and `password` are not.
    pub fn derive_from_password(
        &mut self,
        purpose: Purpose,
        password: &mut [u8],
        params: &PasswordParams,
        memory: &mut [MemoryBlock],
    ) -> Result<Handle<'a>, Error> {
        if !password_fits(password.len()) {
            return Err(Error::InvalidPassword);
        }
        let memory = memory
            .get_mut(..params.memory_blocks())
            .ok_or(Error::NotEnoughMemory)?;
        let derived = self.generate(
            purpose,
            KeyLength::Bytes32,
            &mut Stretch {
                password,
                params,
                memory,
            },
        );
        wipe_stack();
        let handle = derived.map_err(|error| match error {
            Error::EntropyFailed => Error::DerivationFailed,
            other => other,
        })?;
        wipe_password(password);
        Ok(handle)
    }
}

/// Argon2id as the source of a key's bytes: a key from a password is loaded as a generated one is.
struct Stretch<'p, 'm> {
    password: &'p [u8],
    params: &'p PasswordParams,
    memory: &'m mut [MemoryBlock],
}

impl Entropy for Stretch<'_, '_> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        let used = WipeOnDrop(&mut *self.memory);
        stretch(
            self.password,
            &self.params.salt,
            self.params.memory,
            self.params.passes,
            &mut *used.0,
            dest,
        )
    }
}

/// Wipes the working memory when dropped, so that the wipe also runs when Argon2id panics.
struct WipeOnDrop<'m>(&'m mut [MemoryBlock]);

impl Drop for WipeOnDrop<'_> {
    fn drop(&mut self) {
        wipe_memory(self.0);
    }
}

/// Fills `out` with Argon2id, version 0x13, in one lane, from `password` and `salt` over
/// `memory_kib` KiB of `memory` for `passes` passes.
#[cfg(not(kani))]
fn stretch(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    passes: u32,
    memory: &mut [MemoryBlock],
    out: &mut [u8],
) -> Result<(), EntropyError> {
    let params = Params::new(memory_kib, passes, 1, Some(KEY_LEN)).map_err(|_| EntropyError)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, out, memory)
        .map_err(|_| EntropyError)
}

fn wipe_memory(memory: &mut [MemoryBlock]) {
    #[cfg(not(kani))]
    zeroize::Zeroize::zeroize(&mut memory.iter_mut());
    #[cfg(kani)]
    let _ = memory;
}

fn wipe_password(password: &mut [u8]) {
    #[cfg(not(kani))]
    zeroize::Zeroize::zeroize(password);
    #[cfg(kani)]
    password.fill(0);
}

/// Wipes the stack below the caller's frame, as deep as a derivation from a password reaches.
fn wipe_stack() {
    #[cfg(not(kani))]
    zeroize::zeroize_stack::<STACK_WIPE>();
}

#[cfg(kani)]
use model::stretch;

/// What stands in for Argon2id under Kani: any key, then success or failure, as a real derivation
/// may fail after writing part of its output. It records whether it failed.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::{EntropyError, KEY_LEN, MemoryBlock};

    static FAILED: AtomicBool = AtomicBool::new(false);

    pub(crate) fn stretch(
        _password: &[u8],
        _salt: &[u8],
        _memory_kib: u32,
        _passes: u32,
        _memory: &mut [MemoryBlock],
        out: &mut [u8],
    ) -> Result<(), EntropyError> {
        let out = out.first_chunk_mut::<KEY_LEN>().ok_or(EntropyError)?;
        *out = kani::any();
        let fail = kani::any();
        FAILED.store(fail, Ordering::Relaxed);
        if fail {
            return Err(EntropyError);
        }
        Ok(())
    }

    /// Whether the derivation failed.
    pub(crate) fn argon2_failed() -> bool {
        FAILED.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::{MemoryBlock, PASSWORD_PARAMS_LEN, PasswordParams, SALT_LEN, STACK_WIPE, stretch};
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::key::tests::{Counting, Failing, Recording};
    use crate::record::Purpose;
    use crate::slots::{Slot, Slots};

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn encoded(version: u8, memory: u32, passes: u32, salt: &[u8; SALT_LEN]) -> [u8; 25] {
        let mut bytes = [0; PASSWORD_PARAMS_LEN];
        bytes[0] = version;
        bytes[1..5].copy_from_slice(&memory.to_le_bytes());
        bytes[5..9].copy_from_slice(&passes.to_le_bytes());
        bytes[9..].copy_from_slice(salt);
        bytes
    }

    fn blocks(count: usize) -> Vec<MemoryBlock> {
        std::vec![MemoryBlock::new(); count]
    }

    /// The stack, in KiB, that a derivation from a password needs, and the depth of the wipe that
    /// follows it, in an optimised build and in one without optimisation.
    pub(super) const NEEDS: [usize; 2] = [33, 196];
    const WIPES: [usize; 2] = [32, 192];

    /// The documentation of the derivation states the stack it needs and the depth of the wipe
    /// after it, and that depth is the library's.
    #[test]
    fn the_documentation_states_the_stack_a_derivation_needs() {
        let build = usize::from(cfg!(lethewis_unoptimised));
        assert_eq!(WIPES[build] * 1024, STACK_WIPE);
        let source = include_str!("password.rs");
        let at = source.find("    pub fn derive_from_password(").unwrap();
        let mut lines: Vec<&str> = source[..at]
            .lines()
            .rev()
            .take_while(|line| line.trim_start().starts_with("///"))
            .map(|line| line.trim().trim_start_matches("///").trim())
            .collect();
        lines.reverse();
        let text = lines.join(" ");
        for stated in [
            std::format!("Needs {} KiB of stack, or {} KiB when", NEEDS[0], NEEDS[1]),
            std::format!(" {} KiB, or {} KiB, ", WIPES[0], WIPES[1]),
        ] {
            assert!(text.contains(&stated), "{stated}");
        }
    }

    /// Argon2id, version 0x13, in one lane, as the reference implementation's own tests have it.
    #[test]
    fn the_derivation_matches_the_reference_implementation() {
        for (memory, passes, expected) in [
            (
                256,
                2,
                "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
            ),
            (
                65_536,
                1,
                "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98",
            ),
        ] {
            let mut memory_blocks = blocks(65_536);
            let mut out = [0; 32];
            stretch(
                b"password",
                b"somesalt",
                memory,
                passes,
                &mut memory_blocks,
                &mut out,
            )
            .unwrap();
            assert_eq!(out.to_vec(), hex(expected));
        }
    }

    /// The key derived through the slots, at the least parameters, is the one libsodium derives
    /// from the same password, salt and parameters.
    #[test]
    fn a_key_from_a_password_matches_another_implementation() {
        let params =
            PasswordParams::from_bytes(&encoded(1, 65_536, 3, b"lethewis salt 16")).unwrap();
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut password = *b"correct horse battery staple";
        let mut working = blocks(params.memory_blocks());
        slots
            .derive_from_password(Purpose::Wrap, &mut password, &params, &mut working)
            .unwrap();
        let mut expected: [u8; 32] =
            hex("5f56b5f3d09ba3aeac81089cbd7ce7ff10a41406518a7017e9977ca393a02ac4")
                .try_into()
                .unwrap();
        assert_eq!(
            slots.import32(Purpose::Wrap, &mut expected).err(),
            Some(Error::DuplicateKey)
        );
    }

    #[test]
    fn parameters_are_read_as_written() {
        let salt: [u8; SALT_LEN] = core::array::from_fn(|i| u8::try_from(i).unwrap() + 1);
        let bytes = encoded(1, 65_536, 3, &salt);
        assert_eq!(
            bytes[..9],
            [1, 0x00, 0x00, 0x01, 0x00, 3, 0, 0, 0],
            "the version, then the memory and the passes in little-endian order"
        );
        let params = PasswordParams::from_bytes(&bytes).unwrap();
        assert_eq!(params.to_bytes(), bytes);
        assert_eq!(params.memory_blocks(), 65_536);
        let made = PasswordParams::new(65_536, 3, &mut Counting).unwrap();
        assert_eq!(made.to_bytes(), bytes, "the salt is the source's 16 bytes");
    }

    #[test]
    fn parameters_out_of_bounds_are_neither_made_nor_read() {
        let salt = [7; SALT_LEN];
        for (memory, passes, within) in [
            (65_535, 3, false),
            (65_536, 3, true),
            (65_536, 2, false),
            (65_536, 128, true),
            (65_536, 129, false),
            (2_097_152, 4, true),
            (2_097_152, 5, false),
            (2_097_153, 3, false),
            (u32::MAX, u32::MAX, false),
        ] {
            let mut source = Recording::default();
            let made = PasswordParams::new(memory, passes, &mut source);
            assert_eq!(made.is_ok(), within, "{memory} KiB, {passes} passes");
            assert_eq!(source.calls, usize::from(within));
            if !within {
                assert_eq!(made, Err(Error::InvalidParams));
            }
            let read = PasswordParams::from_bytes(&encoded(1, memory, passes, &salt));
            assert_eq!(read.is_ok(), within, "{memory} KiB, {passes} passes");
        }
        for version in [0, 2, 255] {
            assert_eq!(
                PasswordParams::from_bytes(&encoded(version, 65_536, 3, &salt)),
                Err(Error::InvalidParams)
            );
        }
        assert_eq!(
            PasswordParams::new(65_536, 3, &mut Failing),
            Err(Error::EntropyFailed)
        );
    }

    /// Parameters of 256 KiB, below the bounds, made directly: the stack a derivation uses does
    /// not grow with its memory, and the tests below run in every build.
    fn small(salt: u8) -> PasswordParams {
        PasswordParams {
            memory: 256,
            passes: 2,
            salt: [salt; SALT_LEN],
        }
    }

    #[test]
    fn an_empty_password_or_too_little_memory_changes_nothing() {
        let params = small(1);
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut working = blocks(256);
        assert_eq!(
            slots
                .derive_from_password(Purpose::Wrap, &mut [], &params, &mut working)
                .err(),
            Some(Error::InvalidPassword)
        );
        let mut password = *b"password";
        assert_eq!(
            slots
                .derive_from_password(Purpose::Wrap, &mut password, &params, &mut working[..255])
                .err(),
            Some(Error::NotEnoughMemory)
        );
        assert_eq!(&password, b"password");
        slots
            .derive_from_password(Purpose::Wrap, &mut password, &params, &mut working)
            .unwrap();
        assert_eq!(password, [0; 8], "the one slot was still free");
    }

    #[test]
    fn the_password_is_wiped_only_on_success() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut working = blocks(256);
        let mut password = *b"password";
        slots
            .derive_from_password(Purpose::Wrap, &mut password, &small(1), &mut working)
            .unwrap();
        assert_eq!(password, [0; 8]);
        let mut password = *b"password";
        assert_eq!(
            slots
                .derive_from_password(Purpose::Wrap, &mut password, &small(2), &mut working)
                .err(),
            Some(Error::NoFreeSlot)
        );
        assert_eq!(&password, b"password");
    }

    /// The blocks a derivation used are wiped whether it succeeded or not, and the rest of the
    /// memory is left as it was.
    #[test]
    fn the_working_memory_is_wiped() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        for outcome in [Ok(()), Err(Error::DuplicateKey)] {
            let mut working = blocks(300);
            for block in &mut working {
                block.as_mut().fill(7);
            }
            let mut password = *b"password";
            let derived =
                slots.derive_from_password(Purpose::Wrap, &mut password, &small(1), &mut working);
            assert_eq!(derived.map(|_| ()), outcome);
            assert!(
                working[..256]
                    .iter()
                    .all(|block| block.as_ref() == [0; 128])
            );
            assert!(
                working[256..]
                    .iter()
                    .all(|block| block.as_ref() == [7; 128])
            );
        }
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod stack {
    //! What a derivation from a password leaves on the stack, read back from the memory of this
    //! process.

    extern crate std;

    use core::hint::black_box;
    use std::vec::Vec;

    use argon2::{Algorithm, Argon2, Params, Version};
    use blake2::{Blake2b512, Digest};

    use super::tests::NEEDS;
    use super::{MemoryBlock, PasswordParams, SALT_LEN, STACK_WIPE, Stretch, stretch};
    use crate::derive::{Branch, SALT, stack::secrets};
    use crate::epoch::Epoch;
    use crate::error::Error;
    use crate::key::KeyLength;
    use crate::record::Purpose;
    use crate::residue::{assert_clean, below_pad, depth_changed, key_dependent, residue};
    use crate::slots::{Slot, Slots};

    const MEMORY: u32 = 256;
    const PASSES: u32 = 1;

    /// A password whose bytes appear nowhere else.
    fn password() -> [u8; 40] {
        core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(53).wrapping_add(29))
    }

    fn params() -> PasswordParams {
        PasswordParams {
            memory: MEMORY,
            passes: PASSES,
            salt: [5; SALT_LEN],
        }
    }

    fn words(block: &MemoryBlock) -> Vec<u8> {
        block
            .as_ref()
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    /// The secrets Argon2id leaves on the stack in a derivation from `password`, by name: the
    /// password; H0, from which the key follows without the password; the last block of its working
    /// memory; and the key.
    fn argon2_secrets(password: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        let salt = [5; SALT_LEN];
        let h0 = Blake2b512::new()
            .chain_update(1_u32.to_le_bytes())
            .chain_update(32_u32.to_le_bytes())
            .chain_update(MEMORY.to_le_bytes())
            .chain_update(PASSES.to_le_bytes())
            .chain_update(0x13_u32.to_le_bytes())
            .chain_update(2_u32.to_le_bytes())
            .chain_update(u32::try_from(password.len()).unwrap().to_le_bytes())
            .chain_update(password)
            .chain_update(16_u32.to_le_bytes())
            .chain_update(salt)
            .chain_update(0_u32.to_le_bytes())
            .chain_update(0_u32.to_le_bytes())
            .finalize();
        let mut memory = std::vec![MemoryBlock::new(); 256];
        let mut key = [0; 32];
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(MEMORY, PASSES, 1, Some(32)).unwrap(),
        )
        .hash_password_into_with_memory(password, &salt, &mut key, &mut memory)
        .unwrap();
        std::vec![
            ("the password", password.to_vec()),
            ("H0", h0.to_vec()),
            ("the last block", words(&memory[255])),
            ("the key", key.to_vec()),
        ]
    }

    /// The secrets a derivation from `password` handles: those of Argon2id, and those of the
    /// derivation of the key's identifier.
    fn derivation_secrets(password: &[u8]) -> Vec<Vec<u8>> {
        let argon2 = argon2_secrets(password);
        let key = argon2.last().unwrap().1.clone();
        let mut found: Vec<Vec<u8>> = argon2.into_iter().map(|(_, secret)| secret).collect();
        found.extend(secrets(&key, SALT, KeyLength::Bytes32, Branch::KeyId));
        found
    }

    fn other_password() -> [u8; 40] {
        password().map(|byte| byte ^ 0xff)
    }

    fn pieces() -> Vec<Vec<u8>> {
        key_dependent(
            &derivation_secrets(&password()),
            &derivation_secrets(&other_password()),
        )
    }

    /// The test can see residue: Argon2id without a wipe leaves some.
    #[test]
    fn argon2_without_a_wipe_leaves_residue() {
        let others = derivation_secrets(&other_password());
        let mut working = std::vec![MemoryBlock::new(); 256];
        let range = below_pad(false, || {
            let mut key = [0; 32];
            stretch(
                &password(),
                &[5; SALT_LEN],
                MEMORY,
                PASSES,
                &mut working,
                &mut key,
            )
            .unwrap();
            black_box(&key);
        });
        let pieces = key_dependent(
            &argon2_secrets(&password())
                .into_iter()
                .map(|(_, secret)| secret)
                .collect::<Vec<_>>(),
            &others,
        );
        assert!(residue(range, &pieces) > 0);
    }

    /// A derivation that fails after Argon2id has run, because the slots hold its key already.
    #[test]
    fn a_failed_derivation_from_a_password_leaves_no_residue() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut working = std::vec![MemoryBlock::new(); 256];
        slots
            .derive_from_password(Purpose::Wrap, &mut password(), &params(), &mut working)
            .unwrap();
        // A failure leaves the password as it was, in the caller's buffer, above what is read.
        let mut kept = password();
        assert_clean(&pieces, || {
            let derived =
                slots.derive_from_password(Purpose::Wrap, &mut kept, &params(), &mut working);
            assert_eq!(black_box(derived).err(), Some(Error::DuplicateKey));
        });
        assert_eq!(kept, password());
    }

    #[test]
    fn a_derivation_from_a_password_leaves_no_residue() {
        let pieces = pieces();
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut working = std::vec![MemoryBlock::new(); 256];
        assert_clean(&pieces, || {
            let mut password = password();
            slots
                .derive_from_password(Purpose::Wrap, &mut password, &params(), &mut working)
                .unwrap();
            black_box(&password);
        });
    }

    /// The wipe that follows a derivation from a password reaches as deep as it is meant to, also
    /// when the derivation fails after Argon2id has run, and no deeper than the documentation says.
    #[test]
    fn the_wipe_reaches_its_depth() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut working = std::vec![MemoryBlock::new(); 256];
        let needs = 1024 * NEEDS[usize::from(cfg!(lethewis_unoptimised))];
        for outcome in [None, Some(Error::DuplicateKey)] {
            let wiped = depth_changed(|| {
                let mut password = password();
                let derived = slots.derive_from_password(
                    Purpose::Wrap,
                    &mut password,
                    &params(),
                    &mut working,
                );
                assert_eq!(black_box(derived).err(), outcome);
            });
            assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
            assert!(wiped <= needs, "{wiped} bytes reached");
        }
    }

    /// The wipe covers more than the derivation uses: the generation with Argon2id as its source,
    /// which is all the derivation does after its checks.
    #[test]
    fn the_wipe_is_deeper_than_the_derivation() {
        let mut memory = [const { Slot::empty() }; 1];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut [9; 32]);
        let mut working = std::vec![MemoryBlock::new(); 256];
        let used = depth_changed(|| {
            let mut source = Stretch {
                password: &password(),
                params: &params(),
                memory: &mut working,
            };
            slots
                .generate(Purpose::Wrap, KeyLength::Bytes32, &mut source)
                .unwrap();
        });
        std::println!("a derivation from a password uses {used} bytes of stack");
        assert!(used.saturating_mul(2) <= STACK_WIPE, "{used} bytes used");
        assert!(used.saturating_mul(16) >= STACK_WIPE, "{used} bytes used");
    }
}

#[cfg(kani)]
#[coverage(on)]
pub(crate) mod proofs {
    use super::{PASSWORD_PARAMS_LEN, PasswordParams, SALT_LEN, password_fits};
    use crate::entropy::{Entropy, EntropyError};
    use crate::error::Error;

    /// The bounds as the documentation states them, apart from the code's constants.
    fn documented(memory: u32, passes: u32) -> bool {
        (65_536..=2_097_152).contains(&memory)
            && passes >= 3
            && u64::from(memory) * u64::from(passes) <= 8_388_608
    }

    /// Any parameters within the bounds, as the only ways to make or read them give.
    pub(crate) fn any_params() -> PasswordParams {
        let params = PasswordParams {
            memory: kani::any(),
            passes: kani::any(),
            salt: kani::any(),
        };
        kani::assume(documented(params.memory, params.passes));
        params
    }

    fn word(bytes: &[u8; PASSWORD_PARAMS_LEN], at: usize) -> u32 {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    /// Bytes are read exactly when they are version 1 and parameters within the bounds, and what
    /// is read writes back the same bytes: no two encodings of one set of parameters.
    #[kani::proof]
    fn parameters_are_read_exactly_as_written() {
        let bytes: [u8; PASSWORD_PARAMS_LEN] = kani::any();
        let (memory, passes) = (word(&bytes, 1), word(&bytes, 5));
        let read = PasswordParams::from_bytes(&bytes);
        kani::assert(
            read.is_ok() == (bytes[0] == 1 && documented(memory, passes)),
            "bytes are read exactly when they are the version and parameters within the bounds",
        );
        match read {
            Ok(params) => kani::assert(
                params.to_bytes() == bytes,
                "parameters read write back the bytes they were read from",
            ),
            Err(error) => kani::assert(
                error == Error::InvalidParams,
                "bytes that are not parameters are refused as such",
            ),
        }
        let bounded = (65_536..=2_097_152).contains(&memory) && passes >= 3;
        kani::cover!(read.is_ok(), "parameters are read");
        kani::cover!(
            bytes[0] != 1 && documented(memory, passes),
            "another version is refused"
        );
        kani::cover!(
            bytes[0] == 1 && memory < 65_536 && passes >= 3,
            "too little memory"
        );
        kani::cover!(bytes[0] == 1 && memory > 2_097_152, "too much memory");
        kani::cover!(
            bytes[0] == 1 && (65_536..=2_097_152).contains(&memory) && passes < 3,
            "too few passes"
        );
        kani::cover!(
            bytes[0] == 1 && bounded && !documented(memory, passes),
            "too much work"
        );
    }

    /// A password is refused exactly when it is empty or longer than 2^32 - 1 bytes, whatever its
    /// length.
    #[kani::proof]
    fn passwords_are_taken_by_their_length() {
        let length: usize = kani::any();
        kani::assert(
            password_fits(length) == (length >= 1 && length as u64 <= 4_294_967_295),
            "a password fits exactly when it is neither empty nor longer than 2^32 - 1 bytes",
        );
        kani::cover!(length == 0, "an empty password");
        kani::cover!(length as u64 == 4_294_967_295, "the longest password");
        kani::cover!(
            length as u64 == 4_294_967_296,
            "a password one byte too long"
        );
    }

    /// Writes any 16 bytes, then succeeds or fails, and remembers how often it was asked and what
    /// it wrote.
    struct AnySalt {
        calls: u8,
        written: [u8; SALT_LEN],
        failed: bool,
    }

    impl Entropy for AnySalt {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            self.calls = self.calls.saturating_add(1);
            self.written = kani::any();
            dest.copy_from_slice(&self.written);
            self.failed = kani::any();
            if self.failed {
                return Err(EntropyError);
            }
            Ok(())
        }
    }

    /// Parameters are made only within the bounds, without asking the source otherwise, with the
    /// memory and passes asked for and the source's bytes as the salt; and parameters made are read
    /// back as they are.
    #[kani::proof]
    fn parameters_are_made_only_within_the_bounds() {
        let (memory, passes): (u32, u32) = (kani::any(), kani::any());
        let mut source = AnySalt {
            calls: 0,
            written: [0; SALT_LEN],
            failed: false,
        };
        let made = PasswordParams::new(memory, passes, &mut source);
        if documented(memory, passes) {
            kani::assert(
                source.calls == 1,
                "within the bounds the source is asked once",
            );
            kani::assert(
                (made == Err(Error::EntropyFailed)) == source.failed
                    && made.is_ok() == !source.failed,
                "parameters are made exactly when the source succeeds",
            );
        } else {
            kani::assert(
                made == Err(Error::InvalidParams) && source.calls == 0,
                "out of the bounds nothing is made and the source is not asked",
            );
        }
        if let Ok(params) = made {
            let bytes = params.to_bytes();
            kani::assert(
                bytes[0] == 1
                    && word(&bytes, 1) == memory
                    && word(&bytes, 5) == passes
                    && bytes[9..] == source.written,
                "the parameters are the memory and passes asked for, with the source's salt",
            );
            kani::assert(
                PasswordParams::from_bytes(&bytes) == Ok(params),
                "parameters made are read back as they are",
            );
        }
        kani::cover!(made.is_ok(), "parameters are made");
        kani::cover!(made == Err(Error::EntropyFailed), "the source fails");
        kani::cover!(
            made == Err(Error::InvalidParams),
            "parameters out of the bounds"
        );
    }
}

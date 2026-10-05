// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(kani))]
use hkdf::Hkdf;
#[cfg(not(kani))]
use sha2::Sha256;

use crate::key::{Key, KeyLength, wipe};
use crate::record::{ID_LEN, Purpose, length_to_byte};

/// The salt of every derivation.
#[cfg(not(kani))]
const SALT: &[u8] = b"lethewis derivation salt v1";
/// The first bytes of every label.
const PREFIX: &[u8; 8] = b"lethewis";
const VERSION: u8 = 1;
/// Prefix (8), version, purpose, key length, output length (2), name length, and a name of up to
/// 16 bytes.
const LABEL_CAPACITY: usize = 30;
/// How many bytes of stack a derivation is followed by a wipe of: at least twice what it uses, as a
/// test measures in each build and with each SHA-256 back end. Without optimisation it uses far
/// more.
#[cfg(all(not(kani), not(lethewis_unoptimised)))]
const STACK_WIPE: usize = 8192;
#[cfg(all(not(kani), lethewis_unoptimised))]
const STACK_WIPE: usize = 65_536;

/// What a derived value is for. Each branch has a name of its own in the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Branch {
    /// The identifier of a key.
    KeyId,
    /// The key that encrypts the records a wrapping key wraps.
    #[cfg_attr(not(any(test, kani)), expect(dead_code))]
    WrapKey,
}

impl Branch {
    const fn name(self) -> &'static [u8] {
        match self {
            Self::KeyId => b"key id",
            Self::WrapKey => b"wrap key",
        }
    }
}

/// The derivation could not run: the output asked for is longer than HKDF-SHA-256 gives, 255
/// blocks of 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerivationFailed;

/// The identifier of a key, derived from the key itself. It is wiped when dropped.
#[cfg_attr(any(test, kani), derive(Debug, PartialEq, Eq))]
pub(crate) struct KeyId([u8; ID_LEN]);

impl KeyId {
    pub(crate) const fn empty() -> Self {
        Self([0; ID_LEN])
    }

    pub(crate) fn wipe(&mut self) {
        wipe(&mut self.0);
    }

    /// Takes the identifier out of `source` and wipes `source`.
    pub(crate) fn take(&mut self, source: &mut Self) {
        self.0 = source.0;
        source.wipe();
    }
}

impl Drop for KeyId {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Derives the identifier of `key`, which serves `purpose`, straight into `id`.
pub(crate) fn derive_key_id(
    key: &Key,
    purpose: Purpose,
    id: &mut KeyId,
) -> Result<(), DerivationFailed> {
    derive(key, purpose, Branch::KeyId, &mut id.0)
}

/// Fills `out` with the value of `branch` derived from `key`, which serves `purpose`. The key goes
/// through HKDF-Extract with a fixed salt, and HKDF-Expand takes the label. Then the stack the
/// derivation used is wiped, whether it succeeded or not.
pub(crate) fn derive(
    key: &Key,
    purpose: Purpose,
    branch: Branch,
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    let derived = derive_on_stack(key, purpose, branch, out);
    // The wipe ends in inline assembly, which Kani cannot model.
    #[cfg(not(kani))]
    zeroize::zeroize_stack::<STACK_WIPE>();
    derived
}

/// The derivation itself, in a frame of its own: the wipe that follows starts where this frame
/// starts.
#[inline(never)]
fn derive_on_stack(
    key: &Key,
    purpose: Purpose,
    branch: Branch,
    out: &mut [u8],
) -> Result<(), DerivationFailed> {
    let (label, used) = label(purpose, key.length(), branch, out.len())?;
    let info = label.get(..used).ok_or(DerivationFailed)?;
    let material = key.material().ok_or(DerivationFailed)?;
    hkdf(material, info, out)
}

#[cfg(not(kani))]
fn hkdf(material: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), DerivationFailed> {
    Hkdf::<Sha256>::new(Some(SALT), material)
        .expand(info, out)
        .map_err(|_| DerivationFailed)
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "a test computes offsets and the SHA-256 message schedule"
)]
mod stack {
    //! What a derivation leaves on the stack, read back from the memory of this process.

    extern crate std;

    use core::hint::black_box;
    use core::ops::Range;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::vec::Vec;

    use hkdf::Hkdf;
    use sha2::{Digest, Sha256, block_api::compress256};

    use super::{Branch, SALT, STACK_WIPE, derive, derive_on_stack, label};
    use crate::key::{
        Key, KeyLength,
        tests::{Counting, counted},
    };
    use crate::record::Purpose;
    use crate::slots::{Slot, Slots};

    /// Room between the test's frame and the code under test, so that reading the memory back,
    /// which runs at the test's depth, does not reach the stack that code used.
    const PAD: usize = 64 * 1024;
    /// How far below the pad the stack is read: deeper than the deepest wipe.
    const SCAN: usize = 128 * 1024;
    const PAINT: u8 = 0xa7;

    /// Runs `code` below the pad, after painting the stack it is about to use when asked to, and
    /// returns the addresses under the pad.
    #[inline(never)]
    #[expect(
        clippy::large_stack_arrays,
        reason = "the pad is a large array on the stack"
    )]
    fn below_pad(paint: bool, code: impl FnOnce()) -> Range<usize> {
        let pad = black_box([0x11_u8; PAD]);
        let low = black_box(&pad).as_ptr().addr();
        if paint {
            paint_stack();
        }
        code();
        black_box(&pad);
        low.saturating_sub(SCAN)..low
    }

    #[inline(never)]
    #[expect(
        clippy::large_stack_arrays,
        reason = "the paint is a large array on the stack"
    )]
    fn paint_stack() {
        black_box([PAINT; SCAN]);
    }

    fn read(range: Range<usize>) -> Vec<u8> {
        let mut memory = File::open("/proc/self/mem").unwrap();
        memory.seek(SeekFrom::Start(range.start as u64)).unwrap();
        let mut bytes = std::vec![0; range.len()];
        memory.read_exact(&mut bytes).unwrap();
        bytes
    }

    /// A 64-byte key whose bytes appear nowhere else.
    fn key_bytes() -> [u8; 64] {
        core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_mul(37).wrapping_add(11))
    }

    /// The initial state of SHA-256, FIPS 180-4, section 5.3.3.
    const IV: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    /// The round constants of SHA-256, FIPS 180-4, section 4.2.2.
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    /// An HMAC key block: `key` padded with zeros to 64 bytes, each byte combined with `pad` by
    /// exclusive or.
    fn key_block(key: &[u8], pad: u8) -> [u8; 64] {
        core::array::from_fn(|i| key.get(i).copied().unwrap_or(0) ^ pad)
    }

    /// The last block SHA-256 compresses for a 96-byte message whose last 32 bytes are `tail`: the
    /// tail, the end mark and the length in bits.
    fn final_block(tail: &[u8]) -> [u8; 64] {
        let mut block = [0; 64];
        block[..32].copy_from_slice(tail);
        block[32] = 0x80;
        block[56..].copy_from_slice(&768_u64.to_be_bytes());
        block
    }

    /// The SHA-256 state after `blocks`, from the initial state.
    fn state_after(blocks: &[[u8; 64]]) -> [u32; 8] {
        let mut state = IV;
        compress256(&mut state, blocks);
        state
    }

    /// The message schedule SHA-256 computes for `block`, FIPS 180-4, section 6.2.2.
    fn schedule(block: &[u8; 64]) -> [u32; 64] {
        let mut w = [0_u32; 64];
        for (word, bytes) in w.iter_mut().zip(block.chunks(4)) {
            *word = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        for i in 16..64 {
            let (a, b) = (w[i - 15], w[i - 2]);
            let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ a.wrapping_shr(3);
            let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ b.wrapping_shr(10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        w
    }

    /// Words as they sit in memory on either byte order.
    fn words_forms(words: &[u32]) -> [Vec<u8>; 2] {
        [
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
            words.iter().flat_map(|word| word.to_be_bytes()).collect(),
        ]
    }

    /// A state as it sits in memory: as eight words, and as the halves the SHA instructions of
    /// x86-64 keep it in on the way in, during the rounds and on the way out.
    fn state_forms(state: [u32; 8]) -> Vec<Vec<u8>> {
        let mut forms = Vec::from(words_forms(&state));
        for half in [
            [5, 4, 1, 0],
            [7, 6, 3, 2],
            [1, 0, 3, 2],
            [7, 6, 5, 4],
            [0, 1, 4, 5],
            [6, 7, 2, 3],
        ] {
            forms.extend(words_forms(&half.map(|word| state[word])));
        }
        forms
    }

    /// A hash output as bytes and as the words of the state it came from.
    fn hash_forms(hash: &[u8]) -> Vec<Vec<u8>> {
        let words: Vec<u32> = hash
            .chunks(4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
            .collect();
        let mut forms = std::vec![hash.to_vec()];
        forms.extend(state_forms(words.try_into().unwrap()));
        forms
    }

    /// A block a hash compresses, with its message schedule and the schedule plus the round
    /// constants, as they sit in memory.
    fn block_forms(block: &[u8; 64]) -> Vec<Vec<u8>> {
        let w = schedule(block);
        let with_constants: Vec<u32> = w.iter().zip(K).map(|(w, k)| w.wrapping_add(k)).collect();
        let mut forms = std::vec![block.to_vec()];
        forms.extend(words_forms(&w));
        forms.extend(words_forms(&with_constants));
        forms
    }

    /// The secrets a derivation of the identifier of the first `length` bytes of `key` handles:
    /// the key; in Extract, the state after the key and the inner hash; the extracted key, the
    /// HMAC key blocks made from it and the states after each, from which any value could be
    /// derived; in Expand, the inner hash; the message schedules of every secret block; and the
    /// first output block, in plain bytes past its first byte, so that the identifier itself,
    /// which the caller asked for, is not counted.
    fn secrets(key: &[u8], length: KeyLength) -> Vec<Vec<u8>> {
        let key = &key[..length.bytes()];
        let (label, used) = label(Purpose::Wrap, length, Branch::KeyId, 16).unwrap();
        let info = &label[..used];
        let (prk, expander) = Hkdf::<Sha256>::extract(Some(SALT), key);
        let mut output = [0; 32];
        expander.expand(info, &mut output).unwrap();

        let salt_inner = key_block(SALT, 0x36);
        let key_block_of_message: [u8; 64] = match length {
            KeyLength::Bytes32 => final_block(key),
            _ => key.try_into().unwrap(),
        };
        let extract_inner = Sha256::new()
            .chain_update(salt_inner)
            .chain_update(key)
            .finalize();
        let inner_block = key_block(&prk, 0x36);
        let outer_block = key_block(&prk, 0x5c);
        let expand_inner = Sha256::new()
            .chain_update(inner_block)
            .chain_update(info)
            .chain_update([1])
            .finalize();

        let mut secrets = std::vec![key.to_vec(), output[1..].to_vec()];
        secrets.extend(hash_forms(&prk));
        // Every form of the output but the plain one, whose first 16 bytes are the identifier.
        secrets.extend(
            hash_forms(&output)
                .into_iter()
                .enumerate()
                .filter(|&(form, _)| form != 0 && form != 2)
                .map(|(_, bytes)| bytes),
        );
        secrets.extend(state_forms(state_after(&[
            salt_inner,
            key_block_of_message,
        ])));
        secrets.extend(hash_forms(&extract_inner));
        secrets.extend(state_forms(state_after(&[inner_block])));
        secrets.extend(state_forms(state_after(&[outer_block])));
        secrets.extend(hash_forms(&expand_inner));
        for block in [
            key_block_of_message,
            inner_block,
            outer_block,
            final_block(&extract_inner),
            final_block(&expand_inner),
        ] {
            secrets.extend(block_forms(&block));
        }
        secrets
    }

    /// Whether a 16-byte piece looks like data rather than a pattern: the zeros and the padding in
    /// a hash block would match the wiped stack itself.
    fn varied(piece: &[u8]) -> bool {
        let mut bytes = piece.to_vec();
        bytes.sort_unstable();
        bytes.dedup();
        bytes.len() >= 10
    }

    /// The 16-byte pieces of the secrets of the first `length` bytes of `key` that depend on the
    /// key: varied, and absent from the secrets of another key, so that round constants and
    /// padding are not counted.
    fn pieces(key: &[u8], length: KeyLength) -> Vec<Vec<u8>> {
        let other: [u8; 64] = core::array::from_fn(|i| key[i] ^ 0xff);
        let public: HashSet<Vec<u8>> = secrets(&other, length)
            .iter()
            .flat_map(|secret| secret.windows(16).map(<[u8]>::to_vec))
            .collect();
        secrets(key, length)
            .iter()
            .flat_map(|secret| secret.windows(16).map(<[u8]>::to_vec))
            .filter(|piece| varied(piece) && !public.contains(piece))
            .collect()
    }

    /// How many of `pieces` the stack under the pad still holds.
    fn residue(range: Range<usize>, pieces: &[Vec<u8>]) -> usize {
        let stack = read(range);
        let windows: HashSet<&[u8]> = stack.windows(16).collect();
        pieces
            .iter()
            .filter(|piece| windows.contains(piece.as_slice()))
            .count()
    }

    fn loaded_key() -> Key {
        let mut key = Key::empty();
        key.load64(&mut key_bytes());
        key
    }

    /// Runs `code` below the pad and asserts that it leaves none of `pieces` there.
    fn assert_clean(pieces: &[Vec<u8>], code: impl FnOnce()) {
        let range = below_pad(false, code);
        assert_eq!(residue(range, pieces), 0);
    }

    /// The test can see residue: the derivation without the wipe leaves some.
    #[test]
    fn a_derivation_without_the_wipe_leaves_residue() {
        let pieces = pieces(&key_bytes(), KeyLength::Bytes64);
        let key = loaded_key();
        let range = below_pad(false, || {
            let mut id = [0; 16];
            derive_on_stack(&key, Purpose::Wrap, Branch::KeyId, &mut id).unwrap();
            black_box(&id);
        });
        assert!(residue(range, &pieces) > 0);
    }

    #[test]
    fn a_derivation_leaves_no_residue() {
        let key = loaded_key();
        assert_clean(&pieces(&key_bytes(), KeyLength::Bytes64), || {
            let mut id = [0; 16];
            derive(&key, Purpose::Wrap, Branch::KeyId, &mut id).unwrap();
            black_box(&id);
        });
    }

    /// An output longer than HKDF gives fails after Extract, with the extracted key on the stack.
    #[test]
    fn a_failed_derivation_leaves_no_residue() {
        let pieces = pieces(&key_bytes(), KeyLength::Bytes64);
        let key = loaded_key();
        let unwiped = below_pad(false, || {
            let mut out = [0; 8161];
            assert!(derive_on_stack(&key, Purpose::Wrap, Branch::KeyId, &mut out).is_err());
            black_box(&out);
        });
        assert!(residue(unwiped, &pieces) > 0);
        assert_clean(&pieces, || {
            let mut out = [0; 8161];
            assert!(derive(&key, Purpose::Wrap, Branch::KeyId, &mut out).is_err());
            black_box(&out);
        });
    }

    #[test]
    fn importing_a_key_leaves_no_residue() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let mut long = key_bytes();
        assert_clean(&pieces(&key_bytes(), KeyLength::Bytes64), || {
            slots.import64(Purpose::Wrap, &mut long).unwrap();
        });
        let mut short: [u8; 32] = key_bytes()[..32].try_into().unwrap();
        assert_clean(&pieces(&key_bytes(), KeyLength::Bytes32), || {
            slots.import32(Purpose::Wrap, &mut short).unwrap();
        });
    }

    #[test]
    fn generating_a_key_leaves_no_residue() {
        let mut memory = [const { Slot::empty() }; 2];
        let mut slots = Slots::new(&mut memory);
        let counted = counted::<64>();
        for length in [KeyLength::Bytes64, KeyLength::Bytes32] {
            assert_clean(&pieces(&counted, length), || {
                slots
                    .generate(Purpose::Wrap, length, &mut Counting)
                    .unwrap();
            });
        }
    }

    /// How deep below the pad `code` changed the painted stack.
    fn depth_changed(code: impl FnOnce()) -> usize {
        let range = below_pad(true, code);
        let stack = read(range);
        let lowest = stack.iter().position(|&byte| byte != PAINT).unwrap();
        stack.len() - lowest
    }

    /// The wipe that follows a derivation reaches as deep as it is meant to.
    #[test]
    fn the_wipe_reaches_its_depth() {
        let key = loaded_key();
        let wiped = depth_changed(|| {
            let mut id = [0; 16];
            derive(&key, Purpose::Wrap, Branch::KeyId, &mut id).unwrap();
            black_box(&id);
        });
        assert!(wiped >= STACK_WIPE, "{wiped} bytes wiped");
    }

    /// The wipe covers more than the derivation uses.
    #[test]
    fn the_wipe_is_deeper_than_the_derivation() {
        let key = loaded_key();
        let used = depth_changed(|| {
            let mut id = [0; 16];
            derive_on_stack(&key, Purpose::Wrap, Branch::KeyId, &mut id).unwrap();
            black_box(&id);
        });
        std::println!("a derivation uses {used} bytes of stack");
        assert!(used.saturating_mul(2) <= STACK_WIPE, "{used} bytes used");
        // Not needlessly deep either: a thread that cannot spare the stack would be corrupted.
        assert!(used.saturating_mul(8) >= STACK_WIPE, "{used} bytes used");
    }
}

#[cfg(kani)]
use model::hkdf;

/// What stands in for HKDF-SHA-256 under Kani, and how the proofs read an identifier.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::{DerivationFailed, KeyId};
    use crate::record::ID_LEN;

    /// Whether the last derivation failed, so a proof can tell a failure of the derivation from one
    /// the code makes up.
    static FAILED: AtomicBool = AtomicBool::new(false);

    /// HKDF-SHA-256 is beyond Kani. The model fails at will, after writing into `out`, and records
    /// whether it failed; otherwise `out` takes the first bytes of the key with the key's length and
    /// the label folded in, so equal inputs give equal outputs, and the output depends on those
    /// bytes, that length and the label. Folding every byte of the key would be too slow for the
    /// solver; that HKDF uses the whole key and the output length, the unit tests check.
    pub(super) fn hkdf(
        material: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), DerivationFailed> {
        let fail: bool = kani::any();
        FAILED.store(fail, Ordering::Relaxed);
        if fail {
            out.fill(0xa5);
            return Err(DerivationFailed);
        }
        fold(material, info, out);
        Ok(())
    }

    /// Whether the last derivation failed.
    pub(crate) fn failed() -> bool {
        FAILED.load(Ordering::Relaxed)
    }

    pub(crate) fn fold(material: &[u8], info: &[u8], out: &mut [u8]) {
        for (index, at) in out.iter_mut().enumerate() {
            *at = material.get(index).copied().unwrap_or(0);
        }
        if let Some(first) = out.first_mut() {
            *first ^= u8::try_from(material.len()).unwrap_or(u8::MAX);
        }
        for (index, byte) in info.iter().enumerate() {
            if let Some(at) = index.checked_rem(out.len()).and_then(|at| out.get_mut(at)) {
                *at ^= *byte;
            }
        }
    }

    pub(crate) const fn id_bytes(id: &KeyId) -> &[u8; ID_LEN] {
        &id.0
    }

    pub(crate) const fn id_from_bytes(bytes: [u8; ID_LEN]) -> KeyId {
        KeyId(bytes)
    }
}

/// The label of one derivation, and how many of its bytes are used. Every field but the name has a
/// fixed width, and the name, which comes last, is preceded by its length, so two different
/// derivations never share a label.
fn label(
    purpose: Purpose,
    length: KeyLength,
    branch: Branch,
    out_len: usize,
) -> Result<([u8; LABEL_CAPACITY], usize), DerivationFailed> {
    let out_len = u16::try_from(out_len).map_err(|_| DerivationFailed)?;
    let name = branch.name();
    let name_len = u8::try_from(name.len()).map_err(|_| DerivationFailed)?;
    let fixed = [VERSION, purpose as u8, length_to_byte(length)];
    let mut label = [0; LABEL_CAPACITY];
    let mut used: usize = 0;
    for part in [
        &PREFIX[..],
        &fixed,
        &out_len.to_le_bytes(),
        &[name_len],
        name,
    ] {
        let end = used.checked_add(part.len()).ok_or(DerivationFailed)?;
        label
            .get_mut(used..end)
            .ok_or(DerivationFailed)?
            .copy_from_slice(part);
        used = end;
    }
    Ok((label, used))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use hkdf::Hkdf;
    use sha2::Sha256;

    use super::{Branch, DerivationFailed, KeyId, derive, derive_key_id, label};
    use crate::key::{Key, KeyLength};
    use crate::record::Purpose;

    /// Input key material, salt, info, and the expected output in hexadecimal.
    type Case<'a> = (&'a [u8], Option<&'a [u8]>, &'a [u8], &'a str);

    /// RFC 5869, appendix A, test cases 1 to 3: the primitive under the wrapper.
    #[test]
    fn hkdf_sha256_matches_rfc_5869() {
        let ikm22 = [0x0b; 22];
        let salt13: [u8; 13] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let info10: [u8; 10] =
            core::array::from_fn(|i| 0xf0_u8.wrapping_add(u8::try_from(i).unwrap()));
        let ikm80: [u8; 80] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let salt80: [u8; 80] =
            core::array::from_fn(|i| 0x60_u8.wrapping_add(u8::try_from(i).unwrap()));
        let info80: [u8; 80] =
            core::array::from_fn(|i| 0xb0_u8.wrapping_add(u8::try_from(i).unwrap()));
        let cases: [Case<'_>; 3] = [
            (
                &ikm22,
                Some(&salt13),
                &info10,
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            ),
            (
                &ikm80,
                Some(&salt80),
                &info80,
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac78272\
                 71cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f\
                 1d87",
            ),
            (
                &ikm22,
                Some(&[]),
                &[],
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, expected) in cases {
            let mut okm = [0; 82];
            let okm = &mut okm[..expected.len().checked_div(2).unwrap()];
            Hkdf::<Sha256>::new(salt, ikm).expand(info, okm).unwrap();
            assert_eq!(hex(okm), expected);
        }
    }

    #[test]
    fn the_label_is_laid_out_as_documented() {
        let (bytes, used) = label(Purpose::Wrap, KeyLength::Bytes32, Branch::KeyId, 16).unwrap();
        let mut expected = b"lethewis".to_vec();
        expected.extend_from_slice(&[1, 1, 32, 16, 0, 6]);
        expected.extend_from_slice(b"key id");
        assert_eq!(&bytes[..used], &expected[..]);

        let (bytes, used) = label(Purpose::Wrap, KeyLength::Bytes64, Branch::WrapKey, 32).unwrap();
        let mut expected = b"lethewis".to_vec();
        expected.extend_from_slice(&[1, 1, 64, 32, 0, 8]);
        expected.extend_from_slice(b"wrap key");
        assert_eq!(&bytes[..used], &expected[..]);
    }

    /// Keys of both lengths whose bytes are all different: 0, 1, 2, ...
    fn counted_key(length: KeyLength) -> Key {
        let mut key = Key::empty();
        if length == KeyLength::Bytes32 {
            key.load32(&mut core::array::from_fn(|i| u8::try_from(i).unwrap()));
        } else {
            key.load64(&mut core::array::from_fn(|i| u8::try_from(i).unwrap()));
        }
        key
    }

    /// The wrapper against HKDF called directly with the salt and the label written out by hand,
    /// for both key lengths: the whole key goes in, and the label states its length.
    #[test]
    fn derivation_is_hkdf_with_the_salt_and_the_label() {
        for (length, length_byte) in [(KeyLength::Bytes32, 32_u8), (KeyLength::Bytes64, 64)] {
            let key = counted_key(length);
            let mut ours = [0; 16];
            derive(&key, Purpose::Wrap, Branch::KeyId, &mut ours).unwrap();

            let ikm: [u8; 64] = core::array::from_fn(|i| u8::try_from(i).unwrap());
            let ikm = &ikm[..usize::from(length_byte)];
            let mut info = b"lethewis".to_vec();
            info.extend_from_slice(&[1, 1, length_byte, 16, 0, 6]);
            info.extend_from_slice(b"key id");
            let mut direct = [0; 16];
            Hkdf::<Sha256>::new(Some(b"lethewis derivation salt v1"), ikm)
                .expand(&info, &mut direct)
                .unwrap();
            assert_eq!(ours, direct, "{length:?}");
        }
    }

    /// Outputs computed by an independent implementation of HKDF-SHA-256 from the documented salt
    /// and label: they fix the derivation for every key already written.
    #[test]
    fn derivations_match_known_answers() {
        let cases = [
            (
                KeyLength::Bytes32,
                Branch::KeyId,
                "588cab681d064e3003f3d416fb3bdaeb",
            ),
            (
                KeyLength::Bytes32,
                Branch::WrapKey,
                "b888ad072bde93503369146e95a5c4205a7ceff3f8063c2b4f3b6ab61abbb8cb",
            ),
            (
                KeyLength::Bytes64,
                Branch::KeyId,
                "83d471771a447746682fcf57c3e7b7e2",
            ),
            (
                KeyLength::Bytes64,
                Branch::WrapKey,
                "36a276730fac754e12ca4c3b3a6cfdf685d2429d5347438ee3020107dfa668f2",
            ),
        ];
        for (length, branch, expected) in cases {
            let mut out = [0; 32];
            let out = &mut out[..expected.len().checked_div(2).unwrap()];
            derive(&counted_key(length), Purpose::Wrap, branch, out).unwrap();
            assert_eq!(hex(out), expected, "{length:?} {branch:?}");
        }
    }

    #[test]
    fn branches_and_output_lengths_give_unrelated_values() {
        let mut key = Key::empty();
        key.load32(&mut [7; 32]);
        let mut id = [0; 32];
        let mut wrap = [0; 32];
        let mut short = [0; 16];
        derive(&key, Purpose::Wrap, Branch::KeyId, &mut id).unwrap();
        derive(&key, Purpose::Wrap, Branch::WrapKey, &mut wrap).unwrap();
        derive(&key, Purpose::Wrap, Branch::KeyId, &mut short).unwrap();
        assert_ne!(id, wrap);
        assert_ne!(id[..16], short);
    }

    /// The label states the key length, and Extract takes the key as a message rather than as an
    /// HMAC key, which would pad a short key with zeros: either keeps a key and its zero-padded long
    /// form apart.
    #[test]
    fn a_short_key_and_its_zero_padded_long_form_differ() {
        let mut short = Key::empty();
        short.load32(&mut [7; 32]);
        let mut padded = [0; 64];
        padded[..32].fill(7);
        let mut long = Key::empty();
        long.load64(&mut padded);
        let mut from_short = [0; 16];
        let mut from_long = [0; 16];
        derive(&short, Purpose::Wrap, Branch::KeyId, &mut from_short).unwrap();
        derive(&long, Purpose::Wrap, Branch::KeyId, &mut from_long).unwrap();
        assert_ne!(from_short, from_long);
    }

    #[test]
    fn take_moves_the_identifier_and_wipes_the_source() {
        let key = counted_key(KeyLength::Bytes64);
        let mut expected = KeyId::empty();
        derive_key_id(&key, Purpose::Wrap, &mut expected).unwrap();
        let mut source = KeyId::empty();
        derive_key_id(&key, Purpose::Wrap, &mut source).unwrap();
        let mut target = KeyId::empty();
        target.take(&mut source);
        assert_eq!(target, expected);
        assert_eq!(source, KeyId::empty());
        assert_ne!(target, KeyId::empty());
    }

    #[test]
    fn every_branch_has_a_label() {
        for branch in [Branch::KeyId, Branch::WrapKey] {
            let (_, used) = label(Purpose::Wrap, KeyLength::Bytes64, branch, 32).unwrap();
            assert_eq!(used, 14 + branch.name().len());
        }
    }

    #[test]
    fn a_label_states_any_output_length_of_two_bytes() {
        assert!(label(Purpose::Wrap, KeyLength::Bytes32, Branch::KeyId, 65_535).is_ok());
        assert!(label(Purpose::Wrap, KeyLength::Bytes32, Branch::KeyId, 65_536).is_err());
    }

    #[test]
    fn an_output_longer_than_hkdf_gives_is_refused() {
        let key = counted_key(KeyLength::Bytes32);
        assert!(derive(&key, Purpose::Wrap, Branch::KeyId, &mut [0; 8160]).is_ok());
        let mut out = [9; 8161];
        assert_eq!(
            derive(&key, Purpose::Wrap, Branch::KeyId, &mut out),
            Err(DerivationFailed)
        );
        assert!(out.iter().all(|&byte| byte == 9));
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        bytes.iter().fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").unwrap();
            text
        })
    }
}

#[cfg(kani)]
pub(crate) mod proofs {
    use super::{Branch, label, model::fold};
    use crate::key::KeyLength;
    use crate::record::{ID_LEN, Purpose};

    /// The identifier the model of HKDF gives for the first `length` bytes of `key`, worked out
    /// from the label alone, without a `Key` and without `derive`.
    pub(crate) fn expected_key_id(
        key: &[u8; 64],
        length: KeyLength,
        purpose: Purpose,
    ) -> [u8; ID_LEN] {
        let mut id = [0; ID_LEN];
        let _ = label(purpose, length, Branch::KeyId, ID_LEN).map(|(label, used)| {
            fold(&key[..length.bytes()], &label[..used], &mut id);
        });
        id
    }

    fn any_length() -> KeyLength {
        if kani::any() {
            KeyLength::Bytes32
        } else {
            KeyLength::Bytes64
        }
    }

    fn any_branch() -> Branch {
        if kani::any() {
            Branch::KeyId
        } else {
            Branch::WrapKey
        }
    }

    /// Two derivations that differ in anything the label states never share a label.
    #[kani::proof]
    #[kani::unwind(32)]
    fn different_derivations_have_different_labels() {
        let (length_a, branch_a, out_a): (KeyLength, Branch, u16) =
            (any_length(), any_branch(), kani::any());
        let (length_b, branch_b, out_b): (KeyLength, Branch, u16) =
            (any_length(), any_branch(), kani::any());
        let a = label(Purpose::Wrap, length_a, branch_a, usize::from(out_a));
        let b = label(Purpose::Wrap, length_b, branch_b, usize::from(out_b));
        kani::assert(
            a.is_ok() && b.is_ok(),
            "a label of an output length that fits in two bytes is always built",
        );
        if let (Ok((bytes_a, used_a)), Ok((bytes_b, used_b))) = (a, b)
            && (length_a, branch_a, out_a) != (length_b, branch_b, out_b)
        {
            kani::assert(
                used_a != used_b || bytes_a[..used_a] != bytes_b[..used_b],
                "different derivations have different labels",
            );
        }
        kani::cover!(branch_a != branch_b, "two branches");
        kani::cover!(
            length_a != length_b && branch_a == branch_b,
            "two key lengths"
        );
        kani::cover!(
            out_a != out_b && length_a == length_b && branch_a == branch_b,
            "two output lengths"
        );
    }
}

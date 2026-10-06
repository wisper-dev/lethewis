// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(kani))]
use aes_gcm_siv::{
    Aes256GcmSiv, KeyInit, Nonce,
    aead::{AeadInOut, inout::InOutBuf},
};

use crate::key::wipe;
use crate::record::PLAINTEXT_LEN;

/// The size of the key a record is encrypted with, in bytes.
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

/// Nothing was encrypted: the cipher refused the input, or it gave a known input a wrong answer, so
/// this build or this processor does not compute AES-256-GCM-SIV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SealFailed;

/// The record does not open under this key, nonce and associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rejected;

/// An input of the shape of a record, and what AES-256-GCM-SIV makes of it.
struct Known {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: &'static [u8],
    plaintext: [u8; PLAINTEXT_LEN],
    ciphertext: [u8; PLAINTEXT_LEN],
    tag: [u8; TAG_LEN],
}

/// Computed by an implementation of RFC 8452 that shares no code with this one and gives the
/// vectors of its appendices C.2 and C.3.
#[rustfmt::skip]
const KNOWN: Known = Known {
    key: [
        0x03, 0x20, 0x3d, 0x5a, 0x77, 0x94, 0xb1, 0xce, 0xeb, 0x08, 0x25, 0x42,
        0x5f, 0x7c, 0x99, 0xb6, 0xd3, 0xf0, 0x0d, 0x2a, 0x47, 0x64, 0x81, 0x9e,
        0xbb, 0xd8, 0xf5, 0x12, 0x2f, 0x4c, 0x69, 0x86,
    ],
    nonce: [
        0x07, 0x14, 0x21, 0x2e, 0x3b, 0x48, 0x55, 0x62, 0x6f, 0x7c, 0x89, 0x96,
    ],
    aad: b"lethewis self-test v1",
    plaintext: [
        0x05, 0x10, 0x1b, 0x26, 0x31, 0x3c, 0x47, 0x52, 0x5d, 0x68, 0x73, 0x7e,
        0x89, 0x94, 0x9f, 0xaa, 0xb5, 0xc0, 0xcb, 0xd6, 0xe1, 0xec, 0xf7, 0x02,
        0x0d, 0x18, 0x23, 0x2e, 0x39, 0x44, 0x4f, 0x5a, 0x65, 0x70, 0x7b, 0x86,
        0x91, 0x9c, 0xa7, 0xb2, 0xbd, 0xc8, 0xd3, 0xde, 0xe9, 0xf4, 0xff, 0x0a,
        0x15, 0x20, 0x2b, 0x36, 0x41, 0x4c, 0x57, 0x62, 0x6d, 0x78, 0x83, 0x8e,
        0x99, 0xa4, 0xaf, 0xba, 0xc5, 0xd0, 0xdb, 0xe6, 0xf1, 0xfc, 0x07, 0x12,
        0x1d, 0x28, 0x33, 0x3e, 0x49, 0x54, 0x5f, 0x6a, 0x75, 0x80, 0x8b, 0x96,
        0xa1, 0xac, 0xb7, 0xc2, 0xcd, 0xd8, 0xe3, 0xee,
    ],
    ciphertext: [
        0x90, 0x32, 0x9d, 0x1f, 0xb0, 0x2c, 0x7c, 0x0e, 0x6e, 0x36, 0x12, 0xbe,
        0x1c, 0x98, 0x8c, 0x6e, 0xfe, 0x3b, 0xe5, 0xe9, 0x8f, 0x61, 0x42, 0x7f,
        0xab, 0xcf, 0xa6, 0x7e, 0x86, 0xb3, 0xcb, 0x1d, 0x92, 0x5f, 0xf2, 0x63,
        0x46, 0xfd, 0x01, 0xa2, 0x6f, 0x8b, 0x8a, 0xee, 0x64, 0x19, 0xba, 0x0a,
        0x08, 0x77, 0x9d, 0xfd, 0x45, 0xac, 0x69, 0xf2, 0xb7, 0x23, 0x89, 0x64,
        0x9c, 0x45, 0x14, 0x90, 0x25, 0x80, 0x22, 0xca, 0x83, 0x68, 0xcd, 0xc3,
        0x3c, 0xfb, 0xf7, 0x98, 0x4f, 0xb6, 0x24, 0x09, 0x24, 0xdc, 0xdd, 0x02,
        0xc3, 0x79, 0x03, 0x20, 0x8e, 0xc1, 0x20, 0x7b,
    ],
    tag: [
        0xbc, 0x38, 0x39, 0xe5, 0x84, 0x1e, 0x6c, 0x89, 0xab, 0xb7, 0xfc, 0x64,
        0x61, 0xe4, 0x62, 0xab,
    ],
};

/// Encrypts `buffer` in place with AES-256-GCM-SIV and returns the tag. The cipher first encrypts a
/// known input; if its answer is wrong or the cipher fails, `buffer` is wiped and nothing is
/// encrypted.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8; PLAINTEXT_LEN],
) -> Result<[u8; TAG_LEN], SealFailed> {
    seal_checked(&KNOWN, key, nonce, aad, buffer)
}

fn seal_checked(
    known: &Known,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8; PLAINTEXT_LEN],
) -> Result<[u8; TAG_LEN], SealFailed> {
    let sealed = if answers(known) {
        encrypt(key, nonce, aad, buffer)
    } else {
        Err(SealFailed)
    };
    if sealed.is_err() {
        wipe(buffer);
    }
    sealed
}

/// Whether the cipher gives the known answer.
fn answers(known: &Known) -> bool {
    let mut buffer = known.plaintext;
    encrypt(&known.key, &known.nonce, known.aad, &mut buffer)
        .is_ok_and(|tag| buffer == known.ciphertext && tag == known.tag)
}

/// Decrypts `buffer` in place if `tag` matches it, the key, the nonce and the associated data, and
/// otherwise wipes it.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8; PLAINTEXT_LEN],
    tag: &[u8; TAG_LEN],
) -> Result<(), Rejected> {
    let opened = decrypt(key, nonce, aad, buffer, tag);
    if opened.is_err() {
        wipe(buffer);
    }
    opened
}

// In place only: with a separate output, a ciphertext that fails the tag would leave its
// decryption there.

#[cfg(not(kani))]
fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN], SealFailed> {
    Aes256GcmSiv::new(key.into())
        .encrypt_inout_detached(&Nonce::from(*nonce), aad, InOutBuf::from(buffer))
        .map(Into::into)
        .map_err(|_| SealFailed)
}

#[cfg(not(kani))]
fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), Rejected> {
    Aes256GcmSiv::new(key.into())
        .decrypt_inout_detached(
            &Nonce::from(*nonce),
            aad,
            InOutBuf::from(buffer),
            tag.into(),
        )
        .map_err(|_| Rejected)
}

#[cfg(kani)]
use model::{decrypt, encrypt};

/// What stands in for AES-256-GCM-SIV under Kani.
#[cfg(kani)]
pub(crate) mod model {
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::{KEY_LEN, NONCE_LEN, Rejected, SealFailed, TAG_LEN};

    /// Whether the last decryption was rejected, so a proof can tell a rejection by the cipher from
    /// one the code makes up.
    static REJECTED: AtomicBool = AtomicBool::new(false);

    /// AES-256-GCM-SIV is beyond Kani. Encryption writes any bytes, then gives any tag or fails.
    pub(super) fn encrypt(
        _: &[u8; KEY_LEN],
        _: &[u8; NONCE_LEN],
        _: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SealFailed> {
        for byte in buffer.iter_mut() {
            *byte = kani::any();
        }
        if kani::any() {
            Ok(kani::any())
        } else {
            Err(SealFailed)
        }
    }

    /// Decryption writes any bytes, then accepts or rejects at will and records which.
    pub(super) fn decrypt(
        _: &[u8; KEY_LEN],
        _: &[u8; NONCE_LEN],
        _: &[u8],
        buffer: &mut [u8],
        _: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        for byte in buffer.iter_mut() {
            *byte = kani::any();
        }
        let rejected: bool = kani::any();
        REJECTED.store(rejected, Ordering::Relaxed);
        if rejected { Err(Rejected) } else { Ok(()) }
    }

    /// Whether the last decryption was rejected.
    pub(crate) fn rejected() -> bool {
        REJECTED.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    reason = "a test decodes hex and picks bits of a tag"
)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::{
        KNOWN, Known, PLAINTEXT_LEN, Rejected, SealFailed, TAG_LEN, decrypt, encrypt, open, seal,
        seal_checked,
    };

    /// RFC 8452, appendices C.2 and C.3: key, nonce, associated data, plaintext, and the result,
    /// the ciphertext followed by the tag.
    const RFC_8452: [[&str; 5]; 26] = [
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "",
            "07f5f4169bbf55a8400cd47ea6fd400f",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "0100000000000000",
            "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "010000000000000000000000",
            "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "01000000000000000000000000000000",
            "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            "0100000000000000000000000000000002000000000000000000000000000000",
            concat!(
                "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027f",
                "e819e63abcd020b006a976397632eb5d",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            concat!(
                "0100000000000000000000000000000002000000000000000000000000000000",
                "03000000000000000000000000000000",
            ),
            concat!(
                "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e3",
                "9cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "",
            concat!(
                "0100000000000000000000000000000002000000000000000000000000000000",
                "0300000000000000000000000000000004000000000000000000000000000000",
            ),
            concat!(
                "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7",
                "e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce",
                "112864c269fc0d9d88c61fa47e39aa08",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "0200000000000000",
            "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "020000000000000000000000",
            "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "02000000000000000000000000000000",
            "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            "0200000000000000000000000000000003000000000000000000000000000000",
            concat!(
                "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365",
                "aea1bad12702e1965604374aab96dbbc",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            concat!(
                "0200000000000000000000000000000003000000000000000000000000000000",
                "04000000000000000000000000000000",
            ),
            concat!(
                "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47",
                "fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "01",
            concat!(
                "0200000000000000000000000000000003000000000000000000000000000000",
                "0400000000000000000000000000000005000000000000000000000000000000",
            ),
            concat!(
                "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc9",
                "8cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c89",
                "5bde0285037c5de81e5b570a049b62a0",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "010000000000000000000000",
            "02000000",
            "22b3f4cd1835e517741dfddccfa07fa4661b74cf",
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "010000000000000000000000000000000200",
            "0300000000000000000000000000000004000000",
            concat!(
                "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59",
                "cabfe307",
            ),
        ],
        [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "0100000000000000000000000000000002000000",
            "030000000000000000000000000000000400",
            concat!(
                "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc205",
                "6543",
            ),
        ],
        [
            "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
            "e0eaf5284d884a0e77d31646",
            "",
            "",
            "169fbb2fbf389a995f6390af22228a62",
        ],
        [
            "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269",
            "e4b47801afc0577e34699b9e",
            "4fbdc66f14",
            "671fdd",
            "0eaccb93da9bb81333aee0c785b240d319719d",
        ],
        [
            "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3",
            "2f6d1f0434d8848c1177441f",
            "6787f3ea22c127aaf195",
            "195495860f04",
            "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c",
        ],
        [
            "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0",
            "9f572c614b4745914474e7c7",
            "489c8fde2be2cf97e74e932d4ed87d",
            "c9882e5386fd9f92ec",
            "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2",
        ],
        [
            "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235",
            "5c9e940fea2f582950a70d5a",
            "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f",
            "1db2316fd568378da107b52b",
            "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5",
        ],
        [
            "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb",
            "6de71860f762ebfbd08284e4",
            "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
            "21702de0de18baa9c9596291b08466",
            "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd",
        ],
        [
            "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7",
            "028ec6eb5ea7e298342a94d4",
            "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
            "b202b370ef9768ec6561c4fe6b7e7296fa85",
            concat!(
                "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d",
                "0a49",
            ),
        ],
        [
            "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23",
            "688089e55540db1872504e1c",
            concat!(
                "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f",
                "167541",
            ),
            "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
            concat!(
                "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1d",
                "ed1a286594",
            ),
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
            concat!(
                "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3ea",
                "ffffffff000000000000000000000000",
            ),
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
            concat!(
                "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff00000000",
                "0000000000000000",
            ),
        ],
    ];

    /// Records sealed under other keys, nonces and associated data, computed by the same
    /// independent implementation as the known answer.
    #[rustfmt::skip]
    const OTHERS: [Known; 2] = [
        Known {
            key: [
                0x11, 0x46, 0x7b, 0xb0, 0xe5, 0x1a, 0x4f, 0x84, 0xb9, 0xee, 0x23, 0x58,
                0x8d, 0xc2, 0xf7, 0x2c, 0x61, 0x96, 0xcb, 0x00, 0x35, 0x6a, 0x9f, 0xd4,
                0x09, 0x3e, 0x73, 0xa8, 0xdd, 0x12, 0x47, 0x7c,
            ],
            nonce: [
                0x09, 0x32, 0x5b, 0x84, 0xad, 0xd6, 0xff, 0x28, 0x51, 0x7a, 0xa3, 0xcc,
            ],
            aad: b"",
            plaintext: [
                0x64, 0x6b, 0x72, 0x79, 0x80, 0x87, 0x8e, 0x95, 0x9c, 0xa3, 0xaa, 0xb1,
                0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb, 0xe2, 0xe9, 0xf0, 0xf7, 0xfe, 0x05,
                0x0c, 0x13, 0x1a, 0x21, 0x28, 0x2f, 0x36, 0x3d, 0x44, 0x4b, 0x52, 0x59,
                0x60, 0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98, 0x9f, 0xa6, 0xad,
                0xb4, 0xbb, 0xc2, 0xc9, 0xd0, 0xd7, 0xde, 0xe5, 0xec, 0xf3, 0xfa, 0x01,
                0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
                0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2, 0xa9,
                0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0xe1,
            ],
            ciphertext: [
                0xe2, 0xc5, 0x01, 0x55, 0x54, 0x3a, 0x77, 0xb6, 0x26, 0xc3, 0xba, 0x45,
                0x5c, 0xc5, 0x0d, 0xb0, 0x19, 0x56, 0x42, 0x9d, 0xaa, 0xcd, 0x87, 0x15,
                0x22, 0xa4, 0x4a, 0xff, 0xeb, 0xd0, 0x95, 0xa9, 0x9c, 0x10, 0xd3, 0xa2,
                0x3b, 0x8c, 0xf7, 0x37, 0x61, 0xb1, 0xd4, 0x85, 0x2e, 0x3b, 0x30, 0xe8,
                0xf8, 0x5f, 0x86, 0xcc, 0xb0, 0x51, 0x75, 0x4c, 0x8c, 0xfe, 0x62, 0xa8,
                0x00, 0xa4, 0x53, 0x67, 0xe8, 0x39, 0xa9, 0x20, 0xea, 0x63, 0x5d, 0xe1,
                0x61, 0xe6, 0xa7, 0x0f, 0xed, 0x98, 0x93, 0x4c, 0x88, 0x9e, 0x52, 0x03,
                0x4c, 0x00, 0x17, 0x47, 0xc1, 0x30, 0x09, 0x8e,
            ],
            tag: [
                0x73, 0xe5, 0x53, 0x8b, 0x74, 0x86, 0x25, 0x83, 0x68, 0xd5, 0xf8, 0x16,
                0x22, 0xb3, 0xda, 0x25,
            ],
        },
        Known {
            key: [
                0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea, 0xe7, 0xe4, 0xe1, 0xde,
                0xdb, 0xd8, 0xd5, 0xd2, 0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
                0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
            ],
            nonce: [
                0xc8, 0xcd, 0xd2, 0xd7, 0xdc, 0xe1, 0xe6, 0xeb, 0xf0, 0xf5, 0xfa, 0xff,
            ],
            aad: b"lethewis record context 0123456789abcdef",
            plaintext: [
                0x01, 0x14, 0x27, 0x3a, 0x4d, 0x60, 0x73, 0x86, 0x99, 0xac, 0xbf, 0xd2,
                0xe5, 0xf8, 0x0b, 0x1e, 0x31, 0x44, 0x57, 0x6a, 0x7d, 0x90, 0xa3, 0xb6,
                0xc9, 0xdc, 0xef, 0x02, 0x15, 0x28, 0x3b, 0x4e, 0x61, 0x74, 0x87, 0x9a,
                0xad, 0xc0, 0xd3, 0xe6, 0xf9, 0x0c, 0x1f, 0x32, 0x45, 0x58, 0x6b, 0x7e,
                0x91, 0xa4, 0xb7, 0xca, 0xdd, 0xf0, 0x03, 0x16, 0x29, 0x3c, 0x4f, 0x62,
                0x75, 0x88, 0x9b, 0xae, 0xc1, 0xd4, 0xe7, 0xfa, 0x0d, 0x20, 0x33, 0x46,
                0x59, 0x6c, 0x7f, 0x92, 0xa5, 0xb8, 0xcb, 0xde, 0xf1, 0x04, 0x17, 0x2a,
                0x3d, 0x50, 0x63, 0x76, 0x89, 0x9c, 0xaf, 0xc2,
            ],
            ciphertext: [
                0x15, 0xe1, 0x98, 0xf3, 0xaf, 0xf5, 0xcf, 0xce, 0x54, 0xac, 0x6d, 0x76,
                0x22, 0x08, 0x81, 0xab, 0xfd, 0x1b, 0x66, 0x64, 0x1f, 0x1c, 0x8b, 0x5c,
                0xd4, 0x22, 0xc6, 0xf0, 0x65, 0xc7, 0xf7, 0x3f, 0x08, 0xa5, 0x2d, 0xe0,
                0x27, 0x62, 0xfb, 0xa4, 0xb4, 0x1b, 0x66, 0xb2, 0x83, 0xf3, 0x9f, 0x7a,
                0x79, 0x5a, 0x0f, 0x35, 0x59, 0xc7, 0x39, 0x3e, 0x62, 0x36, 0x84, 0x5b,
                0x91, 0x21, 0x3a, 0x0e, 0x1e, 0x69, 0xc4, 0x3c, 0xc2, 0x26, 0xe9, 0x2f,
                0xbc, 0x92, 0x9c, 0x23, 0xb3, 0xff, 0x3f, 0x73, 0x76, 0x7d, 0x9c, 0x79,
                0xcd, 0x0f, 0xeb, 0x33, 0xa7, 0xfc, 0xac, 0x20,
            ],
            tag: [
                0x1c, 0xde, 0x16, 0x87, 0xc2, 0x39, 0x41, 0xba, 0xaf, 0x11, 0xa9, 0xa9,
                0x15, 0xc5, 0x82, 0x16,
            ],
        },
    ];

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn array<const N: usize>(text: &str) -> [u8; N] {
        hex(text).try_into().unwrap()
    }

    #[test]
    fn the_cipher_gives_the_vectors_of_rfc_8452() {
        for [key, nonce, aad, plaintext, result] in RFC_8452 {
            let (key, nonce, aad) = (array(key), array(nonce), hex(aad));
            let mut buffer = hex(plaintext);
            let tag = encrypt(&key, &nonce, &aad, &mut buffer).unwrap();
            assert_eq!([&buffer[..], &tag[..]].concat(), hex(result), "{plaintext}");
            decrypt(&key, &nonce, &aad, &mut buffer, &tag).unwrap();
            assert_eq!(buffer, hex(plaintext));
        }
    }

    #[test]
    fn every_changed_bit_of_a_tag_is_rejected() {
        for [key, nonce, aad, _, result] in RFC_8452 {
            let (key, nonce, aad, result) = (array(key), array(nonce), hex(aad), hex(result));
            let (ciphertext, tag) = result.split_at(result.len() - TAG_LEN);
            for bit in 0..TAG_LEN * 8 {
                let mut tag: [u8; TAG_LEN] = tag.try_into().unwrap();
                tag[bit / 8] ^= 1 << (bit % 8);
                let mut buffer = ciphertext.to_vec();
                assert_eq!(
                    decrypt(&key, &nonce, &aad, &mut buffer, &tag),
                    Err(Rejected)
                );
            }
        }
    }

    #[test]
    fn an_empty_ciphertext_with_a_zero_tag_is_rejected() {
        for aad in [&b""[..], b"any associated data"] {
            assert_eq!(
                decrypt(&KNOWN.key, &KNOWN.nonce, aad, &mut [], &[0; TAG_LEN]),
                Err(Rejected)
            );
        }
    }

    #[test]
    fn a_record_seals_to_the_known_answer_and_opens() {
        let mut buffer = KNOWN.plaintext;
        let tag = seal(&KNOWN.key, &KNOWN.nonce, KNOWN.aad, &mut buffer).unwrap();
        assert_eq!((buffer, tag), (KNOWN.ciphertext, KNOWN.tag));
        open(&KNOWN.key, &KNOWN.nonce, KNOWN.aad, &mut buffer, &tag).unwrap();
        assert_eq!(buffer, KNOWN.plaintext);
    }

    #[test]
    fn records_under_other_keys_seal_and_open() {
        for known in OTHERS {
            let mut buffer = known.plaintext;
            let tag = seal(&known.key, &known.nonce, known.aad, &mut buffer).unwrap();
            assert_eq!((buffer, tag), (known.ciphertext, known.tag));
            open(&known.key, &known.nonce, known.aad, &mut buffer, &tag).unwrap();
            assert_eq!(buffer, known.plaintext);
        }
    }

    /// The known input with one byte of one field changed.
    fn changed(field: usize, at: usize) -> Known {
        let mut known = Known { ..KNOWN };
        match field {
            0 => known.key[at % 32] ^= 1,
            1 => known.nonce[at % 12] ^= 1,
            2 => known.aad = b"lethewis self-test v2",
            3 => known.plaintext[at] ^= 1,
            4 => known.ciphertext[at] ^= 1,
            _ => known.tag[at % TAG_LEN] ^= 1,
        }
        known
    }

    #[test]
    fn a_wrong_answer_fails_the_seal_and_wipes_the_buffer() {
        for field in 0..6 {
            for at in [0, 41, PLAINTEXT_LEN - 1] {
                let mut buffer = KNOWN.plaintext;
                assert_eq!(
                    seal_checked(
                        &changed(field, at),
                        &KNOWN.key,
                        &KNOWN.nonce,
                        KNOWN.aad,
                        &mut buffer
                    ),
                    Err(SealFailed),
                    "field {field}, byte {at}"
                );
                assert_eq!(buffer, [0; PLAINTEXT_LEN]);
            }
        }
    }

    #[test]
    fn a_record_that_does_not_open_is_wiped() {
        for field in 0..6 {
            for at in [0, 41, PLAINTEXT_LEN - 1] {
                let known = changed(field, at);
                let mut buffer = if field == 3 {
                    KNOWN.ciphertext
                } else {
                    known.ciphertext
                };
                if field == 3 {
                    buffer[at] ^= 1;
                }
                assert_eq!(
                    open(&known.key, &known.nonce, known.aad, &mut buffer, &known.tag),
                    Err(Rejected),
                    "field {field}, byte {at}"
                );
                assert_eq!(buffer, [0; PLAINTEXT_LEN]);
            }
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::{PLAINTEXT_LEN, model::rejected, open, seal};

    /// For any key, nonce, associated data and record, and whatever the cipher does: sealing either
    /// gives a tag, or fails and leaves the buffer zero.
    #[kani::proof]
    #[kani::unwind(93)]
    fn a_failed_seal_leaves_the_buffer_wiped() {
        let mut buffer: [u8; PLAINTEXT_LEN] = kani::any();
        let aad: [u8; 4] = kani::any();
        let sealed = seal(&kani::any(), &kani::any(), &aad, &mut buffer);
        kani::assert(
            sealed.is_ok() || buffer == [0; PLAINTEXT_LEN],
            "a failed seal leaves the buffer zero",
        );
        kani::cover!(sealed.is_ok(), "a record is sealed");
        kani::cover!(sealed.is_err(), "a seal fails");
    }

    /// For any key, nonce, associated data, record and tag, and whatever the cipher does: opening
    /// fails exactly when the cipher rejects the record, and then leaves the buffer zero.
    #[kani::proof]
    #[kani::unwind(93)]
    fn a_rejected_record_leaves_the_buffer_wiped() {
        let mut buffer: [u8; PLAINTEXT_LEN] = kani::any();
        let aad: [u8; 4] = kani::any();
        let opened = open(&kani::any(), &kani::any(), &aad, &mut buffer, &kani::any());
        kani::assert(
            opened.is_err() == rejected(),
            "a record is refused exactly when the cipher rejects it",
        );
        kani::assert(
            opened.is_ok() || buffer == [0; PLAINTEXT_LEN],
            "a refused record leaves the buffer zero",
        );
        kani::cover!(opened.is_ok(), "a record opens");
        kani::cover!(opened.is_err(), "a record is refused");
    }
}

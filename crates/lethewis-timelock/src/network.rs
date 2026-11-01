// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{Error, curve};

/// The length of a round's signature: a point of G1 of BLS12-381, compressed.
pub const SIGNATURE_LEN: usize = 48;

/// A drand network: the hash naming its chain, its group key, and when its rounds come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub(crate) chain_hash: [u8; 32],
    pub(crate) public_key: [u8; curve::KEY_LEN],
    pub(crate) genesis: u64,
    pub(crate) period: u64,
}

/// The drand network quicknet. Round 1 comes at 1692803367 seconds since the Unix epoch, then one
/// round every 3 seconds, each signed in G1 with the hash to the curve of RFC 9380.
pub const QUICKNET: Network = Network {
    chain_hash: [
        0x52, 0xdb, 0x9b, 0xa7, 0x0e, 0x0c, 0xc0, 0xf6, 0xea, 0xf7, 0x80, 0x3d, //
        0xd0, 0x74, 0x47, 0xa1, 0xf5, 0x47, 0x77, 0x35, 0xfd, 0x3f, 0x66, 0x17, //
        0x92, 0xba, 0x94, 0x60, 0x0c, 0x84, 0xe9, 0x71,
    ],
    public_key: [
        0x83, 0xcf, 0x0f, 0x28, 0x96, 0xad, 0xee, 0x7e, 0xb8, 0xb5, 0xf0, 0x1f, //
        0xca, 0xd3, 0x91, 0x22, 0x12, 0xc4, 0x37, 0xe0, 0x07, 0x3e, 0x91, 0x1f, //
        0xb9, 0x00, 0x22, 0xd3, 0xe7, 0x60, 0x18, 0x3c, 0x8c, 0x4b, 0x45, 0x0b, //
        0x6a, 0x0a, 0x6c, 0x3a, 0xc6, 0xa5, 0x77, 0x6a, 0x2d, 0x10, 0x64, 0x51, //
        0x0d, 0x1f, 0xec, 0x75, 0x8c, 0x92, 0x1c, 0xc2, 0x2b, 0x0e, 0x17, 0xe6, //
        0x3a, 0xaf, 0x4b, 0xcb, 0x5e, 0xd6, 0x63, 0x04, 0xde, 0x9c, 0xf8, 0x09, //
        0xbd, 0x27, 0x4c, 0xa7, 0x3b, 0xab, 0x4a, 0xf5, 0xa6, 0xe9, 0xc7, 0x6a, //
        0x4b, 0xc0, 0x9e, 0x76, 0xea, 0xe8, 0x99, 0x1e, 0xf5, 0xec, 0xe4, 0x5a,
    ],
    genesis: 1_692_803_367,
    period: 3,
};

impl Network {
    /// The hash naming the chain, as drand gives it.
    #[must_use]
    pub const fn chain_hash(&self) -> &[u8; 32] {
        &self.chain_hash
    }

    /// The first round published at `time` or later, in seconds since the Unix epoch, or `None`
    /// for a time before round 1.
    #[must_use]
    pub const fn round_at_or_after(&self, time: u64) -> Option<u64> {
        let Some(since) = time.checked_sub(self.genesis) else {
            return None;
        };
        since.div_ceil(self.period).checked_add(1)
    }

    /// When `round` is published, in seconds since the Unix epoch, or `None` for round 0 and for a
    /// round past the largest time.
    #[must_use]
    pub const fn time_of(&self, round: u64) -> Option<u64> {
        let Some(before) = round.checked_sub(1) else {
            return None;
        };
        let Some(since) = before.checked_mul(self.period) else {
            return None;
        };
        since.checked_add(self.genesis)
    }

    /// Checks that `signature` is this network's signature of `round`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRound`] for round 0. [`Error::SignatureRejected`] for a signature that is
    /// not a point of G1 in canonical compressed form, is the identity, or does not sign the round
    /// under the network's key.
    pub fn verify(&self, round: u64, signature: &[u8; SIGNATURE_LEN]) -> Result<(), Error> {
        if round == 0 {
            return Err(Error::InvalidRound);
        }
        if curve::verify(&self.public_key, signature, &curve::message(round)) {
            Ok(())
        } else {
            Err(Error::SignatureRejected)
        }
    }
}

#[cfg(kani)]
#[coverage(on)]
mod proofs;

#[cfg(test)]
mod tests {
    use blst::min_sig::{AggregateSignature, PublicKey, Signature};
    use blst::{BLST_ERROR, Pairing, blst_fp, blst_p1_affine, blst_p2_affine};
    use sha2::{Digest, Sha256};

    use super::{Network, QUICKNET, SIGNATURE_LEN};
    use crate::vectors::{BEACONS, signature_of, unhex};
    use crate::{Error, curve};

    /// The genesis seed of quicknet, which its chain hash covers.
    const SEED: &str = "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e";

    /// The modulus of the base field of BLS12-381.
    const MODULUS: &str = concat!(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf",
        "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    );

    #[test]
    fn the_key_and_the_clock_are_those_the_chain_hash_names() {
        let hash = Sha256::new()
            .chain_update(u32::try_from(QUICKNET.period).unwrap().to_be_bytes())
            .chain_update(i64::try_from(QUICKNET.genesis).unwrap().to_be_bytes())
            .chain_update(QUICKNET.public_key)
            .chain_update(unhex::<32>(SEED))
            .chain_update(b"quicknet")
            .finalize();
        assert_eq!(hash[..], QUICKNET.chain_hash()[..]);
    }

    #[test]
    fn the_signatures_of_quicknet_verify() {
        for (round, signature) in BEACONS {
            assert_eq!(
                QUICKNET.verify(round, &unhex(signature)),
                Ok(()),
                "round {round}"
            );
        }
    }

    #[test]
    fn a_signature_verifies_for_its_round_only() {
        let signature = signature_of(1000);
        for round in [999, 1001, 1000 << 32, u64::MAX] {
            assert_eq!(
                QUICKNET.verify(round, &signature),
                Err(Error::SignatureRejected)
            );
        }
        assert_eq!(QUICKNET.verify(0, &signature), Err(Error::InvalidRound));
    }

    #[test]
    fn a_changed_signature_is_rejected() {
        let signature = signature_of(1000);
        for at in 0..SIGNATURE_LEN {
            for bit in 0..8 {
                let mut changed = signature;
                changed[at] ^= 1 << bit;
                assert_eq!(
                    QUICKNET.verify(1000, &changed),
                    Err(Error::SignatureRejected),
                    "byte {at}, bit {bit}"
                );
            }
        }
    }

    #[test]
    fn the_key_of_quicknet_is_a_point_of_its_group_other_than_the_identity() {
        assert!(PublicKey::key_validate(&QUICKNET.public_key).is_ok());
    }

    /// A point of order 3 added to a signature leaves the pairing unchanged, so only the check of
    /// the group refuses the sum.
    #[test]
    fn a_signature_outside_the_group_is_rejected() {
        // (0, 2), with 2 in Montgomery form as blst keeps it.
        let order_three = Signature::from(blst_p1_affine {
            x: blst_fp { l: [0; 6] },
            y: blst_fp {
                l: [
                    0x3213_0000_0006_554f,
                    0xb93c_0018_d6c4_0005,
                    0x5760_5e0d_b0dd_bb51,
                    0x8b25_6521_ed1f_9bcb,
                    0x6cf2_8d79_0162_2c03,
                    0x11eb_ab9d_bb81_e28c,
                ],
            },
        });
        let signature = Signature::from_bytes(&signature_of(1000)).unwrap();
        let sum = AggregateSignature::aggregate(&[&signature, &order_three], false).unwrap();
        let sum = sum.to_signature();
        let mut pairing = Pairing::new(true, curve::DST);
        let key = PublicKey::from_bytes(&QUICKNET.public_key).unwrap();
        let (key, point): (blst_p2_affine, blst_p1_affine) = (key.into(), sum.into());
        let message = curve::message(1000);
        assert_eq!(
            pairing.aggregate(&key, true, &point, false, &message, &[]),
            BLST_ERROR::BLST_SUCCESS
        );
        pairing.commit();
        assert!(
            pairing.finalverify(None),
            "the pairing alone accepts the sum"
        );
        let sum = sum.to_bytes();
        assert_ne!(sum, signature_of(1000));
        for outside in [order_three.to_bytes(), sum] {
            assert_eq!(
                QUICKNET.verify(1000, &outside),
                Err(Error::SignatureRejected)
            );
        }
    }

    #[test]
    fn the_identity_is_rejected_as_a_signature_and_as_a_key() {
        let mut identity = [0; SIGNATURE_LEN];
        identity[0] = 0xc0;
        assert_eq!(
            QUICKNET.verify(1000, &identity),
            Err(Error::SignatureRejected)
        );
        let mut key = [0; 96];
        key[0] = 0xc0;
        let network = Network {
            public_key: key,
            ..QUICKNET
        };
        assert_eq!(
            network.verify(1000, &identity),
            Err(Error::SignatureRejected)
        );
    }

    #[test]
    fn encodings_other_than_the_canonical_compressed_one_are_rejected() {
        let signature = signature_of(1000);
        let mut uncompressed = signature;
        uncompressed[0] &= 0x7f;
        let mut past_the_modulus: [u8; SIGNATURE_LEN] = unhex(MODULUS);
        past_the_modulus[0] |= 0x80;
        let mut infinity_with_bits = [0; SIGNATURE_LEN];
        infinity_with_bits[0] = 0xc0;
        infinity_with_bits[SIGNATURE_LEN - 1] = 1;
        for encoding in [uncompressed, past_the_modulus, infinity_with_bits] {
            assert_eq!(
                QUICKNET.verify(1000, &encoding),
                Err(Error::SignatureRejected)
            );
        }
    }

    #[test]
    fn rounds_and_times_follow_the_clock_of_the_network() {
        // The last round whose time 64 bits hold, which comes at the largest time exactly.
        const LAST: u64 = 6_148_914_690_672_249_417;
        let genesis = QUICKNET.genesis;
        assert_eq!(QUICKNET.round_at_or_after(0), None);
        assert_eq!(QUICKNET.round_at_or_after(genesis - 1), None);
        assert_eq!(QUICKNET.round_at_or_after(genesis), Some(1));
        assert_eq!(QUICKNET.round_at_or_after(genesis + 1), Some(2));
        assert_eq!(QUICKNET.round_at_or_after(genesis + 3), Some(2));
        assert_eq!(QUICKNET.round_at_or_after(genesis + 4), Some(3));
        assert_eq!(QUICKNET.round_at_or_after(u64::MAX - 1), Some(LAST));
        assert_eq!(QUICKNET.round_at_or_after(u64::MAX), Some(LAST));
        assert_eq!(QUICKNET.time_of(0), None);
        assert_eq!(QUICKNET.time_of(1), Some(genesis));
        assert_eq!(QUICKNET.time_of(2), Some(genesis + 3));
        assert_eq!(QUICKNET.time_of(33_512_211), Some(1_793_339_997));
        assert_eq!(QUICKNET.time_of(LAST), Some(u64::MAX));
        assert_eq!(QUICKNET.time_of(LAST + 1), None);
        assert_eq!(QUICKNET.time_of(u64::MAX), None);
    }
}

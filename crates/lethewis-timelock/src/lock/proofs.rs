// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{LOCK_MAX_SECONDS, LOCK_RANDOM_LEN};
use crate::age::model::{made, payload};
use crate::age::{LOCKED_KEY_LEN, MAC_LEN, NONCE_LEN, PAYLOAD_LEN, header};
use crate::curve::model::{asked, message};
use crate::decimal::{self, Decimal};
use crate::ibe::BODY_LEN;
use crate::ibe::model::{unwrapped, wrapped};
use crate::{Error, QUICKNET};

#[kani::proof]
#[kani::solver(kissat)]
fn a_key_is_locked_until_the_round_of_its_time_within_a_year() {
    let key: [u8; LOCKED_KEY_LEN] = kani::any();
    let now: u64 = kani::any();
    let until: u64 = kani::any();
    let random: [u8; LOCK_RANDOM_LEN] = kani::any();
    let locked = QUICKNET.lock(&key, now, until, &random);
    let wrap = wrapped();
    let mac = made();
    let sealed = payload();
    let in_time =
        QUICKNET.genesis <= now && now < until && until.wrapping_sub(now) <= LOCK_MAX_SECONDS;
    if !in_time {
        kani::assert(
            locked == Err(Error::InvalidTime) && wrap.times == 0,
            "a time out of range is refused before any work",
        );
        return;
    }
    let round = wrap
        .message
        .first_chunk::<8>()
        .map_or(0, |bytes| u64::from_be_bytes(*bytes));
    let first = QUICKNET.time_of(round).is_some_and(|time| until <= time)
        && QUICKNET
            .time_of(round.wrapping_sub(1))
            .is_none_or(|time| time < until);
    let (file_key, sigma, nonce) = (
        random.first_chunk::<16>(),
        random.get(16..).and_then(<[u8]>::first_chunk::<16>),
        random.last_chunk::<16>(),
    );
    kani::assert(
        wrap.times == 1
            && wrap.key == QUICKNET.public_key
            && wrap.message == message(round)
            && first
            && Some(&wrap.file_key) == file_key
            && Some(&wrap.sigma) == sigma,
        "the file key is encrypted to the first round published at the time or later, with the \
         bytes drawn",
    );
    match &locked {
        Ok(lock) => {
            let expected = Decimal::of(round).map(|decimal| {
                let mut expected = header(&decimal, &QUICKNET.chain_hash, &wrap.body);
                expected.finish(&mac.mac, &sealed.nonce, &sealed.payload);
                expected
            });
            kani::assert(
                mac.times == 1
                    && Some(&mac.file_key) == file_key
                    && sealed.seals == 1
                    && Some(&sealed.file_key) == file_key
                    && Some(&sealed.nonce) == nonce
                    && sealed.key == key
                    && expected.as_ref() == Some(lock),
                "the lock holds the key sealed under the file key and nonce drawn",
            );
        }
        Err(error) => kani::assert(
            *error == Error::RandomUnusable,
            "a time in range fails only with unusable random bytes",
        ),
    }
    kani::cover!(locked.is_ok(), "a key locked");
    kani::cover!(
        locked == Err(Error::RandomUnusable) && sealed.seals == 0,
        "no scalar from the bytes"
    );
    kani::cover!(
        locked == Err(Error::RandomUnusable) && sealed.seals == 1,
        "the payload not sealed"
    );
}

#[kani::proof]
#[kani::solver(kissat)]
fn a_key_is_opened_only_with_the_signature_of_its_round_as_locked() {
    let Some(round) = decimal::proofs::any() else {
        return;
    };
    let body: [u8; BODY_LEN] = kani::any();
    let lock_mac: [u8; MAC_LEN] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();
    let locked: [u8; PAYLOAD_LEN] = kani::any();
    let mut lock = header(&round, &QUICKNET.chain_hash, &body);
    lock.finish(&lock_mac, &nonce, &locked);
    let signature = kani::any();
    let before: [u8; LOCKED_KEY_LEN] = kani::any();
    let mut key = before;
    let opened = QUICKNET.open(lock.as_bytes(), &signature, &mut key);
    let verified = asked();
    let unwrap = unwrapped();
    let mac = made();
    let sealed = payload();
    kani::assert(
        opened.is_ok() || key == before,
        "the key changes only when the lock opens",
    );
    if round.value() == 0 {
        kani::assert(
            opened == Err(Error::InvalidRound) && unwrap.times == 0,
            "round 0 opens nothing",
        );
        return;
    }
    kani::assert(
        verified.times == 1
            && verified.signature == signature
            && verified.message == message(round.value()),
        "the signature is checked for the round of the lock",
    );
    if !verified.answer {
        kani::assert(
            opened == Err(Error::SignatureRejected) && unwrap.times == 0,
            "a signature rejected opens nothing",
        );
        return;
    }
    kani::assert(
        unwrap.times == 1 && unwrap.signature == signature && unwrap.body == body,
        "the file key is decrypted from the lock with the signature",
    );
    let mac_checked = mac.times == 1 && mac.file_key == unwrap.file_key;
    let payload_opened = sealed.opens == 1
        && sealed.file_key == unwrap.file_key
        && sealed.nonce == nonce
        && sealed.payload == locked;
    kani::assert(
        opened.is_err()
            || (mac_checked && mac.mac == lock_mac && payload_opened && key == sealed.key),
        "a key comes only out of a payload under the file key the MAC confirms",
    );
    kani::assert(
        opened.is_ok() || opened == Err(Error::LockRejected),
        "a lock that does not open is rejected",
    );
    kani::cover!(opened.is_ok(), "a key opened");
    kani::cover!(
        opened == Err(Error::LockRejected) && mac.times == 0,
        "the file key not decrypted"
    );
    kani::cover!(
        opened == Err(Error::LockRejected) && mac.times == 1 && sealed.opens == 0,
        "the MAC not confirmed"
    );
    kani::cover!(
        opened == Err(Error::LockRejected) && sealed.opens == 1,
        "the payload not opened"
    );
}

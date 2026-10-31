// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{LOCK_LEN, Lock, MAC_LEN, NONCE_LEN, PAYLOAD_LEN, header, read};
use crate::decimal::{self, DIGITS, Decimal};
use crate::ibe::BODY_LEN;
use crate::network::QUICKNET;

fn written(
    round: &Decimal,
    body: &[u8; BODY_LEN],
    mac: &[u8; MAC_LEN],
    nonce: &[u8; NONCE_LEN],
    payload: &[u8; PAYLOAD_LEN],
) -> Lock {
    let mut lock = header(round, &QUICKNET.chain_hash, body);
    lock.finish(mac, nonce, payload);
    lock
}

#[kani::proof]
fn a_lock_is_read_as_written() {
    let Some(round) = decimal::proofs::any() else {
        return;
    };
    let body: [u8; BODY_LEN] = kani::any();
    let mac: [u8; MAC_LEN] = kani::any();
    let nonce: [u8; NONCE_LEN] = kani::any();
    let payload: [u8; PAYLOAD_LEN] = kani::any();
    let lock = written(&round, &body, &mac, &nonce, &payload);
    let read = read(lock.as_bytes(), &QUICKNET.chain_hash);
    kani::assert(
        read.as_ref().is_ok_and(|parts| {
            parts.round == round
                && parts.body == body
                && parts.mac == mac
                && parts.nonce == nonce
                && parts.payload == payload
        }),
        "a lock is read as written",
    );
    kani::cover!(Decimal::of(0) == Some(round), "a lock of round 0");
    kani::cover!(
        *round.digits() == [b'9'; DIGITS],
        "a lock of the last round"
    );
}

#[kani::proof]
fn only_what_is_written_is_read() {
    let bytes: [u8; LOCK_LEN] = kani::any();
    let Ok(parts) = read(&bytes, &QUICKNET.chain_hash) else {
        return;
    };
    let lock = written(
        &parts.round,
        &parts.body,
        &parts.mac,
        &parts.nonce,
        &parts.payload,
    );
    kani::assert(*lock.as_bytes() == bytes, "only what is written is read");
    kani::cover!(
        *parts.round.digits() == [b'9'; DIGITS],
        "a lock of the last round read"
    );
}

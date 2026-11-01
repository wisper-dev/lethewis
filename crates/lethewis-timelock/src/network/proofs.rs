// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{QUICKNET, SIGNATURE_LEN};
use crate::Error;
use crate::curve::model::{asked, message};

/// When a round is published, worked out in 128-bit numbers, apart from the code.
fn published(round: u64) -> u128 {
    let since = u128::from(round)
        .wrapping_sub(1)
        .wrapping_mul(u128::from(QUICKNET.period));
    since.wrapping_add(u128::from(QUICKNET.genesis))
}

#[kani::proof]
fn a_time_gives_the_first_round_published_then_or_later() {
    let time: u64 = kani::any();
    let found = QUICKNET.round_at_or_after(time);
    match found {
        None => kani::assert(time < QUICKNET.genesis, "no round only before round 1"),
        Some(round) => {
            kani::assert(round >= 1, "rounds start at 1");
            kani::assert(time >= QUICKNET.genesis, "no round before round 1");
            kani::assert(
                published(round) >= u128::from(time),
                "published then or later",
            );
            kani::assert(
                round == 1 || published(round.wrapping_sub(1)) < u128::from(time),
                "the round before is published earlier",
            );
        }
    }
    kani::cover!(found.is_none(), "a time before round 1");
    kani::cover!(
        found.is_some_and(|round| round > 1 && published(round) > u128::from(time)),
        "a time between two rounds"
    );
}

#[kani::proof]
fn a_round_is_published_at_its_time() {
    let round: u64 = kani::any();
    let time = QUICKNET.time_of(round);
    match time {
        None => kani::assert(
            round == 0 || published(round) > u128::from(u64::MAX),
            "no time only for round 0 and past the largest time",
        ),
        Some(time) => {
            kani::assert(round >= 1, "rounds start at 1");
            kani::assert(
                u128::from(time) == published(round),
                "the time of the round",
            );
            kani::assert(
                QUICKNET.round_at_or_after(time) == Some(round),
                "the round of its time",
            );
        }
    }
    kani::cover!(round > 1 && time.is_none(), "a round past the largest time");
    kani::cover!(round > 1 && time.is_some(), "a round with a time");
}

#[kani::proof]
fn a_signature_is_accepted_exactly_when_the_curve_accepts_it_for_the_round() {
    let round: u64 = kani::any();
    let signature: [u8; SIGNATURE_LEN] = kani::any();
    let checked = QUICKNET.verify(round, &signature);
    let asked = asked();
    if round == 0 {
        kani::assert(
            checked == Err(Error::InvalidRound) && asked.times == 0,
            "round 0 is refused before the curve is asked",
        );
    } else {
        kani::assert(asked.times == 1, "the curve is asked once");
        kani::assert(asked.key == QUICKNET.public_key, "with the network's key");
        kani::assert(asked.signature == signature, "with the signature given");
        kani::assert(
            asked.message == message(round),
            "with the message of the round",
        );
        kani::assert(
            checked
                == if asked.answer {
                    Ok(())
                } else {
                    Err(Error::SignatureRejected)
                },
            "as the curve answers",
        );
    }
    kani::cover!(checked.is_ok(), "a signature accepted");
    kani::cover!(
        checked == Err(Error::SignatureRejected),
        "a signature rejected"
    );
}

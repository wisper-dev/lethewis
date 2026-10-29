// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The body of a batch of an archive, sealed in chunks as the chunks of a block are.

use super::data::{OpenChunk, SealChunk};
use crate::{
    block::{CHUNK_LEN, body_data_len_in, body_len_in, chunk_nonce, chunks_in},
    error::Error,
    seal::{self, KEY_LEN as CIPHER_KEY_LEN, TAG_LEN},
};

/// At least twice what archiving or opening a batch uses, chunk buffer included, as tests measure
/// in each build.
#[cfg(all(not(kani), not(lethewis_unoptimised)))]
pub(super) const STACK_WIPE: usize = 163_840;
#[cfg(all(not(kani), lethewis_unoptimised))]
pub(super) const STACK_WIPE: usize = crate::xwing::STACK_WIPE;

pub(super) fn wipe_batch_stack() {
    // The wipe ends in inline assembly, which Kani cannot model.
    #[cfg(not(kani))]
    zeroize::zeroize_stack::<STACK_WIPE>();
}

/// [`Chunks`] in a build outside the proofs and the tests, or a model of it in them.
pub(super) trait SealBatch {
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        aad: &[u8],
        data: &[u8],
        body: &mut [u8],
    ) -> Result<(), Error>;
}

pub(super) trait OpenBatch {
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        aad: &[u8],
        body: &[u8],
        data: &mut [u8],
    ) -> Result<(), Error>;
}

pub(super) struct Chunks;

impl SealBatch for Chunks {
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        aad: &[u8],
        data: &[u8],
        body: &mut [u8],
    ) -> Result<(), Error> {
        seal_batch_in::<CHUNK_LEN>(key, aad, data, body, seal::Aes)
    }
}

impl OpenBatch for Chunks {
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        aad: &[u8],
        body: &[u8],
        data: &mut [u8],
    ) -> Result<(), Error> {
        open_batch_in::<CHUNK_LEN>(key, aad, body, data, seal::Aes)
    }
}

#[cfg(any(test, kani))]
impl<F> SealBatch for F
where
    F: FnMut(&[u8; CIPHER_KEY_LEN], &[u8], &[u8], &mut [u8]) -> Result<(), Error>,
{
    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        aad: &[u8],
        data: &[u8],
        body: &mut [u8],
    ) -> Result<(), Error> {
        self(key, aad, data, body)
    }
}

#[cfg(any(test, kani))]
impl<F> OpenBatch for F
where
    F: FnMut(&[u8; CIPHER_KEY_LEN], &[u8], &[u8], &mut [u8]) -> Result<(), Error>,
{
    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        aad: &[u8],
        body: &[u8],
        data: &mut [u8],
    ) -> Result<(), Error> {
        self(key, aad, body, data)
    }
}

pub(super) fn fits<const C: usize>(data: usize, body: usize) -> Result<(), Error> {
    let len = u64::try_from(data)
        .ok()
        .and_then(body_len_in::<C>)
        .ok_or(Error::WrongLength)?;
    if u64::try_from(body).is_ok_and(|body| body == len) {
        Ok(())
    } else {
        Err(Error::WrongLength)
    }
}

/// Each chunk is sealed in a buffer of this frame, so the data never pass through `body`. A failed
/// seal stops after the chunks before it; the caller wipes the body.
#[inline(never)]
pub(super) fn seal_batch_in<const C: usize>(
    key: &[u8; CIPHER_KEY_LEN],
    aad: &[u8],
    data: &[u8],
    body: &mut [u8],
    mut seal_with: impl SealChunk,
) -> Result<(), Error> {
    fits::<C>(data.len(), body.len())?;
    let mut chunk = [0; C];
    seal_chunks::<C>(key, aad, data, body, &mut chunk, &mut seal_with)
}

fn seal_chunks<const C: usize>(
    key: &[u8; CIPHER_KEY_LEN],
    aad: &[u8],
    mut data: &[u8],
    mut body: &mut [u8],
    chunk: &mut [u8; C],
    seal_with: &mut impl SealChunk,
) -> Result<(), Error> {
    let len = u64::try_from(data.len()).map_err(|_| Error::WrongLength)?;
    let (chunks, _) = chunks_in::<C>(len);
    for index in 0..chunks {
        let last = index.checked_add(1) == Some(chunks);
        let take = if last { data.len() } else { C };
        let (piece, rest) = data.split_at_checked(take).ok_or(Error::WrongLength)?;
        let whole = take.checked_add(TAG_LEN).ok_or(Error::WrongLength)?;
        let (out, after) = core::mem::take(&mut body)
            .split_at_mut_checked(whole)
            .ok_or(Error::WrongLength)?;
        let (sealed, tag) = out.split_at_mut_checked(take).ok_or(Error::WrongLength)?;
        let inner = chunk.get_mut(..take).ok_or(Error::WrongLength)?;
        inner.copy_from_slice(piece);
        let made = seal_with
            .seal(key, &chunk_nonce(index, last), aad, inner)
            .map_err(|_| Error::CipherFailed)?;
        sealed.copy_from_slice(inner);
        tag.copy_from_slice(&made);
        (data, body) = (rest, after);
    }
    Ok(())
}

pub(super) fn holds<const C: usize>(body: usize, data: usize) -> Result<(), Error> {
    let held = u64::try_from(body)
        .ok()
        .and_then(body_data_len_in::<C>)
        .ok_or(Error::RecordRejected)?;
    if u64::try_from(data).is_ok_and(|data| data == held) {
        Ok(())
    } else {
        Err(Error::WrongLength)
    }
}

/// Each chunk is opened in a buffer of this frame and goes into `data` only once it has opened.
/// One that does not open stops the opening after those before it; the caller wipes the data.
#[inline(never)]
pub(super) fn open_batch_in<const C: usize>(
    key: &[u8; CIPHER_KEY_LEN],
    aad: &[u8],
    body: &[u8],
    data: &mut [u8],
    mut open_with: impl OpenChunk,
) -> Result<(), Error> {
    holds::<C>(body.len(), data.len())?;
    let mut chunk = [0; C];
    open_chunks::<C>(key, aad, body, data, &mut chunk, &mut open_with)
}

fn open_chunks<const C: usize>(
    key: &[u8; CIPHER_KEY_LEN],
    aad: &[u8],
    mut body: &[u8],
    mut data: &mut [u8],
    chunk: &mut [u8; C],
    open_with: &mut impl OpenChunk,
) -> Result<(), Error> {
    let len = u64::try_from(data.len()).map_err(|_| Error::WrongLength)?;
    let (chunks, _) = chunks_in::<C>(len);
    for index in 0..chunks {
        let last = index.checked_add(1) == Some(chunks);
        let take = if last { data.len() } else { C };
        let (out, rest) = core::mem::take(&mut data)
            .split_at_mut_checked(take)
            .ok_or(Error::WrongLength)?;
        let (piece, after) = body.split_at_checked(take).ok_or(Error::RecordRejected)?;
        let (tag, after) = after
            .split_first_chunk::<TAG_LEN>()
            .ok_or(Error::RecordRejected)?;
        let inner = chunk.get_mut(..take).ok_or(Error::WrongLength)?;
        inner.copy_from_slice(piece);
        open_with
            .open(key, &chunk_nonce(index, last), aad, inner, tag)
            .map_err(|_| Error::RecordRejected)?;
        out.copy_from_slice(inner);
        (data, body) = (rest, after);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::{fits, holds, open_batch_in, seal_batch_in};
    use crate::block::{body_len_in, chunk_nonce};
    use crate::error::Error;
    use crate::seal::{self, Rejected, SealFailed};

    const KEY: [u8; 32] = [0x3c; 32];
    const AAD: &[u8] = b"lethewis data batch";

    fn data_of(len: usize) -> Vec<u8> {
        (0..len)
            .map(|at| u8::try_from(at % 251).unwrap().wrapping_mul(7))
            .collect()
    }

    fn body_of(data: &[u8]) -> Vec<u8> {
        let len = body_len_in::<16>(u64::try_from(data.len()).unwrap()).unwrap();
        let mut body = vec![0; usize::try_from(len).unwrap()];
        seal_batch_in::<16>(&KEY, AAD, data, &mut body, seal::Aes).unwrap();
        body
    }

    fn opened(body: &[u8], len: usize) -> (Result<(), Error>, Vec<u8>) {
        let mut data = vec![7; len];
        let result = open_batch_in::<16>(&KEY, AAD, body, &mut data, seal::Aes);
        (result, data)
    }

    #[test]
    fn a_body_is_its_chunks_each_followed_by_its_tag() {
        for len in [0, 1, 15, 16, 17, 32, 33, 48] {
            let data = data_of(len);
            let body = body_of(&data);
            let pieces: Vec<&[u8]> = if len == 0 {
                vec![&[]]
            } else {
                data.chunks(16).collect()
            };
            let mut at = 0;
            for (index, piece) in pieces.iter().enumerate() {
                let last = index + 1 == pieces.len();
                let nonce = chunk_nonce(u64::try_from(index).unwrap(), last);
                let mut sealed = piece.to_vec();
                let tag = seal::seal_data(&KEY, &nonce, AAD, &mut sealed).unwrap();
                assert_eq!(body[at..at + piece.len()], sealed[..], "{len}, {index}");
                assert_eq!(body[at + piece.len()..at + piece.len() + 16], tag, "{len}");
                at += piece.len() + 16;
            }
            assert_eq!(at, body.len(), "{len}");
            assert_eq!(opened(&body, len), (Ok(()), data), "{len}");
        }
    }

    #[test]
    fn the_cipher_sees_neither_the_body_nor_the_data() {
        let data = data_of(40);
        let mut body = vec![0; 88];
        let range = body.as_ptr_range();
        let (start, end) = (range.start.addr(), range.end.addr());
        let mut calls = 0;
        let sealing = |key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]| {
            let at = buffer.as_ptr().addr();
            assert!(at < start || at >= end, "the cipher was given the body");
            calls += 1;
            seal::seal_data(key, nonce, aad, buffer)
        };
        seal_batch_in::<16>(&KEY, AAD, &data, &mut body, sealing).unwrap();
        assert_eq!(calls, 3);
        assert_eq!(body, body_of(&data));
        let mut held = vec![0; 40];
        let range = held.as_ptr_range();
        let (start, end) = (range.start.addr(), range.end.addr());
        let mut calls = 0;
        let opening =
            |key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8], tag: &[u8; 16]| {
                let at = buffer.as_ptr().addr();
                assert!(at < start || at >= end, "the cipher was given the data");
                calls += 1;
                seal::open_data(key, nonce, aad, buffer, tag)
            };
        open_batch_in::<16>(&KEY, AAD, &body, &mut held, opening).unwrap();
        assert_eq!(calls, 3);
        assert_eq!(held, data);
    }

    #[test]
    #[expect(
        clippy::integer_division,
        reason = "a test finds the chunk of a changed byte"
    )]
    fn a_changed_body_does_not_open() {
        let data = data_of(40);
        let body = body_of(&data);
        let mut bodies = vec![(body[..64].to_vec(), 32, 1), (body[..32].to_vec(), 16, 0)];
        let mut grown = body[..64].to_vec();
        grown.extend_from_slice(&body[32..]);
        bodies.push((grown, 56, 2));
        let mut swapped = body[32..64].to_vec();
        swapped.extend_from_slice(&body[..32]);
        swapped.extend_from_slice(&body[64..]);
        bodies.push((swapped, 40, 0));
        for at in 0..body.len() {
            let mut changed = body.clone();
            changed[at] ^= 1 << (at % 8);
            bodies.push((changed, 40, at / 32));
        }
        for (changed, len, refused) in &bodies {
            let (result, held) = opened(changed, *len);
            assert_eq!(result, Err(Error::RecordRejected), "{len}");
            let opened_before = (refused * 16).min(*len);
            assert_eq!(held[..opened_before], data[..opened_before], "{len}");
            assert!(held[opened_before..].iter().all(|&byte| byte == 7), "{len}");
        }
        for (key, aad) in [(&[0x3d; 32], AAD), (&KEY, &b"lethewis data batcH"[..])] {
            let mut held = vec![7; 40];
            assert_eq!(
                open_batch_in::<16>(key, aad, &body, &mut held, seal::Aes),
                Err(Error::RecordRejected)
            );
            assert_eq!(held, vec![7; 40]);
        }
    }

    #[test]
    fn buffers_of_other_lengths_are_refused() {
        assert_eq!(fits::<16>(40, 88), Ok(()));
        assert_eq!(fits::<16>(0, 16), Ok(()));
        for (data, body) in [(40, 87), (40, 89), (0, 15), (0, 0), (16, 33)] {
            assert_eq!(fits::<16>(data, body), Err(Error::WrongLength), "{data}");
        }
        assert_eq!(holds::<16>(88, 40), Ok(()));
        assert_eq!(holds::<16>(88, 39), Err(Error::WrongLength));
        for body in [0, 15, 33, 48] {
            assert_eq!(holds::<16>(body, 0), Err(Error::RecordRejected), "{body}");
        }
        let data = data_of(40);
        let mut body = vec![9; 87];
        assert_eq!(
            seal_batch_in::<16>(&KEY, AAD, &data, &mut body, seal::Aes),
            Err(Error::WrongLength)
        );
        assert_eq!(body, vec![9; 87]);
        let sealed = body_of(&data);
        assert_eq!(opened(&sealed, 39), (Err(Error::WrongLength), vec![7; 39]));
        assert_eq!(
            opened(&sealed[..70], 5),
            (Err(Error::RecordRejected), vec![7; 5])
        );
    }

    #[test]
    fn a_failure_on_any_chunk_stops_there() {
        let data = data_of(40);
        let body = body_of(&data);
        for failing in 0..3 {
            let mut calls = 0;
            let sealing = |key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]| {
                calls += 1;
                if calls == failing + 1 {
                    Err(SealFailed)
                } else {
                    seal::seal_data(key, nonce, aad, buffer)
                }
            };
            let mut written = vec![9; 88];
            assert_eq!(
                seal_batch_in::<16>(&KEY, AAD, &data, &mut written, sealing),
                Err(Error::CipherFailed),
                "{failing}"
            );
            assert_eq!(written[..32 * failing], body[..32 * failing], "{failing}");
            assert!(
                written[32 * failing..].iter().all(|&byte| byte == 9),
                "{failing}"
            );
            let mut calls = 0;
            let opening = |key: &[u8; 32],
                           nonce: &[u8; 12],
                           aad: &[u8],
                           buffer: &mut [u8],
                           tag: &[u8; 16]| {
                calls += 1;
                if calls == failing + 1 {
                    Err(Rejected)
                } else {
                    seal::open_data(key, nonce, aad, buffer, tag)
                }
            };
            let mut held = vec![7; 40];
            assert_eq!(
                open_batch_in::<16>(&KEY, AAD, &body, &mut held, opening),
                Err(Error::RecordRejected),
                "{failing}"
            );
            assert_eq!(held[..16 * failing], data[..16 * failing], "{failing}");
            assert!(
                held[16 * failing..].iter().all(|&byte| byte == 7),
                "{failing}"
            );
        }
    }
}

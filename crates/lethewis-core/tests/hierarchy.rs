// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The hierarchy of keys end to end, through the public interface alone: ways in from a password
//! with the chip and from words, a profile key locked under each, keys of chats under the profile
//! key, and a change of epoch that destroys a chat and revokes a way in replaced by another. Each
//! block of slots stands for a run of the application, which keeps between runs only its records,
//! the password parameters, and the number and root of the epoch.

use hkdf::Hkdf;
use lethewis_core::{
    Entropy, EntropyError, Epoch, Erasure, Error, Handle, KeyLength, LOCK_RECORD_LEN, MemoryBlock,
    PasswordParams, Position, Purpose, RECORD_LEN, Root, RootFailed, Slot, Slots, WORD_COUNT,
    WORD_LEN, Words,
};
use sha2::Sha256;
use zeroize::Zeroize;

/// The key that never leaves the chip.
const CHIP: [u8; 32] = [0xc4; 32];
/// The bytes of a passkey, and of the one that replaces it.
const OLD: u8 = 0x5a;
const NEW: u8 = 0xa5;

/// A source that gives other bytes on every call, the same in every run.
struct Source(u64);

impl Entropy for Source {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let [.., top] = self.0.to_le_bytes();
            *byte = top;
        }
        Ok(())
    }
}

/// The platform's root of each epoch: it records each switch and erasure, and erases for certain.
#[derive(Default)]
struct Platform(Vec<(&'static str, u64)>);

impl Root for Platform {
    fn switch(&mut self, next: u64) -> Result<(), RootFailed> {
        self.0.push(("switch", next));
        Ok(())
    }

    fn erase(&mut self, epoch: u64) -> Erasure {
        self.0.push(("erase", epoch));
        Erasure::Guaranteed
    }
}

fn root(epoch: u8) -> [u8; 32] {
    [epoch; 32]
}

fn passkey(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// The chip's answer to a challenge: HMAC-SHA-256 under its key.
fn answer(challenge: &[u8; 32]) -> [u8; 32] {
    Hkdf::<Sha256>::extract(Some(&CHIP), challenge).0.into()
}

/// The way in from `password` and the chip: the key from the password combined with the chip's
/// answer to its challenge.
fn with_the_chip<'a>(
    slots: &mut Slots<'a>,
    password: &[u8],
    params: &PasswordParams,
    working: &mut [MemoryBlock],
) -> Result<Handle<'a>, Error> {
    let key = slots.derive_from_password(&mut password.to_vec(), params, working)?;
    let mut challenge = [0; 32];
    slots.challenge(key, &mut challenge)?;
    let mut answered = answer(&challenge);
    challenge.zeroize();
    let answered = slots.import32(Purpose::Wrap, &mut answered)?;
    slots.combine(key, answered)
}

/// The key of the chat in `record` under `profile`.
fn chat_key<'a>(
    slots: &mut Slots<'a>,
    profile: Handle<'a>,
    context: &[u8],
    record: &[u8; RECORD_LEN],
) -> Result<[u8; 32], Error> {
    let chat = slots.unwrap(profile, context, record)?;
    let mut key = [0; 32];
    slots.reveal32(chat, Position::First, Purpose::ExternalData, &mut key)?;
    slots.release(chat)?;
    Ok(key)
}

#[test]
fn a_profile_opens_with_a_password_and_the_chip_or_with_the_words() {
    let mut source = Source(1);
    let params = PasswordParams::new(65_536, 3, &mut source).unwrap();
    let stored = params.to_bytes();
    let mut working = vec![MemoryBlock::new(); params.memory_blocks()];
    let mut words: Words = [[0; WORD_LEN]; WORD_COUNT];
    let (mut by_password, mut by_words) = ([0; LOCK_RECORD_LEN], [0; LOCK_RECORD_LEN]);
    let mut chat = [0; RECORD_LEN];
    let mut key = [0; 32];
    {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut root(1));
        let password = with_the_chip(&mut slots, b"correct horse", &params, &mut working).unwrap();
        let recovery = slots.generate_words(&mut source, &mut words).unwrap();
        let profile = slots
            .generate(Purpose::Wrap, KeyLength::Bytes64, &mut source)
            .unwrap();
        for (way_in, context, record) in [
            (password, b"password".as_slice(), &mut by_password),
            (recovery, b"words".as_slice(), &mut by_words),
        ] {
            slots
                .lock(profile, way_in, context, &mut source, record)
                .unwrap();
            slots.release(way_in).unwrap();
        }
        let created = slots
            .generate(Purpose::ExternalData, KeyLength::Bytes32, &mut source)
            .unwrap();
        slots
            .wrap(created, profile, b"chat", &mut source, &mut chat)
            .unwrap();
        slots
            .reveal32(created, Position::First, Purpose::ExternalData, &mut key)
            .unwrap();
    }
    {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut root(1));
        let params = PasswordParams::from_bytes(&stored).unwrap();
        let password = with_the_chip(&mut slots, b"correct horse", &params, &mut working).unwrap();
        let profile = slots.unlock(password, b"password", &by_password).unwrap();
        assert_eq!(chat_key(&mut slots, profile, b"chat", &chat), Ok(key));
    }
    let mut memory = [const { Slot::empty() }; 4];
    let mut epoch = Epoch::empty();
    let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut root(1));
    let recovery = slots.derive_from_words(&mut words).unwrap();
    let profile = slots.unlock(recovery, b"words", &by_words).unwrap();
    assert_eq!(chat_key(&mut slots, profile, b"chat", &chat), Ok(key));
}

/// What the application keeps after the first run in epoch 1.
struct Kept {
    words: Words,
    by_words: [u8; LOCK_RECORD_LEN],
    by_old: [u8; LOCK_RECORD_LEN],
    chats: [[u8; RECORD_LEN]; 2],
    keys: [[u8; 32]; 2],
}

/// The first run: a profile key locked under words and under the old passkey, and the keys of two
/// chats under it.
fn first_run(source: &mut Source) -> Result<Kept, Error> {
    let mut kept = Kept {
        words: [[0; WORD_LEN]; WORD_COUNT],
        by_words: [0; LOCK_RECORD_LEN],
        by_old: [0; LOCK_RECORD_LEN],
        chats: [[0; RECORD_LEN]; 2],
        keys: [[0; 32]; 2],
    };
    let mut memory = [const { Slot::empty() }; 4];
    let mut epoch = Epoch::empty();
    let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut root(1));
    let profile = slots.generate(Purpose::Wrap, KeyLength::Bytes32, source)?;
    let recovery = slots.generate_words(source, &mut kept.words)?;
    slots.lock(profile, recovery, b"words", source, &mut kept.by_words)?;
    slots.release(recovery)?;
    let old = slots.import32(Purpose::Wrap, &mut passkey(OLD))?;
    slots.lock(profile, old, b"passkey", source, &mut kept.by_old)?;
    slots.release(old)?;
    for ((context, record), key) in [b"chat 1", b"chat 2"]
        .iter()
        .zip(&mut kept.chats)
        .zip(&mut kept.keys)
    {
        let chat = slots.generate(Purpose::ExternalData, KeyLength::Bytes32, source)?;
        slots.wrap(chat, profile, *context, source, record)?;
        slots.reveal32(chat, Position::First, Purpose::ExternalData, key)?;
        slots.release(chat)?;
    }
    Ok(kept)
}

/// The key of the second chat through the old passkey, in a run of epoch 1 with the root `of`.
fn left_behind(of: u8, kept: &Kept) -> Result<[u8; 32], Error> {
    let mut memory = [const { Slot::empty() }; 4];
    let mut epoch = Epoch::empty();
    let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut root(of));
    let old = slots.import32(Purpose::Wrap, &mut passkey(OLD))?;
    let profile = slots.unlock(old, b"passkey", &kept.by_old)?;
    let [_, destroyed] = &kept.chats;
    chat_key(&mut slots, profile, b"chat 2", destroyed)
}

#[test]
fn a_change_of_epoch_destroys_a_chat_and_revokes_a_replaced_way_in() {
    let mut source = Source(2);
    let kept = first_run(&mut source).unwrap();
    let ([kept_chat, destroyed], [key, destroyed_key]) = (kept.chats, kept.keys);
    let (mut kept_next, mut by_words_next, mut by_new) =
        ([0; RECORD_LEN], [0; LOCK_RECORD_LEN], [0; LOCK_RECORD_LEN]);
    let mut platform = Platform::default();
    {
        let mut memory = [const { Slot::empty() }; 4];
        let mut epoch = Epoch::empty();
        let mut slots = Slots::new(&mut memory, &mut epoch, 1, &mut root(1));
        let old = slots.import32(Purpose::Wrap, &mut passkey(OLD)).unwrap();
        let profile = slots.unlock(old, b"passkey", &kept.by_old).unwrap();
        slots.release(old).unwrap();
        assert_eq!(
            chat_key(&mut slots, profile, b"chat 2", &destroyed),
            Ok(destroyed_key)
        );
        let chat = slots.unwrap(profile, b"chat 1", &kept_chat).unwrap();
        slots.begin_epoch(&mut root(2)).unwrap();
        let new = slots.import32(Purpose::Wrap, &mut passkey(NEW)).unwrap();
        slots
            .lock(profile, new, b"passkey", &mut source, &mut by_new)
            .unwrap();
        slots
            .wrap(chat, profile, b"chat 1", &mut source, &mut kept_next)
            .unwrap();
        slots
            .carry(b"words", &mut source, &kept.by_words, &mut by_words_next)
            .unwrap();
        assert_eq!(slots.commit_epoch(&mut platform), Ok(Erasure::Guaranteed));
    }
    assert_eq!(platform.0, [("switch", 2), ("erase", 1)]);
    let mut memory = [const { Slot::empty() }; 4];
    let mut epoch = Epoch::empty();
    let mut slots = Slots::new(&mut memory, &mut epoch, 2, &mut root(2));
    let old = slots.import32(Purpose::Wrap, &mut passkey(OLD)).unwrap();
    assert_eq!(
        slots.unlock(old, b"passkey", &kept.by_old),
        Err(Error::StaleRecord)
    );
    assert_eq!(
        slots.unlock(old, b"passkey", &by_new),
        Err(Error::RecordRejected)
    );
    slots.release(old).unwrap();
    let new = slots.import32(Purpose::Wrap, &mut passkey(NEW)).unwrap();
    let profile = slots.unlock(new, b"passkey", &by_new).unwrap();
    assert_eq!(
        chat_key(&mut slots, profile, b"chat 1", &kept_next),
        Ok(key)
    );
    for (context, record) in [(b"chat 1", &kept_chat), (b"chat 2", &destroyed)] {
        assert_eq!(
            slots.unwrap(profile, context, record),
            Err(Error::RecordRejected)
        );
    }
    slots.release(profile).unwrap();
    let mut words = kept.words;
    let recovery = slots.derive_from_words(&mut words).unwrap();
    assert_eq!(
        slots.unlock(recovery, b"words", &kept.by_words),
        Err(Error::StaleRecord)
    );
    let profile = slots.unlock(recovery, b"words", &by_words_next).unwrap();
    assert_eq!(
        chat_key(&mut slots, profile, b"chat 1", &kept_next),
        Ok(key)
    );
    assert_eq!(left_behind(2, &kept), Err(Error::StaleRecord));
    assert_eq!(left_behind(1, &kept), Ok(destroyed_key));
}

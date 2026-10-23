// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use core::marker::PhantomData;

use super::{
    ArchivePublic, AssociatedData, CIPHER_KEY_LEN, Direction, END_RECORD_LEN, Entropy,
    EntropyError, Epoch, Erasure, Error, Exporting, Handle, Key, KeyId, KeyLength, Kind, LAYER_LEN,
    LOCK_RECORD_LEN, MEMBERS, NONCE_LEN, Occupancy, Opening, Out, PLAINTEXT_LEN, Position, Purpose,
    RECORD_LEN, Receipt, Receiving, Rejected, Root, RootFailed, SealFailed, Sealing, Slot, Slots,
    Stages, Status, TAG_LEN, opening,
};
use crate::block::{BLOCK_HEADER_LEN, CARRY_LABEL, SALT_LEN, chunks_in, data_len_in};
use crate::derive::{
    Branch,
    model::{any_failed, failed, id_bytes, id_from_bytes, runs},
    proofs::{
        expected_archive_check, expected_archive_data, expected_archive_key,
        expected_archive_layer_key, expected_archive_randomness, expected_archive_seal_key,
        expected_carry_check, expected_carry_chunk, expected_challenge, expected_combined,
        expected_data_check, expected_data_chunk, expected_export_key, expected_hedge,
        expected_key_id, expected_layer_key, expected_lock_key, expected_words_key,
        expected_wrap_key,
    },
};
use crate::keyset::proofs::{allowed, any_purpose, any_whole_stages};
use crate::password::{MemoryBlock, model::argon2_failed, proofs::any_params};
use crate::record::{
    ARCHIVE_KEY_RECORD_LEN, ARCHIVE_LAYER_LEN, ARCHIVE_RECORD_LEN, ARCHIVED_LEN, ID_LEN,
};
use crate::seal;
use crate::words::{
    Words, bits_of,
    proofs::{any_list, expected_words},
};
use crate::xwing::{self, CIPHERTEXT_LEN, PUBLIC_LEN, model::answered as xwing_answered};

/// `seal`, as the stand-in for the cipher it is in the proofs.
fn sealing<F, const N: usize>(seal: F) -> F
where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8; N],
    ) -> Result<[u8; TAG_LEN], SealFailed>,
{
    seal
}

type Bytes = [u8; 64];
type Id = [u8; ID_LEN];
/// One of each position. Keys and identifiers are kept apart rather than in one array: an array
/// of them is compared in one piece, which needs a deeper unwinding than any key.
type Three<T> = (T, T, T);

/// Everything a slot holds. A structure read by field, not a tuple taken apart: Kani 0.68.0
/// reports spurious failures on values taken from a large tuple by a pattern.
#[derive(Clone, Copy, PartialEq)]
struct Snapshot {
    occupancy: Occupancy,
    generation: u64,
    lengths: [KeyLength; MEMBERS],
    keys: Three<Bytes>,
    ids: Three<Id>,
    stages: Stages,
    purpose: Purpose,
    unlocks: bool,
    changed: bool,
    sealed: bool,
    recorded: bool,
    pending: Option<(usize, u64)>,
    chain: [u8; TAG_LEN],
    direction: Direction,
}

fn snapshot(slot: &Slot) -> Snapshot {
    let [first, second, third] = &slot.keys;
    let [first_id, second_id, third_id] = &slot.ids;
    Snapshot {
        occupancy: slot.occupancy,
        generation: slot.generation,
        lengths: [first.length(), second.length(), third.length()],
        keys: (*first.bytes(), *second.bytes(), *third.bytes()),
        ids: (
            *id_bytes(first_id),
            *id_bytes(second_id),
            *id_bytes(third_id),
        ),
        stages: slot.stages,
        purpose: slot.purpose,
        unlocks: slot.unlocks,
        changed: slot.changed,
        sealed: slot.sealed,
        recorded: slot.recorded,
        pending: slot.pending,
        chain: slot.chain,
        direction: slot.direction,
    }
}

// Kani 0.68.0 reports spurious failures when a key buffer is read through a symbolic index, so
// the reads below take every element and then pick one, with no check left behind a branch.

fn slot_at<'s>(slots: &'s Slots<'_>, index: usize) -> &'s Slot {
    let (first, second) = (&slots.memory[0], &slots.memory[1]);
    if index == 0 { first } else { second }
}

fn snapshot_at(before: &[Snapshot; 2], index: usize) -> Snapshot {
    let [first, second] = *before;
    if index == 0 { first } else { second }
}

fn at<T: Copy>(items: &[T; MEMBERS], position: usize) -> T {
    let [first, second, third] = *items;
    match position {
        0 => first,
        1 => second,
        _ => third,
    }
}

fn pick<T: Copy>(items: &Three<T>, position: usize) -> T {
    match position {
        0 => items.0,
        1 => items.1,
        _ => items.2,
    }
}

/// Whether two buffers hold the same bytes, compared in pieces no longer than a key.
fn same<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    same_bytes(a, b)
}

/// The same for two slices of one length.
fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.chunks(64).zip(b.chunks(64)).all(|(x, y)| x == y)
}

fn snapshots(slots: &Slots<'_>) -> [Snapshot; 2] {
    [snapshot(&slots.memory[0]), snapshot(&slots.memory[1])]
}

/// Every slot but `changed` matches its snapshot.
fn unchanged_except(slots: &Slots<'_>, before: &[Snapshot; 2], changed: usize) -> bool {
    (0..2).all(|index| index == changed || snapshot(&slots.memory[index]) == before[index])
}

/// The same, from the snapshots taken after a call: slots read once cost the solver about half
/// of what a read at each check costs.
fn unchanged_but(after: &[Snapshot; 2], before: &[Snapshot; 2], changed: usize) -> bool {
    (0..2).all(|index| index == changed || after[index] == before[index])
}

/// Whether the slot holds no key, no identifier at any position and no state of a transfer.
fn wiped(slot: &Slot) -> bool {
    let now = snapshot(slot);
    now.lengths == [KeyLength::Bytes32; MEMBERS]
        && now.keys == ([0; 64], [0; 64], [0; 64])
        && now.ids == ([0; ID_LEN], [0; ID_LEN], [0; ID_LEN])
        && now.pending.is_none()
        && now.chain == [0; TAG_LEN]
        && now.direction == Direction::Idle
}

fn first_free(before: &[Snapshot; 2]) -> Option<usize> {
    before
        .iter()
        .position(|snapshot| snapshot.occupancy == Occupancy::Free)
}

fn any_length() -> KeyLength {
    if kani::any() {
        KeyLength::Bytes32
    } else {
        KeyLength::Bytes64
    }
}

fn any_key(key: &mut Key) {
    key.fill_any();
}

/// The first `length` bytes of `bytes`, followed by zeros.
fn padded(bytes: Bytes, length: KeyLength) -> Bytes {
    let mut out = bytes;
    if length == KeyLength::Bytes32 {
        out[32..].copy_from_slice(&[0; 32]);
    }
    out
}

/// A slot in any state, for any purpose, with any generation and any stages whose primary is
/// enabled; when loaded, holding a key of a length its purpose takes and any identifier at each
/// position the stages fill, a set of one unless it is for external data or for data, from a secret
/// or stored if it is for wrapping, changed and wrapped for the next epoch or not, and held by a
/// record of this epoch or not. A loaded set for external data or for data came in a transfer or
/// not, under a key of either slot with any generation; a loaded key for transfers has any chain
/// and direction. A free or retired slot keeps the purpose of the set it last held, and holds no
/// state of a transfer. Every load, addition and unwrap keeps a key's length one its purpose takes,
/// every load and unwrap makes a set neither for external data nor for data a set of one, and no
/// change or addition takes one. A receipt marks only the set for external data it loads, and a
/// receipt of a block only the set for data it makes, with the slot of its key; only an export, a
/// receipt and their ends give a key for transfers a chain and a direction; every release clears
/// the state of a transfer. Their proofs show it.
fn any_slot() -> Slot {
    any_slot_in(any_occupancy())
}

fn any_occupancy() -> Occupancy {
    match kani::any::<u8>() % 3 {
        0 => Occupancy::Free,
        1 => Occupancy::Loaded,
        _ => Occupancy::Retired,
    }
}

fn any_slot_in(occupancy: Occupancy) -> Slot {
    let mut slot = Slot::empty();
    slot.generation = kani::any();
    slot.occupancy = occupancy;
    let purpose = any_purpose();
    slot.purpose = purpose;
    slot.stages = if purpose != Purpose::ExternalData
        && purpose != Purpose::Data
        && occupancy == Occupancy::Loaded
    {
        Stages::one()
    } else {
        any_whole_stages()
    };
    slot.unlocks = purpose == Purpose::Wrap && kani::any();
    if slot.occupancy == Occupancy::Loaded {
        slot.changed = kani::any();
        slot.sealed = kani::any();
        slot.recorded = kani::any();
        slot.pending =
            if (purpose == Purpose::ExternalData || purpose == Purpose::Data) && kani::any() {
                Some((if kani::any() { 0 } else { 1 }, kani::any()))
            } else {
                None
            };
        (slot.chain, slot.direction) = if purpose == Purpose::Transfer {
            let direction = if kani::any() {
                Direction::Idle
            } else if kani::any() {
                Direction::Out
            } else {
                Direction::In
            };
            (kani::any(), direction)
        } else {
            ([0; TAG_LEN], Direction::Idle)
        };
        let stages = slot.stages;
        let fill = |position: usize, key: &mut Key, id: &mut KeyId| {
            if stages.stage(position).is_some() {
                any_key(key);
                kani::assume(allowed(purpose, key.length()));
                *id = id_from_bytes(kani::any());
            }
        };
        let [first, second, third] = &mut slot.keys;
        let [first_id, second_id, third_id] = &mut slot.ids;
        fill(0, first, first_id);
        fill(1, second, second_id);
        fill(2, third, third_id);
    }
    slot
}

/// Any epoch with any key and any count of draws, and, if `changing`, with a change to the next
/// under way and any key for it.
fn any_epoch(changing: bool) -> Epoch {
    let mut epoch = Epoch::empty();
    epoch.number = kani::any();
    epoch.key.load32(&mut kani::any());
    if changing {
        epoch.next.load32(&mut kani::any());
    }
    epoch.changing = changing;
    epoch.drawn = kani::any();
    epoch
}

/// The first 32 bytes of `key`.
fn first_half(key: &Key) -> [u8; 32] {
    let mut half = [0; 32];
    half.copy_from_slice(&key.bytes()[..32]);
    half
}

// Three cases by the state of the first slot cover every state; the slot written has a constant
// state on every path, since a write to a slot chosen at run time costs both.

/// `check` with the first slot free, the slot written, and the second in any state.
fn into_the_first<T>(check: impl Fn([Slot; 2]) -> T) -> T {
    check([any_slot_in(Occupancy::Free), any_slot()])
}

/// `check` with the first slot in `first`, and the second free, loaded or retired.
fn past_a<T>(first: Occupancy, check: impl Fn([Slot; 2]) -> T) -> T {
    match kani::any::<u8>() % 3 {
        0 => check([any_slot_in(first), any_slot_in(Occupancy::Free)]),
        1 => check([any_slot_in(first), any_slot_in(Occupancy::Loaded)]),
        _ => check([any_slot_in(first), any_slot_in(Occupancy::Retired)]),
    }
}

/// Whether a loaded slot of `before` holds a key with the identifier `id`.
fn held(before: &[Snapshot; 2], id: &Id) -> bool {
    before.iter().any(|snapshot| {
        snapshot.occupancy == Occupancy::Loaded
            && (0..MEMBERS).any(|position| {
                snapshot.stages.stage(position).is_some() && pick(&snapshot.ids, position) == *id
            })
    })
}

/// Whether a loaded slot of `before` for a purpose other than `purpose` holds a key with the
/// identifier `id`.
fn held_for_another(before: &[Snapshot; 2], id: &Id, purpose: Purpose) -> bool {
    before.iter().any(|snapshot| {
        snapshot.occupancy == Occupancy::Loaded
            && snapshot.purpose != purpose
            && (0..MEMBERS).any(|position| {
                snapshot.stages.stage(position).is_some() && pick(&snapshot.ids, position) == *id
            })
    })
}

/// A platform source that writes any bytes and then either succeeds or fails, as a real one
/// may fail after writing part of its output. It remembers how often and for how many bytes it
/// was asked, how often it answered, and what it wrote.
struct AnyEntropy {
    written: Bytes,
    calls: u8,
    answered: u8,
    requested: usize,
    at: usize,
    failed: bool,
}

impl AnyEntropy {
    fn new() -> Self {
        Self {
            written: [0; 64],
            calls: 0,
            answered: 0,
            requested: 0,
            at: 0,
            failed: false,
        }
    }
}

impl Entropy for AnyEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        self.calls = self.calls.saturating_add(1);
        self.requested = dest.len();
        self.at = dest.as_ptr().addr();
        let bytes: Bytes = kani::any();
        dest.copy_from_slice(&bytes[..dest.len()]);
        self.written[..dest.len()].copy_from_slice(dest);
        self.failed = kani::any();
        if self.failed {
            return Err(EntropyError);
        }
        self.answered = self.answered.saturating_add(1);
        Ok(())
    }
}

fn widen(handle: Handle<'_>) -> Handle<'static> {
    Handle {
        slots: handle.slots,
        index: handle.index,
        generation: handle.generation,
        memory: PhantomData,
    }
}

/// Imports one key of either length with any bytes for `purpose`. Returns the outcome and, on
/// success, the bytes and length the slot must now hold.
fn import_any(
    slots: &mut Slots<'_>,
    purpose: Purpose,
) -> (Result<Handle<'static>, Error>, Bytes, KeyLength) {
    let (result, expected, length) = if kani::any() {
        let mut source: [u8; 32] = kani::any();
        let original = source;
        let result = slots.import32(purpose, &mut source);
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&original);
        kani::assert(
            source == if result.is_ok() { [0; 32] } else { original },
            "an import wipes its source exactly when it succeeds",
        );
        (result, bytes, KeyLength::Bytes32)
    } else {
        let mut source: [u8; 64] = kani::any();
        let original = source;
        let result = slots.import64(purpose, &mut source);
        kani::assert(
            source == if result.is_ok() { [0; 64] } else { original },
            "an import wipes its source exactly when it succeeds",
        );
        (result, original, KeyLength::Bytes64)
    };
    (result.map(widen), expected, length)
}

/// Loads one key by any of the three ways, with any key and length, for `purpose`. Returns the
/// outcome, the bytes and length the slot must hold on success, whether a platform source was
/// asked and failed, and whether the key was imported.
fn load_any(
    slots: &mut Slots<'_>,
    purpose: Purpose,
) -> (Result<Handle<'static>, Error>, Bytes, KeyLength, bool, bool) {
    if kani::any() {
        let (result, expected, length) = import_any(slots, purpose);
        return (result, expected, length, false, true);
    }
    let mut entropy = AnyEntropy::new();
    let length = any_length();
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let result = slots.generate(purpose, length, &mut entropy);
    let unasked = result == Err(Error::NoFreeSlot)
        || result == Err(Error::WrongLength)
        || result == Err(Error::WrongPurpose);
    kani::assert(
        if unasked {
            entropy.calls == 0
        } else {
            entropy.calls == 1 && entropy.requested == length.bytes()
        },
        "a key for transfers, a length the purpose does not take and a full set ask the source \
         for nothing, and otherwise it is asked once, for the length of the key",
    );
    kani::assert(
        unasked || (result == Err(Error::EntropyFailed)) == entropy.failed,
        "a generation fails with EntropyFailed exactly when the source fails",
    );
    kani::assert(
        slots.epoch.drawn
            == if unasked || entropy.failed {
                count
            } else {
                count.wrapping_add(1)
            },
        "a draw the source answers is counted once",
    );
    if let Ok(handle) = result {
        let buffer = slot_at(slots, handle.index).keys[0].bytes().as_ptr().addr();
        kani::assert(
            entropy.at != buffer,
            "the source writes into a buffer of the library's, not into the slot",
        );
    }
    // What the slot must hold: the hedge of what the source wrote, worked out from the model.
    let mut hedged = [0; 64];
    if length == KeyLength::Bytes32 {
        let mut drawn = [0; 32];
        drawn.copy_from_slice(&entropy.written[..32]);
        hedged[..32].copy_from_slice(&expected_hedge(&epoch_key, count, Branch::HedgeKey, &drawn));
    } else {
        hedged = expected_hedge(&epoch_key, count, Branch::HedgeKey, &entropy.written);
    }
    kani::cover!(
        result == Err(Error::EntropyFailed),
        "the platform source fails"
    );
    kani::cover!(
        entropy.failed && entropy.written.iter().any(|&byte| byte != 0),
        "the source fails after writing bytes"
    );
    kani::cover!(
        result.is_ok() && length == KeyLength::Bytes32,
        "a short key is generated"
    );
    kani::cover!(
        result.is_ok() && length == KeyLength::Bytes64,
        "a long key is generated"
    );
    kani::cover!(
        result.is_ok() && slots.epoch.changing,
        "a key is generated during a change of epoch"
    );
    (result.map(widen), hedged, length, entropy.failed, false)
}

/// Whether `handle`, issued for a set whose key at `position` is `expected` of `length`,
/// either still reaches exactly that key in a slot loaded with its generation, or can never be
/// live again: its slot is retired or has moved past its generation, which no call ever moves
/// back.
fn own_key_or_never_again(
    slots: &Slots<'_>,
    handle: &Handle<'_>,
    position: usize,
    expected: &Bytes,
    length: KeyLength,
) -> bool {
    // Read field by field: a whole snapshot of a slot chosen at run time costs a copy of both.
    let slot = slot_at(slots, handle.index);
    let [first, second, third] = &slot.keys;
    let key = match position {
        0 => first,
        1 => second,
        _ => third,
    };
    (slot.occupancy == Occupancy::Loaded
        && slot.generation == handle.generation
        && at(
            &[
                slot.stages.stage(0),
                slot.stages.stage(1),
                slot.stages.stage(2),
            ],
            position,
        )
        .is_some()
        && key.bytes() == expected
        && key.length() == length)
        || slot.occupancy == Occupancy::Retired
        || slot.generation > handle.generation
}

/// The number, keys, state and count of draws of the epoch.
fn epoch_snapshot(slots: &Slots<'_>) -> (u64, [u8; 32], [u8; 32], bool, u64) {
    (
        slots.epoch.number,
        first_half(&slots.epoch.key),
        first_half(&slots.epoch.next),
        slots.epoch.changing,
        slots.epoch.drawn,
    )
}

fn forged(id: usize) -> Handle<'static> {
    Handle {
        slots: id,
        index: kani::any(),
        generation: kani::any(),
        memory: PhantomData,
    }
}

/// A handle of this set naming either slot with any generation, and any position whose key the
/// handle reaches exactly or that can never be live again.
struct Tracked {
    handle: Handle<'static>,
    position: usize,
    expected: Bytes,
    length: KeyLength,
    live: bool,
}

fn live(slots: &Slots<'_>, id: usize, handle: &Handle<'_>) -> bool {
    handle.slots == id && handle.index < 2 && {
        let slot = slot_at(slots, handle.index);
        slot.occupancy == Occupancy::Loaded && slot.generation == handle.generation
    }
}

fn track(slots: &Slots<'_>, id: usize) -> Tracked {
    let handle = Handle {
        slots: id,
        index: if kani::any() { 0 } else { 1 },
        generation: kani::any(),
        memory: PhantomData,
    };
    let position: usize = kani::any();
    kani::assume(position < MEMBERS);
    let expected: Bytes = kani::any();
    let length = any_length();
    kani::assume(own_key_or_never_again(
        slots, &handle, position, &expected, length,
    ));
    let live = live(slots, id, &handle);
    Tracked {
        handle,
        position,
        expected,
        length,
        live,
    }
}

/// After one step: the tracked handle still reaches exactly its own key or can never be live
/// again, and a live one stays live unless it was released.
fn kept(slots: &Slots<'_>, id: usize, tracked: &Tracked, released: bool) {
    kani::assert(
        own_key_or_never_again(
            slots,
            &tracked.handle,
            tracked.position,
            &tracked.expected,
            tracked.length,
        ),
        "a handle reaches exactly its own key or can never be live again",
    );
    kani::assert(
        !tracked.live || released || live(slots, id, &tracked.handle),
        "a live handle stays live until it is released",
    );
    kani::cover!(
        tracked.live && tracked.position == 2,
        "a live handle reaches the key at the last position"
    );
}

/// The step of an import, from `memory`: for any handle of this set and any position whose key
/// the handle reaches exactly or that can never be live again, the import keeps it so, and a
/// live handle stays live; a handle the import issues is a live handle of this set that
/// reaches exactly its own key. Returns whether the import succeeded and whether the handle
/// was live.
fn import_step(mut memory: [Slot; 2]) -> (bool, bool) {
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(false);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let tracked = track(&slots, id);
    let (result, issued, issued_length) = import_any(&mut slots, any_purpose());
    kani::assert(
        match result {
            Ok(handle) => {
                live(&slots, id, &handle)
                    && own_key_or_never_again(&slots, &handle, 0, &issued, issued_length)
            }
            Err(_) => true,
        },
        "a new handle reaches exactly its own key",
    );
    kept(&slots, id, &tracked, false);
    (result.is_ok(), tracked.live)
}

/// The step of an import with the first slot free; with the next two and
/// `a_step_by_a_release`, one step of any sequence of imports and releases from any state of
/// two slots. By induction over the steps, from the moment a handle is issued it reaches
/// exactly its own keys until it is released, and after that every call refuses it, also while
/// its slot holds a new set.
#[kani::proof]
#[kani::unwind(65)]
fn a_step_by_an_import_into_the_first_slot() {
    let (imported, live) = into_the_first(import_step);
    kani::cover!(
        imported && !live,
        "a key is imported beside a released handle"
    );
    kani::cover!(imported && live, "a key is imported beside a live handle");
}

/// The step of an import with the first slot loaded.
#[kani::proof]
#[kani::unwind(65)]
fn a_step_by_an_import_past_a_loaded_slot() {
    let (imported, live) = past_a(Occupancy::Loaded, import_step);
    kani::cover!(
        imported && !live,
        "a key is imported beside a released handle"
    );
    kani::cover!(imported && live, "a key is imported beside a live handle");
}

/// The step of an import with the first slot retired, where no handle is live beside a free
/// slot.
#[kani::proof]
#[kani::unwind(65)]
fn a_step_by_an_import_past_a_retired_slot() {
    let (imported, _) = past_a(Occupancy::Retired, import_step);
    kani::cover!(imported, "a key is imported beside a released handle");
}

/// The step of a release, from any state of two slots: for any handle of this set and any
/// position whose key the handle reaches exactly or that can never be live again, the release
/// keeps it so, and a live handle stays live unless it is the one released; a release of a live
/// handle wipes every key and identifier of its set at once, unless the set has changed in
/// this epoch, and any other is refused.
#[kani::proof]
#[kani::unwind(65)]
fn a_step_by_a_release() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let tracked = track(&slots, id);
    let target = if kani::any() {
        tracked.handle
    } else {
        forged(id)
    };
    let target_live = live(&slots, id, &target);
    let target_changed = target_live && slot_at(&slots, target.index).changed;
    let result = slots.release(target);
    let released =
        target_live && !target_changed && tracked.live && target.index == tracked.handle.index;
    kani::assert(
        if target_changed {
            result == Err(Error::Unsaved)
        } else if target_live {
            result == Ok(()) && wiped(slot_at(&slots, target.index))
        } else {
            result == Err(Error::StaleHandle)
        },
        "a live handle releases its set, whose keys and identifiers are zero at once, unless \
         the set has changed in this epoch, and any other is refused",
    );
    kani::cover!(released, "the tracked set is released");
    kani::cover!(
        !tracked.live
            && !target_live
            && target.index == tracked.handle.index
            && target.generation == tracked.handle.generation
            && slot_at(&slots, tracked.handle.index).occupancy == Occupancy::Loaded,
        "a released handle is refused while its slot holds a new set"
    );
    kept(&slots, id, &tracked, released);
}

/// From any state of two slots, a handle whose set number is not this set's is refused,
/// whatever slot and generation it names, and no slot changes.
#[kani::proof]
#[kani::unwind(65)]
fn a_handle_from_other_slots_is_refused() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(false);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);

    let foreign = Handle {
        slots: kani::any(),
        index: kani::any(),
        generation: kani::any(),
        memory: PhantomData,
    };
    kani::assume(foreign.slots != id);
    kani::cover!(
        foreign.index < 2 && {
            let named = snapshot_at(&before, foreign.index);
            named.occupancy == Occupancy::Loaded && named.generation == foreign.generation
        },
        "the foreign handle names a loaded slot and its generation"
    );

    kani::assert(
        slots.release(foreign) == Err(Error::StaleHandle),
        "a handle from other slots is refused",
    );
    kani::assert(unchanged_except(&slots, &before, 2), "no slot changes");
}

/// A slot in any state and with any generation whose buffers hold keys of any bytes and either
/// length and any identifiers at every position, loaded or not, and changed or not and in a
/// transfer if loaded.
fn any_dirty_slot() -> Slot {
    let mut slot = Slot::empty();
    slot.generation = kani::any();
    slot.occupancy = match kani::any::<u8>() % 3 {
        0 => Occupancy::Free,
        1 => Occupancy::Loaded,
        _ => Occupancy::Retired,
    };
    let [first, second, third] = &mut slot.keys;
    any_key(first);
    any_key(second);
    any_key(third);
    slot.ids = [
        id_from_bytes(kani::any()),
        id_from_bytes(kani::any()),
        id_from_bytes(kani::any()),
    ];
    if slot.occupancy == Occupancy::Loaded {
        slot.changed = kani::any();
        slot.sealed = kani::any();
        slot.recorded = kani::any();
        slot.pending = Some((kani::any(), kani::any()));
        slot.chain = kani::any();
        slot.direction = match kani::any::<u8>() % 3 {
            0 => Direction::Idle,
            1 => Direction::Out,
            _ => Direction::In,
        };
    }
    slot
}

/// From any state of two slots, with any bytes left in any buffer, creating `Slots` wipes every
/// key and identifier, loads no slot and leaves none changed, and takes the epoch and its key.
#[kani::proof]
#[kani::unwind(65)]
fn creating_slots_wipes_every_key() {
    let mut memory = [any_dirty_slot(), any_dirty_slot()];
    kani::cover!(
        memory.iter().all(|slot| slot.occupancy == Occupancy::Loaded
            && slot.keys[2].length() == KeyLength::Bytes64),
        "both slots hold a long key in the last position before"
    );
    kani::cover!(
        memory.iter().any(|slot| {
            slot.occupancy == Occupancy::Free && slot.keys[1].bytes().iter().any(|&byte| byte != 0)
        }),
        "a free slot holds bytes before"
    );
    let epoch = kani::any();
    let mut epoch_key: [u8; 32] = kani::any();
    let original = epoch_key;
    let mut epoch_memory = any_epoch(kani::any());
    epoch_memory.key.fill_any();
    let slots = Slots::new(&mut memory, &mut epoch_memory, epoch, &mut epoch_key);
    kani::assert(
        slots.epoch.number == epoch
            && first_half(&slots.epoch.key) == original
            && slots.epoch.key.bytes()[32..] == [0; 32]
            && slots.epoch.key.length() == KeyLength::Bytes32
            && *slots.epoch.next.bytes() == [0; 64]
            && epoch_key == [0; 32]
            && !slots.epoch.changing,
        "creating slots takes the epoch and its key, wipes the source, and leaves nothing else \
         in the memory of the epoch",
    );
    for slot in slots.memory.iter() {
        kani::assert(
            slot.occupancy != Occupancy::Loaded,
            "creating slots loads no slot",
        );
        kani::assert(
            wiped(slot),
            "creating slots wipes every key and identifier, and every state of a transfer",
        );
        kani::assert(
            !slot.changed && !slot.sealed && !slot.recorded,
            "creating slots leaves no set changed or held by a record",
        );
    }
}

/// Whether a key for `purpose` may come from the caller's bytes, as the documentation of the
/// purposes states it: a key for wrapping, for external data or for transfers. Written apart
/// from the code.
fn takes_bytes(purpose: Purpose) -> bool {
    purpose == Purpose::Wrap || purpose == Purpose::ExternalData || purpose == Purpose::Transfer
}

/// Whether a key for `purpose` may be generated from the platform's source alone, as the
/// documentation of the purposes states it: any but a key for transfers and an archive seed.
/// Written apart from the code.
fn generated_alone(purpose: Purpose) -> bool {
    purpose != Purpose::Transfer && purpose != Purpose::Archive
}

/// Whether a record under a stored key may hold a set for `purpose`, as the documentation of the
/// purposes states it: external data, transfers, the outer layers of an archive and data.
/// Written apart from the code.
fn kept_in_a_record(purpose: Purpose) -> bool {
    purpose == Purpose::ExternalData
        || purpose == Purpose::Transfer
        || purpose == Purpose::ArchiveSeal
        || purpose == Purpose::Data
}

/// Whether a lock record may hold a set for `purpose`, as the documentation of the purposes
/// states it: a stored key for wrapping, or for wrapping the seed of an archive key. Written
/// apart from the code.
fn kept_in_a_lock(purpose: Purpose) -> bool {
    purpose == Purpose::Wrap || purpose == Purpose::ArchiveWrap
}

/// A load by import or from the platform source for any purpose, from `memory`: it takes the
/// first free slot, issues that slot's generation, keeps it in the slot and leaves a set of one
/// there: exactly the expected bytes at the first position, zero past the key's length, enabled
/// and the primary, with the purpose given and the identifier derived from those bytes and
/// their length alone, nothing at the other positions, and no state of a transfer; an import
/// fails with `WrongPurpose` first for a key only the library creates, and a generation for a key
/// for transfers or an archive seed; a load fails with `WrongLength`
/// then for a length the purpose does not take, then with `NoFreeSlot` without a free slot,
/// with `EntropyFailed` when the source fails, with `DerivationFailed` when the derivation
/// fails, and with `DuplicateKey` exactly when a loaded slot holds a key with that identifier,
/// for any purpose; a failed load changes no slot, and neither a refused length nor a full set
/// asks the source; no load panics or overflows. Returns the outcome, and whether a slot for
/// another purpose holds the key.
fn load_from(mut memory: [Slot; 2]) -> (Result<Handle<'static>, Error>, bool) {
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let first_free = first_free(&before);
    let purpose = any_purpose();
    let (result, expected, length, source_failed, imported) = load_any(&mut slots, purpose);
    let id = expected_key_id(&expected, length);
    kani::assert(
        if !(if imported {
            takes_bytes(purpose)
        } else {
            generated_alone(purpose)
        }) {
            result == Err(Error::WrongPurpose)
        } else if !allowed(purpose, length) {
            result == Err(Error::WrongLength)
        } else if first_free.is_none() {
            result == Err(Error::NoFreeSlot)
        } else if source_failed {
            result == Err(Error::EntropyFailed)
        } else if failed() {
            result == Err(Error::DerivationFailed)
        } else if held(&before, &id) {
            result == Err(Error::DuplicateKey)
        } else {
            result.is_ok()
        },
        "an import of a key only the library creates, and a generation of a key for transfers \
         or of the seed of an archive key, fail with WrongPurpose, a load with WrongLength for \
         a length its purpose does not take, then with NoFreeSlot without a free slot, \
         with EntropyFailed when the source fails, with DerivationFailed when the derivation \
         fails, with DuplicateKey when the key is held, and otherwise succeeds",
    );
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "a load fails to derive the identifier"
    );
    kani::cover!(
        result == Err(Error::WrongLength),
        "a key too long for its purpose is refused"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && imported,
        "a key only the library creates is not imported"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && !imported,
        "a key for transfers or an archive seed is not generated"
    );
    if let (Ok(handle), Some(index)) = (result, first_free) {
        let generation = snapshot_at(&before, index).generation;
        kani::assert(
            handle.index == index && handle.generation == generation,
            "a load takes the first free slot and issues its generation",
        );
        let now = snapshot(slot_at(&slots, index));
        kani::assert(
            now.occupancy == Occupancy::Loaded && now.generation == generation,
            "the slot is loaded and keeps its generation",
        );
        kani::assert(
            now.keys == (expected, [0; 64], [0; 64]) && now.lengths[0] == length,
            "the slot holds exactly the key at the first position, zero past its length, and \
             nothing elsewhere",
        );
        kani::assert(
            now.ids == (id, [0; ID_LEN], [0; ID_LEN])
                && now.stages == Stages::one()
                && now.purpose == purpose
                && now.unlocks == (imported && purpose == Purpose::Wrap)
                && now.pending.is_none()
                && now.chain == [0; TAG_LEN]
                && now.direction == Direction::Idle
                && !now.recorded,
            "the slot keeps the purpose, a set of one and the identifier derived from its key, \
             no state of a transfer, and is held by no record; an imported key for wrapping is \
             a key from a secret, a generated one is stored",
        );
        kani::assert(
            unchanged_except(&slots, &before, index),
            "a load changes no other slot",
        );
        kani::cover!(length == KeyLength::Bytes32, "a short key is loaded");
        kani::cover!(length == KeyLength::Bytes64, "a long key is loaded");
        kani::cover!(
            purpose == Purpose::ExternalData,
            "a key for external data is loaded"
        );
        kani::cover!(
            purpose == Purpose::Transfer,
            "a key for transfers is imported"
        );
        kani::cover!(
            purpose == Purpose::ArchiveWrap || purpose == Purpose::ArchiveSeal,
            "a stored key of the archive or a key of a chat for its archive is generated"
        );
        kani::cover!(purpose == Purpose::Data, "a key for data is generated");
    } else {
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a failed load changes no slot",
        );
    }
    (result, held_for_another(&before, &id, purpose))
}

/// A load with the first slot free; with the next two, any state of two slots.
#[kani::proof]
#[kani::unwind(65)]
fn a_load_into_the_first_slot() {
    let (result, elsewhere) = into_the_first(load_from);
    kani::cover!(
        result == Err(Error::DuplicateKey) && elsewhere,
        "a load finds its key held for another purpose"
    );
}

/// A load with the first slot loaded.
#[kani::proof]
#[kani::unwind(65)]
fn a_load_past_a_loaded_slot() {
    let (result, elsewhere) = past_a(Occupancy::Loaded, load_from);
    kani::cover!(
        result == Err(Error::DuplicateKey) && elsewhere,
        "a load finds its key held for another purpose"
    );
    kani::cover!(
        result == Err(Error::DuplicateKey) && !elsewhere,
        "a load finds its key held for its own purpose"
    );
    kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
}

/// A load with the first slot retired, where no key is held beside a free slot.
#[kani::proof]
#[kani::unwind(65)]
fn a_load_past_a_retired_slot() {
    let (result, _) = past_a(Occupancy::Retired, load_from);
    kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
}

/// A derivation from a password, from `memory`, with any parameters within the bounds, any
/// password of up to two bytes and any working memory: an empty password, and memory too small
/// for the parameters, are refused before anything else; a failing Argon2 is `DerivationFailed`,
/// never the failure of a platform source; the password is wiped exactly when the derivation
/// succeeds; a failed derivation changes no slot, and one that succeeds loads the first free
/// slot with a 32-byte key and the identifier derived from it. The rest is the load of a
/// generation, proven above for a source that writes any bytes and may fail.
fn derivation_from(mut memory: [Slot; 2]) -> Result<Handle<'static>, Error> {
    let mut epoch = any_epoch(false);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let params = any_params();
    let mut password: [u8; 2] = kani::any();
    let original = password;
    let length: usize = kani::any();
    kani::assume(length <= 2);
    let mut blocks = [MemoryBlock; 2_097_152];
    let count: usize = kani::any();
    kani::assume(count <= blocks.len());
    let result = slots.derive_from_password(&mut password[..length], &params, &mut blocks[..count]);
    kani::assert(
        if length == 0 {
            result == Err(Error::InvalidPassword)
        } else if count < params.memory_blocks() {
            result == Err(Error::NotEnoughMemory)
        } else {
            result != Err(Error::EntropyFailed)
        },
        "an empty password and too little memory are refused first, and Argon2 never \
         fails as a platform source does",
    );
    kani::assert(
        !argon2_failed() || result == Err(Error::DerivationFailed),
        "a failure of Argon2id is DerivationFailed",
    );
    let wiped: [u8; 2] = core::array::from_fn(|at| if at < length { 0 } else { original[at] });
    kani::assert(
        password == if result.is_ok() { wiped } else { original },
        "the password is wiped exactly when the derivation succeeds",
    );
    if let Ok(handle) = result {
        let now = snapshot(slot_at(&slots, handle.index));
        kani::assert(
            first_free(&before) == Some(handle.index)
                && now.occupancy == Occupancy::Loaded
                && now.lengths[0] == KeyLength::Bytes32
                && now.keys.0[32..] == [0; 32]
                && now.ids.0 == expected_key_id(&now.keys.0, KeyLength::Bytes32)
                && now.stages == Stages::one()
                && now.purpose == Purpose::Wrap
                && now.unlocks
                && !now.recorded,
            "the first free slot holds a 32-byte key from a secret and its identifier, held by \
             no record",
        );
        kani::assert(
            unchanged_except(&slots, &before, handle.index),
            "a derivation changes no other slot",
        );
    } else {
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a failed derivation changes no slot",
        );
    }
    kani::cover!(result.is_ok(), "a key is derived from a password");
    kani::cover!(result == Err(Error::InvalidPassword), "an empty password");
    kani::cover!(result == Err(Error::NotEnoughMemory), "too little memory");
    kani::cover!(argon2_failed(), "Argon2 fails");
    result.map(widen)
}

/// A derivation from a password with the first slot free.
#[kani::proof]
#[kani::unwind(65)]
fn a_derivation_from_a_password_into_the_first_slot() {
    let _ = into_the_first(derivation_from);
}

/// A derivation from a password with the first slot loaded.
#[kani::proof]
#[kani::unwind(65)]
fn a_derivation_from_a_password_past_a_loaded_slot() {
    let result = past_a(Occupancy::Loaded, derivation_from);
    kani::cover!(
        result == Err(Error::DuplicateKey),
        "a derivation finds its key held"
    );
    kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
}

/// A derivation from a password with the first slot retired, where no key is held beside a
/// free slot.
#[kani::proof]
#[kani::unwind(65)]
fn a_derivation_from_a_password_past_a_retired_slot() {
    let result = past_a(Occupancy::Retired, derivation_from);
    kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
}

/// A derivation from any bytes that twelve words stand for, from `memory`, of a key from a
/// secret or a key for transfers: a failure of a derivation is `DerivationFailed`, and nothing
/// else is, never the failure of a platform source; a failed derivation changes no slot, and
/// one that succeeds loads the first free slot with the 32-byte key for that purpose derived
/// from the bytes and the identifier derived from it. The rest is
/// the load of a generation, proven above for a source that writes any bytes and may fail.
fn derivation_from_words(mut memory: [Slot; 2]) -> Result<Handle<'static>, Error> {
    let mut epoch = any_epoch(false);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let bytes: [u8; 16] = kani::any();
    let purpose = if kani::any() {
        Purpose::Wrap
    } else {
        Purpose::Transfer
    };
    let result = slots.derive_into(&bytes, purpose);
    kani::assert(
        (result == Err(Error::DerivationFailed)) == any_failed(),
        "a failure of a derivation is DerivationFailed, and nothing else is",
    );
    if let Ok(handle) = result {
        let now = snapshot(slot_at(&slots, handle.index));
        let key = expected_words_key(&bytes, purpose);
        kani::assert(
            first_free(&before) == Some(handle.index)
                && now.occupancy == Occupancy::Loaded
                && now.lengths[0] == KeyLength::Bytes32
                && now.keys.0[..32] == key
                && now.keys.0[32..] == [0; 32]
                && now.ids.0 == expected_key_id(&now.keys.0, KeyLength::Bytes32)
                && now.stages == Stages::one()
                && now.purpose == purpose
                && now.unlocks == (purpose == Purpose::Wrap)
                && !now.recorded,
            "the first free slot holds the key for the purpose that the bytes derive, from a \
             secret if it is for wrapping, and the identifier derived from it, held by no \
             record",
        );
        kani::assert(
            unchanged_except(&slots, &before, handle.index),
            "a derivation changes no other slot",
        );
    } else {
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a failed derivation changes no slot",
        );
    }
    kani::cover!(result.is_ok(), "a key is derived from words");
    kani::cover!(
        result.is_ok() && purpose == Purpose::Transfer,
        "a key for transfers is derived from words"
    );
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "the derivation fails"
    );
    result.map(widen)
}

/// A derivation from words with the first slot free.
#[kani::proof]
#[kani::unwind(65)]
fn a_derivation_from_words_into_the_first_slot() {
    let _ = into_the_first(derivation_from_words);
}

/// A derivation from words with the first slot loaded.
#[kani::proof]
#[kani::unwind(65)]
fn a_derivation_from_words_past_a_loaded_slot() {
    let result = past_a(Occupancy::Loaded, derivation_from_words);
    kani::cover!(
        result == Err(Error::DuplicateKey),
        "a derivation finds its key held"
    );
    kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
}

/// A derivation from words with the first slot retired.
#[kani::proof]
#[kani::unwind(65)]
fn a_derivation_from_words_past_a_retired_slot() {
    let result = past_a(Occupancy::Retired, derivation_from_words);
    kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
}

/// Whether two sets of words are the same, compared word by word.
fn same_words(a: &Words, b: &Words) -> bool {
    a.iter().zip(b).all(|(x, y)| x == y)
}

/// Any twelve words of any list of three, for either purpose a key from words serves, with the
/// first slot free: words the list refuses
/// change no slot and derive nothing; the words are wiped exactly when the derivation succeeds;
/// a failure of the platform source is never reported; a failed derivation changes no slot.
/// Where the key goes, the derivations from words above prove.
#[kani::proof]
#[kani::unwind(65)]
fn words_are_wiped_exactly_when_their_key_is_derived() {
    into_the_first(|mut memory| {
        let mut epoch = any_epoch(false);
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let list = any_list();
        let mut words: Words = kani::any();
        let original = words;
        let purpose = if kani::any() {
            Purpose::Wrap
        } else {
            Purpose::Transfer
        };
        let result = slots.derive_from_words_in(&list, purpose, &mut words);
        let refused = matches!(result, Err(Error::UnknownWord | Error::InvalidChecksum));
        kani::assert(!refused || !any_failed(), "refused words derive nothing");
        kani::assert(
            result != Err(Error::EntropyFailed),
            "no platform source is asked",
        );
        kani::assert(
            same_words(
                &words,
                &if result.is_ok() {
                    [[0; 8]; 12]
                } else {
                    original
                },
            ),
            "the words are wiped exactly when the derivation succeeds",
        );
        if result.is_ok() {
            let numbers: [u16; 12] = core::array::from_fn(|at| {
                let word = u64::from_le_bytes(original[at]);
                if word == list[1] {
                    1
                } else if word == list[2] {
                    2
                } else {
                    0
                }
            });
            let (read, _) = bits_of(&numbers);
            kani::assert(
                snapshot(&slots.memory[0]).keys.0[..32] == expected_words_key(&read, purpose),
                "the key in the slot is the one the bytes the words stand for derive",
            );
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a failed derivation changes no slot",
            );
        }
        kani::cover!(result.is_ok(), "a key is derived from words");
        kani::cover!(result == Err(Error::UnknownWord), "an unknown word");
        kani::cover!(
            result == Err(Error::InvalidChecksum),
            "a checksum that does not hold"
        );
        kani::cover!(
            result == Err(Error::DuplicateKey),
            "valid words whose key is held"
        );
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "valid words whose derivation fails"
        );
    });
}

/// Generation with any list of three, with the first slot free: the source is asked once for
/// 16 bytes, its failure is `EntropyFailed`, the count of draws grows exactly when it answers,
/// and the words of its bytes hedged with the key of this epoch are written exactly when the key
/// is derived; a failed generation changes neither the words nor any slot. During a change of
/// epoch or not.
#[kani::proof]
#[kani::unwind(65)]
fn words_are_written_exactly_when_their_key_is_generated() {
    into_the_first(|mut memory| {
        let mut epoch = any_epoch(kani::any());
        let mut slots = Slots {
            memory: &mut memory,
            epoch: &mut epoch,
        };
        let before = snapshots(&slots);
        let list = any_list();
        let mut source = AnyEntropy::new();
        let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
        let mut words: Words = kani::any();
        let original = words;
        let result = slots.generate_words_from(&list, &mut source, &mut words);
        kani::assert(
            source.calls == 1 && source.requested == 16,
            "the source is asked once for 16 bytes",
        );
        kani::assert(
            source.failed == (result == Err(Error::EntropyFailed)),
            "a failure of the source is EntropyFailed, and nothing else is",
        );
        kani::assert(
            slots.epoch.drawn == count.wrapping_add(u64::from(!source.failed)),
            "the count of draws grows by one exactly when the source answers",
        );
        let mut drawn = [0; 16];
        drawn.copy_from_slice(&source.written[..16]);
        let bytes = expected_hedge(&epoch_key, count, Branch::HedgeWords, &drawn);
        let expected = if result.is_ok() {
            expected_words(&list, &bytes)
        } else {
            original
        };
        kani::assert(
            same_words(&words, &expected),
            "the words of the hedged bytes are written exactly when the key is derived",
        );
        if result.is_ok() {
            let now = snapshot(&slots.memory[0]);
            kani::assert(
                now.keys.0[..32] == expected_words_key(&bytes, Purpose::Wrap)
                    && now.unlocks
                    && !now.recorded,
                "the key in the slot is the one the hedged bytes derive, a key from a secret \
                 held by no record",
            );
        } else {
            kani::assert(
                unchanged_except(&slots, &before, 2),
                "a failed generation changes no slot",
            );
        }
        kani::cover!(result.is_ok(), "words are generated");
        kani::cover!(
            result.is_ok() && slots.epoch.changing,
            "words are generated during a change of epoch"
        );
        kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
        kani::cover!(
            result == Err(Error::DuplicateKey),
            "the key generated is held"
        );
        kani::cover!(
            result == Err(Error::DerivationFailed),
            "the derivation fails"
        );
    });
}

/// Without a free slot, from `memory`, generation asks nothing of the source and changes
/// neither the words nor any slot.
fn generation_without_a_free_slot(mut memory: [Slot; 2]) {
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let mut source = AnyEntropy::new();
    let mut words: Words = kani::any();
    let original = words;
    let result = slots.generate_words_from(&any_list(), &mut source, &mut words);
    kani::assert(
        result == Err(Error::NoFreeSlot) && source.calls == 0,
        "without a free slot nothing is asked",
    );
    kani::assert(
        same_words(&words, &original) && unchanged_except(&slots, &before, 2),
        "nothing changes",
    );
}

/// The same in each of the four ways two slots can be taken.
#[kani::proof]
#[kani::unwind(65)]
fn no_words_are_generated_without_a_free_slot() {
    let (loaded, retired) = (Occupancy::Loaded, Occupancy::Retired);
    let layout = kani::any::<u8>() % 4;
    match layout {
        0 => generation_without_a_free_slot([any_slot_in(loaded), any_slot_in(loaded)]),
        1 => generation_without_a_free_slot([any_slot_in(loaded), any_slot_in(retired)]),
        2 => generation_without_a_free_slot([any_slot_in(retired), any_slot_in(loaded)]),
        _ => generation_without_a_free_slot([any_slot_in(retired), any_slot_in(retired)]),
    }
    kani::cover!(layout == 3, "both slots retired");
}

/// From any state of two slots and any generation, which includes every state a load leaves: a
/// handle of this set naming any slot and generation releases a set only if that slot is
/// loaded with that generation and unchanged in this epoch, and otherwise is refused and changes
/// nothing; a release wipes
/// every key and identifier of the set and advances the generation by one, or retires the slot
/// when the generation runs out; no release panics or overflows.
#[kani::proof]
#[kani::unwind(65)]
fn a_handle_releases_only_a_matching_loaded_slot() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };

    let handle = forged(id);
    let before = snapshots(&slots);
    kani::cover!(
        before
            .iter()
            .all(|snapshot| snapshot.occupancy == Occupancy::Loaded),
        "both slots hold a set when the handle arrives"
    );
    kani::cover!(
        before[0].occupancy == Occupancy::Free,
        "the first slot is free when the handle arrives"
    );
    let target = Some(handle.index)
        .filter(|&index| index < 2)
        .map(|index| snapshot_at(&before, index))
        .filter(|named| {
            named.occupancy == Occupancy::Loaded && named.generation == handle.generation
        });
    let result = slots.release(handle);
    if target.is_some_and(|named| named.changed) {
        kani::assert(
            result == Err(Error::Unsaved) && unchanged_except(&slots, &before, 2),
            "a set changed in this epoch is not released, and no slot changes",
        );
        kani::cover!(true, "a changed set is kept");
    } else if let Some(named) = target {
        kani::assert(result == Ok(()), "a matching handle releases its set");
        let slot = slot_at(&slots, handle.index);
        kani::assert(
            wiped(slot),
            "a release wipes every key and identifier of the set",
        );
        if named.generation == u64::MAX {
            kani::assert(
                slot.occupancy == Occupancy::Retired,
                "a slot whose generation runs out is retired",
            );
            kani::cover!(true, "a slot is retired when its generation runs out");
        } else {
            kani::assert(
                slot.occupancy == Occupancy::Free
                    && Some(slot.generation) == named.generation.checked_add(1),
                "a release frees the slot and advances the generation by one",
            );
            kani::cover!(true, "a release advances the generation by one");
        }
        kani::assert(
            unchanged_except(&slots, &before, handle.index),
            "a release changes no other slot",
        );
    } else {
        kani::assert(
            result == Err(Error::StaleHandle),
            "any other handle is refused",
        );
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a refused handle changes no slot",
        );
        kani::cover!(
            before
                .iter()
                .any(|snapshot| snapshot.occupancy == Occupancy::Loaded),
            "a handle is refused while a set is loaded"
        );
    }
}

/// From any state of two slots, for a handle of this set naming any slot and generation, any
/// position and any purpose named: revealing writes exactly the 32-byte key at that position
/// into the output when the handle is live, the set and the call both name external data and
/// the position holds an enabled key of a set in no unfinished transfer; otherwise it is
/// refused as `StaleHandle`, `WrongPurpose`, `Unfinished` or `WrongStage`, in that order, and
/// the output is left as it was. No slot changes either way.
#[kani::proof]
#[kani::unwind(65)]
fn only_an_enabled_key_for_external_data_is_revealed() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(false);
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let handle = forged(id);
    let position = any_position();
    let purpose = any_purpose();
    let before = snapshots(&slots);
    let original: [u8; 32] = kani::any();
    let mut out = original;
    let result = slots.reveal32(handle, position, purpose, &mut out);

    let named = snapshot_at(&before, handle.index);
    let at_position = position.index();
    let stage = at(
        &[
            named.stages.stage(0),
            named.stages.stage(1),
            named.stages.stage(2),
        ],
        at_position,
    );
    let expected = if !names_loaded(&before, &handle) {
        Err(Error::StaleHandle)
    } else if purpose != Purpose::ExternalData || named.purpose != purpose {
        Err(Error::WrongPurpose)
    } else if named.pending.is_some() {
        Err(Error::Unfinished)
    } else if stage != Some(Status::Enabled) {
        Err(Error::WrongStage)
    } else {
        Ok(())
    };
    kani::assert(
        result == expected,
        "a reveal succeeds exactly for an enabled key of a live set for external data, named so \
         by the call, and is otherwise refused for the first reason",
    );
    kani::assert(
        if result.is_ok() {
            out[..] == pick(&named.keys, at_position)[..32]
                && at_length(&named.lengths, at_position) == KeyLength::Bytes32
        } else {
            out == original
        },
        "a reveal writes exactly the 32-byte key at the position, or nothing",
    );
    kani::assert(
        unchanged_except(&slots, &before, 2),
        "a reveal changes no slot",
    );
    kani::cover!(result.is_ok(), "a key is revealed");
    kani::cover!(
        result.is_ok() && at_position == 2,
        "the key at the last position is revealed"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && named.purpose == Purpose::Wrap,
        "a key for wrapping is not revealed"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && named.purpose == Purpose::Transfer,
        "a key for transfers is not revealed"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose)
            && named.purpose == Purpose::Data
            && purpose == named.purpose,
        "a key for data is not revealed, even to a call that names it"
    );
    kani::cover!(
        result == Err(Error::Unfinished),
        "a key of an unfinished transfer is not revealed"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && named.purpose == Purpose::ExternalData,
        "a call that does not name external data reveals nothing"
    );
    kani::cover!(
        result == Err(Error::WrongStage) && stage == Some(Status::Disabled),
        "a disabled key is not revealed"
    );
    kani::cover!(
        result == Err(Error::WrongStage) && stage.is_none(),
        "an empty position reveals nothing"
    );
    kani::cover!(
        result == Err(Error::StaleHandle)
            && handle.index < 2
            && named.occupancy == Occupancy::Loaded,
        "a handle of another generation is refused"
    );
}

/// The key at `position` of a set's plaintext, as long as its length byte says, followed by
/// zeros, and its length; read from the layout, not by the parser.
fn plaintext_key(plaintext: &[u8; PLAINTEXT_LEN], position: usize) -> (Bytes, KeyLength) {
    let start = 35 + 66 * position;
    let length = if plaintext[start + 1] == 32 {
        KeyLength::Bytes32
    } else {
        KeyLength::Bytes64
    };
    let key: Bytes = plaintext[start + 2..start + 66].try_into().unwrap();
    (padded(key, length), length)
}

/// Admitting any 233 bytes of plaintext of any kind of record into `memory`: the set it holds
/// goes into the first free slot exactly when a slot is free, the bytes parse, each key's
/// identifier is derived, and no key is held in a loaded slot or twice in the set; then the
/// slot holds, at each position the plaintext fills, exactly the key it holds there with the
/// stage it states and the identifier derived from it, nothing at the others, and the purpose,
/// primary and revision the plaintext states, unchanged in this epoch, a stored set and in no
/// transfer, held by a record exactly when it came from a plain record. From a plain record, a
/// plaintext of another epoch or of a set other than for external data, for transfers, of a
/// chat for its archive or for data is refused as `RecordRejected`; from a lock record, a
/// plaintext of an epoch other than zero or of a set other than a stored key for wrapping or
/// for the archive; from a record of an export, a plaintext of an epoch other than zero or of a
/// set not for external data; from any, a set neither for external data nor for data other than
/// a set of one that has never changed. Otherwise no slot changes, and the failure is
/// `NoFreeSlot`, `RecordRejected`, `DerivationFailed` or `DuplicateKey`, in that order. The
/// offsets are written from the layout, independently of the parser.
fn admit_from(mut memory: [Slot; 2]) {
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let plaintext: [u8; PLAINTEXT_LEN] = kani::any();
    let kind = any_kind();
    let before = snapshots(&slots);
    let first_free = first_free(&before);
    let result = slots.admit(&plaintext, kind);
    kani::assert(
        first_free.is_some()
            || (result == Err(Error::NoFreeSlot) && unchanged_except(&slots, &before, 2)),
        "with no slot free a plaintext is refused as NoFreeSlot and changes no slot",
    );
    // Worked out only when a slot is free, so that the states with none cost the solver
    // nothing.
    let Some(index) = first_free else {
        return;
    };
    let parsed = crate::keyset::parse(&plaintext).map(|(_, stages, _)| stages);
    let mut named_epoch = [0; 8];
    named_epoch.copy_from_slice(&plaintext[19..27]);
    let other_epoch = u64::from_le_bytes(named_epoch)
        != if kind == Kind::Record {
            slots.epoch.number
        } else {
            0
        };
    let members = [0, 1, 2].map(|position| plaintext_key(&plaintext, position));
    let ids = members.map(|(key, length)| expected_key_id(&key, length));
    let filled = [0, 1, 2].map(|position| plaintext[35 + 66 * position] != 0);
    let mut revision = [0; 8];
    revision.copy_from_slice(&plaintext[27..35]);
    let (wrapping, external) = (plaintext[1] == 1, plaintext[1] == 2);
    let staged = external || plaintext[1] == 7;
    let named = match plaintext[1] {
        1 => Some(Purpose::Wrap),
        2 => Some(Purpose::ExternalData),
        3 => Some(Purpose::Transfer),
        4 => Some(Purpose::Archive),
        5 => Some(Purpose::ArchiveWrap),
        6 => Some(Purpose::ArchiveSeal),
        7 => Some(Purpose::Data),
        _ => None,
    };
    let of_kind = named.is_some_and(|purpose| match kind {
        Kind::Record => kept_in_a_record(purpose),
        Kind::Lock => kept_in_a_lock(purpose),
        Kind::Export => purpose == Purpose::ExternalData,
        Kind::ArchiveKey => purpose == Purpose::Archive,
    });
    let one = filled == [true, false, false]
        && plaintext[35] == 1
        && plaintext[2] == 0
        && revision == [0; 8];
    let repeated = (0..MEMBERS).any(|position| {
        at(&filled, position)
            && (held(&before, &at(&ids, position))
                || (0..position)
                    .any(|earlier| at(&filled, earlier) && at(&ids, earlier) == at(&ids, position)))
    });
    kani::assert(
        if parsed.is_err() || other_epoch || !of_kind || (!staged && !one) {
            result == Err(Error::RecordRejected)
        } else if any_failed() {
            result == Err(Error::DerivationFailed)
        } else if repeated {
            result == Err(Error::DuplicateKey)
        } else {
            result.is_ok()
        },
        "a plaintext is admitted exactly when it parses, names its epoch, holds a set of the \
         purposes its kind of record holds, of one key unless for external data or for data, \
         finds a free slot, its keys' identifiers are derived and none is held already or \
         twice",
    );
    if let (Ok(handle), Ok(stages)) = (result, parsed) {
        let now = snapshot(slot_at(&slots, index));
        kani::assert(
            handle.index == index
                && live(&slots, id, &handle)
                && now.generation == snapshot_at(&before, index).generation,
            "the set goes into the first free slot, which keeps its generation, and its handle \
             is live in these slots",
        );
        for position in 0..MEMBERS {
            let (key, length) = at(&members, position);
            let stage = match plaintext[35 + 66 * position] {
                0 => None,
                1 => Some(Status::Enabled),
                _ => Some(Status::Disabled),
            };
            kani::assert(
                now.stages.stage(position) == stage,
                "each position keeps the stage the plaintext states",
            );
            if stage.is_some() {
                kani::assert(
                    pick(&now.keys, position) == key
                        && at(&now.lengths, position) == length
                        && pick(&now.ids, position) == at(&ids, position),
                    "each key is exactly the one the plaintext holds, with its identifier",
                );
            } else {
                kani::assert(
                    pick(&now.keys, position) == [0; 64] && pick(&now.ids, position) == [0; ID_LEN],
                    "an empty position holds nothing",
                );
            }
        }
        kani::assert(
            Some(now.purpose) == named,
            "the slot keeps the purpose the plaintext states",
        );
        let purpose = now.purpose;
        kani::assert(
            now.stages == stages
                && now.stages.primary() == usize::from(plaintext[2])
                && !now.unlocks
                && !now.changed
                && now.recorded == (kind == Kind::Record)
                && now.pending.is_none()
                && now.chain == [0; TAG_LEN]
                && now.direction == Direction::Idle,
            "the slot keeps the primary, the revision and the purpose the plaintext states, a \
             stored set, unchanged in this epoch and in no transfer, held by a record exactly \
             when it came from a record of this epoch",
        );
        kani::assert(
            unchanged_except(&slots, &before, index),
            "admitting changes no other slot",
        );
        kani::cover!(
            filled == [true, true, true] && plaintext[35] == 2,
            "a full set with a disabled key is admitted"
        );
        kani::cover!(
            purpose == Purpose::ExternalData,
            "a set of external data is admitted"
        );
        kani::cover!(purpose == Purpose::Wrap, "a set for wrapping is admitted");
        kani::cover!(
            purpose == Purpose::Transfer,
            "a key for transfers is admitted"
        );
        kani::cover!(
            kind == Kind::Export,
            "a set of external data is admitted from an export"
        );
        kani::cover!(
            purpose == Purpose::ArchiveSeal,
            "a key of a chat for its archive is admitted"
        );
        kani::cover!(
            purpose == Purpose::ArchiveWrap,
            "a stored key of the archive is admitted"
        );
        kani::cover!(
            purpose == Purpose::Data && filled == [true, true, true],
            "a full set for data is admitted"
        );
    } else {
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a refused plaintext changes no slot",
        );
    }
    kani::cover!(parsed.is_err(), "a malformed plaintext is refused");
    kani::cover!(
        parsed.is_ok() && other_epoch,
        "a plaintext of another epoch is refused"
    );
    kani::cover!(
        parsed.is_ok() && !other_epoch && wrapping && !one && filled == [true, false, false],
        "a set for wrapping that has changed is refused"
    );
    kani::cover!(
        parsed.is_ok() && !other_epoch && kind == Kind::Export && !external,
        "an export of a set not for external data is refused"
    );
    kani::cover!(
        parsed.is_ok() && !other_epoch && named == Some(Purpose::Archive),
        "an archive seed is refused by every record of a set"
    );
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "an identifier is not derived"
    );
    kani::cover!(
        result == Err(Error::DuplicateKey) && filled[1] && ids[0] == ids[1],
        "a set that holds one key twice is refused"
    );
}

/// Admitting with the first slot free; with the next two, any state of two slots.
#[kani::proof]
#[kani::unwind(65)]
fn admitting_into_the_first_slot() {
    into_the_first(admit_from);
}

/// Admitting with the first slot loaded.
#[kani::proof]
#[kani::unwind(65)]
fn admitting_past_a_loaded_slot() {
    past_a(Occupancy::Loaded, admit_from);
}

/// Admitting with the first slot retired.
#[kani::proof]
#[kani::unwind(65)]
fn admitting_past_a_retired_slot() {
    past_a(Occupancy::Retired, admit_from);
}

/// Stands in for the cipher of `N` bytes: writes any bytes, accepts or rejects at will or as it is
/// told, and remembers how often it was called, and the key and nonce it was given, what it wrote
/// and whether it accepted.
struct AnyCipher<const N: usize> {
    answer: Option<bool>,
    calls: usize,
    aad: Bound,
    key: [u8; CIPHER_KEY_LEN],
    nonce: [u8; NONCE_LEN],
    given: [u8; N],
    tag: [u8; TAG_LEN],
    written: [u8; N],
    accepted: bool,
}

impl<const N: usize> AnyCipher<N> {
    fn new() -> Self {
        Self {
            answer: None,
            calls: 0,
            aad: Bound::none(),
            key: [0; CIPHER_KEY_LEN],
            nonce: [0; NONCE_LEN],
            given: [0; N],
            tag: [0; TAG_LEN],
            written: [0; N],
            accepted: false,
        }
    }

    /// One that accepts every record when `answer` is true and rejects every one otherwise.
    fn answering(answer: bool) -> Self {
        Self {
            answer: Some(answer),
            ..Self::new()
        }
    }

    /// Opens as [`AnyCipher::open`] does, and keeps the associated data it was given.
    fn open_bound(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8; N],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        self.aad = Bound::of(aad);
        self.open(key, nonce, buffer, tag)
    }

    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        buffer: &mut [u8; N],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        let written: [u8; N] = kani::any();
        let accepted = self.answer.unwrap_or_else(kani::any);
        (self.given, self.tag) = (*buffer, *tag);
        *buffer = written;
        (self.key, self.nonce, self.written, self.accepted) = (*key, *nonce, written, accepted);
        self.calls = self.calls.saturating_add(1);
        if accepted { Ok(()) } else { Err(Rejected) }
    }
}

/// For a loaded set in any state of the purpose records of any kind are wrapped under, any
/// 261-byte record, any associated data of up to two bytes and any behaviour of the cipher its
/// interface allows: opening tries the key of the set, once, with the cipher key derived from
/// it and the key of this epoch, or from it alone for a lock record, a record of an export and
/// the seed of an archive key, each kind with a derivation of its own, and not at all when that
/// derivation fails,
/// which is `DerivationFailed`; it leaves in the output the plaintext the cipher wrote when the
/// cipher accepts it and it names that key's identifier as its parent, and otherwise fails with
/// `RecordRejected` and leaves the output as it was.
#[kani::proof]
#[kani::unwind(65)]
fn opening_uses_the_key_of_the_parent() {
    let mut memory = [any_slot_in(Occupancy::Loaded)];
    let kind = any_kind();
    kani::assume(memory[0].purpose == kind.parent_purpose());
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let record: [u8; RECORD_LEN] = kani::any();
    let aad: [u8; 2] = kani::any();
    let before = snapshot(&slots.memory[0]);
    let epoch_key = first_half(&slots.epoch.key);
    let mut cipher = AnyCipher::<PLAINTEXT_LEN>::new();
    let original: [u8; PLAINTEXT_LEN] = kani::any();
    let mut found = original;

    let result = slots.open_under(
        0,
        &aad,
        &record,
        &mut found,
        &mut opening(|key, nonce, _, buffer, tag| cipher.open(key, nonce, buffer, tag)),
        kind,
    );
    kani::assert(
        cipher.calls == usize::from(!any_failed()),
        "the key is tried once, unless its derivation fails",
    );
    let expected = match kind {
        Kind::Record => expected_wrap_key(&before.keys.0, before.lengths[0], &epoch_key),
        Kind::Lock => expected_lock_key(&before.keys.0, before.lengths[0]),
        Kind::Export | Kind::ArchiveKey => {
            let mut key = [0; 32];
            key.copy_from_slice(&before.keys.0[..32]);
            if kind == Kind::Export {
                expected_export_key(&key)
            } else {
                expected_archive_key(&key)
            }
        }
    };
    kani::assert(
        any_failed() || (cipher.key == expected && cipher.nonce[..] == record[..NONCE_LEN]),
        "the trial uses the cipher key derived from the key, and the record's nonce",
    );
    let named = cipher.accepted && cipher.written[3..19] == before.ids.0;
    kani::assert(
        if any_failed() {
            result == Err(Error::DerivationFailed) && same(&found, &original)
        } else if named {
            result == Ok(()) && same(&found, &cipher.written)
        } else {
            result == Err(Error::RecordRejected) && same(&found, &original)
        },
        "opening keeps the plaintext exactly when the cipher accepts it and it names the key, \
         and otherwise leaves the output as it was",
    );
    kani::cover!(
        result.is_ok() && kind == Kind::Lock,
        "the key from a secret opens the record"
    );
    kani::cover!(
        result.is_ok() && kind == Kind::Record,
        "the stored key opens the record"
    );
    kani::cover!(
        result.is_ok() && kind == Kind::Export,
        "the key for transfers opens the record"
    );
    kani::cover!(
        result.is_ok() && kind == Kind::ArchiveKey,
        "the stored key of the archive opens the seed"
    );
    kani::cover!(
        result == Err(Error::RecordRejected) && cipher.accepted,
        "the key opens the record but is not named in it"
    );
}

/// Any kind of record.
fn any_kind() -> Kind {
    match kani::any::<u8>() % 4 {
        0 => Kind::Record,
        1 => Kind::Lock,
        2 => Kind::Export,
        _ => Kind::ArchiveKey,
    }
}

/// Any context of up to two bytes.
fn any_context(bytes: &[u8; 2]) -> &[u8] {
    let length: usize = kani::any();
    kani::assume(length <= 2);
    &bytes[..length]
}

/// Whether `handle` names a loaded slot with its generation, read from the snapshots.
fn names_loaded(before: &[Snapshot; 2], handle: &Handle<'_>) -> bool {
    handle.index < 2 && {
        let named = snapshot_at(before, handle.index);
        named.occupancy == Occupancy::Loaded && named.generation == handle.generation
    }
}

/// Unwrapping, unlocking or receiving in `memory`, for a handle of this set naming any slot and
/// generation, any record or lock record and any context of up to two bytes, whatever the
/// cipher does: an empty context, a stale parent, a parent not of the purpose the kind of
/// record is wrapped under, one of the other level and a full set are refused, in that order,
/// and then a key for transfers that writes an export, before anything is decrypted. An unlock
/// opens the outer layer once, under the key derived
/// from the key of this epoch, and refuses it as `StaleRecord`, decrypting nothing more, unless
/// the cipher accepts it and it names this epoch; the inner record it then opens is the one the
/// outer layer holds. A refused call changes no slot, and one that succeeds needs every trial
/// the cipher accepts and every derivation to succeed, and changes only the first free slot,
/// and, for a receipt, the key for transfers, which takes the tag of the record as its chain and
/// the direction of receipts; the set received waits for the end of that key's export, by its
/// slot and generation, and is otherwise in no transfer, unchanged and stored. What
/// the trial of the parent's key gives, `opening_uses_the_key_of_the_parent` proves. A receipt
/// when `receipt` says so, and otherwise an unwrap or an unlock: the kinds apart cost the
/// solver less than together. Returns the outcome, the kind of record and the purpose of the
/// parent.
fn unwrap_from(mut memory: [Slot; 2], receipt: bool) -> (Result<(), Error>, Kind, Purpose) {
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let parent = forged(id);
    let kind = if receipt {
        Kind::Export
    } else if kani::any() {
        Kind::Lock
    } else {
        Kind::Record
    };
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let before = snapshots(&slots);
    let parent_live = names_loaded(&before, &parent);
    let named = snapshot_at(&before, parent.index);
    let wanted = if receipt {
        Purpose::Transfer
    } else {
        Purpose::Wrap
    };
    let serving = parent_live && named.purpose == wanted;
    let level = serving && named.unlocks == (kind == Kind::Lock);
    let first_free = first_free(&before);
    let turned = receipt && named.direction == Direction::Out;
    let (epoch_key, number) = (first_half(&slots.epoch.key), slots.epoch.number);
    let mut layer = AnyCipher::<LAYER_LEN>::new();
    let mut cipher = AnyCipher::<PLAINTEXT_LEN>::new();
    let record: [u8; RECORD_LEN] = kani::any();

    let result = if kind == Kind::Lock {
        let record: [u8; LOCK_RECORD_LEN] = kani::any();
        slots.unlock_on_stack(
            parent,
            context,
            &record,
            opening(|key, nonce, aad, buffer, tag| layer.open_bound(key, nonce, aad, buffer, tag)),
            opening(|key, nonce, aad, buffer, tag| cipher.open_bound(key, nonce, aad, buffer, tag)),
        )
    } else if kind == Kind::Record {
        slots.unwrap_on_stack(
            parent,
            context,
            &record,
            opening(|key, nonce, aad, buffer, tag| cipher.open_bound(key, nonce, aad, buffer, tag)),
        )
    } else {
        slots.receive_on_stack(
            parent,
            context,
            &record,
            opening(|key, nonce, aad, buffer, tag| cipher.open_bound(key, nonce, aad, buffer, tag)),
        )
    };
    let lock = kind == Kind::Lock;
    // Worked out on every path, so that no proof of one kind leaves a check of another unreached.
    let mut tag = [0; TAG_LEN];
    tag.copy_from_slice(&record[NONCE_LEN + PLAINTEXT_LEN..]);
    let refused_before = context.is_empty() || !level || first_free.is_none() || turned;
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext)
        } else if !parent_live {
            result == Err(Error::StaleHandle)
        } else if !serving {
            result == Err(Error::WrongPurpose)
        } else if !level {
            result == Err(Error::WrongLevel)
        } else if first_free.is_none() {
            result == Err(Error::NoFreeSlot)
        } else if turned {
            result == Err(Error::Unfinished)
        } else {
            true
        },
        "an unwrap, an unlock and a receipt refuse a bad context, a stale parent, a parent not \
         of the purpose they take, a parent of the other level and a full set, and a receipt a \
         key for transfers that writes an export",
    );
    kani::assert(
        !refused_before || (cipher.calls == 0 && layer.calls == 0),
        "those refusals come before any decryption",
    );
    let (in_a_record, in_an_export) = (
        Bound::to(context),
        Bound::chained(b"lethewis key export", &named.chain, context),
    );
    let bound = if receipt { in_an_export } else { in_a_record };
    kani::assert(
        (cipher.calls == 0 || cipher.aad == bound)
            && (layer.calls == 0 || layer.aad == Bound::to(context)),
        "a record is opened bound to its context, a record of an export also to the chain of \
         its key",
    );
    let current = layer.accepted && layer.written[..8] == number.to_le_bytes();
    let layer_key = expected_layer_key(&epoch_key);
    let mut inner = [0; RECORD_LEN];
    inner.copy_from_slice(&layer.written[8..]);
    let held = cipher.nonce[..] == inner[..NONCE_LEN]
        && same_bytes(&cipher.given, &inner[NONCE_LEN..NONCE_LEN + PLAINTEXT_LEN])
        && cipher.tag[..] == inner[NONCE_LEN + PLAINTEXT_LEN..];
    kani::assert(
        !lock
            || refused_before
            || (any_failed()
                && layer.calls == 0
                && cipher.calls == 0
                && result == Err(Error::DerivationFailed))
            || (layer.calls == 1
                && layer.key == layer_key
                && (current || (result == Err(Error::StaleRecord) && cipher.calls == 0))),
        "an unlock opens the outer layer once, under the key of this epoch, and refuses it as \
         StaleRecord, decrypting nothing more, unless it opens and names this epoch",
    );
    kani::assert(
        !lock || cipher.calls == 0 || held,
        "the inner record is the one the outer layer holds: its nonce, encrypted part and tag",
    );
    kani::assert(
        result.is_err() || (cipher.accepted && !any_failed() && (!lock || current)),
        "a set is loaded only after the trials the cipher accepts and when every derivation \
         succeeds",
    );
    kani::assert(
        refused_before || !any_failed() || result == Err(Error::DerivationFailed),
        "a call that a derivation fails fails with DerivationFailed",
    );
    let after = snapshots(&slots);
    kani::assert(
        match (result, first_free) {
            (Ok(handle), Some(index)) => {
                let received = snapshot_at(&after, index);
                handle.index == index
                    && handle.slots == id
                    && handle.generation == snapshot_at(&before, index).generation
                    && if kind == Kind::Export {
                        // The parent is loaded, so it is the slot other than the first free one:
                        // read by a known index, a slot costs the solver one copy, not two.
                        let other = if index == 0 { 1 } else { 0 };
                        let mut chained = snapshot_at(&before, other);
                        chained.chain = tag;
                        chained.direction = Direction::In;
                        parent.index == other
                            && received.pending == Some((other, parent.generation))
                            && received.chain == [0; TAG_LEN]
                            && received.direction == Direction::Idle
                            && !received.changed
                            && !received.sealed
                            && !received.recorded
                            && !received.unlocks
                            && snapshot_at(&after, other) == chained
                    } else {
                        unchanged_but(&after, &before, index)
                    }
            }
            _ => result.is_err() && unchanged_but(&after, &before, 2),
        },
        "a refused call changes no slot, and one that succeeds only the first free slot, whose \
         handle names these slots and that slot's generation, and for a receipt the chain and \
         direction of the key for transfers; the set received waits for that key's export to \
         end, and is otherwise in no transfer, unchanged and stored",
    );
    (result.map(|_| ()), kind, named.purpose)
}

/// The outcomes of an unwrap or an unlock that decrypts, and the refusals of a parent.
fn every_outcome((result, kind, parent): (Result<(), Error>, Kind, Purpose)) {
    kani::cover!(
        result.is_ok() && kind == Kind::Record,
        "a record is unwrapped"
    );
    kani::cover!(
        result.is_ok() && kind == Kind::Lock,
        "a lock record is unlocked"
    );
    kani::cover!(result == Err(Error::RecordRejected), "a record is rejected");
    kani::cover!(
        result == Err(Error::StaleRecord),
        "a lock record not of this epoch is refused"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && parent == Purpose::Transfer,
        "a key for transfers unwraps nothing"
    );
    kani::cover!(
        result == Err(Error::WrongLevel) && kind == Kind::Lock,
        "a stored key unlocks nothing"
    );
    kani::cover!(
        result == Err(Error::WrongLevel) && kind == Kind::Record,
        "a key from a secret unwraps nothing"
    );
}

/// The outcomes of a receipt that decrypts, and the refusal of a key not for transfers.
fn every_receipt((result, _, parent): (Result<(), Error>, Kind, Purpose)) {
    kani::cover!(result.is_ok(), "a record of an export is received");
    kani::cover!(result == Err(Error::RecordRejected), "a record is rejected");
    kani::cover!(
        result == Err(Error::WrongPurpose) && parent == Purpose::Wrap,
        "a key for wrapping receives nothing"
    );
    kani::cover!(
        result == Err(Error::Unfinished),
        "a key that writes an export receives nothing"
    );
}

/// Unwrapping with the first slot free; with the next two, any state of two slots.
#[kani::proof]
#[kani::unwind(65)]
fn an_unwrap_into_the_first_slot() {
    every_outcome(into_the_first(|memory| unwrap_from(memory, false)));
}

/// Unwrapping with the first slot loaded.
#[kani::proof]
#[kani::unwind(65)]
fn an_unwrap_past_a_loaded_slot() {
    every_outcome(past_a(Occupancy::Loaded, |memory| {
        unwrap_from(memory, false)
    }));
}

/// Unwrapping with the first slot retired, where a live parent leaves no slot free, so nothing
/// is decrypted.
#[kani::proof]
#[kani::unwind(65)]
fn an_unwrap_past_a_retired_slot() {
    let (result, _, _) = past_a(Occupancy::Retired, |memory| unwrap_from(memory, false));
    kani::cover!(
        result == Err(Error::NoFreeSlot),
        "a live parent leaves no slot free"
    );
}

/// Receiving with the first slot free; with the next two, any state of two slots.
#[kani::proof]
#[kani::unwind(65)]
fn a_receipt_into_the_first_slot() {
    every_receipt(into_the_first(|memory| unwrap_from(memory, true)));
}

/// Receiving with the first slot loaded.
#[kani::proof]
#[kani::unwind(65)]
fn a_receipt_past_a_loaded_slot() {
    every_receipt(past_a(Occupancy::Loaded, |memory| {
        unwrap_from(memory, true)
    }));
}

/// Receiving with the first slot retired, where a live key for transfers leaves no slot free.
#[kani::proof]
#[kani::unwind(65)]
fn a_receipt_past_a_retired_slot() {
    let (result, _, _) = past_a(Occupancy::Retired, |memory| unwrap_from(memory, true));
    kani::cover!(
        result == Err(Error::NoFreeSlot),
        "a live key for transfers leaves no slot free"
    );
}

/// From any state of two slots and of the epoch, with a change to the next under way or not,
/// for handles of this set naming any slots and generations, any context of up to two bytes and
/// any record buffer, whatever the platform's source and the cipher do: a wrap, a lock or an
/// export, as `kind` says, changes no key, stage or epoch; a wrap or a lock marks the set
/// wrapped for the next epoch only when it succeeds during a change, a wrap marks it held by a
/// record of this epoch when it succeeds outside one, and an export marks nothing and gives the
/// key for transfers the tag of the record it writes as its chain and the direction of exports;
/// each writes the record only when it succeeds, starting with the nonce the source gave last,
/// hedged at its count with the key the record is wrapped in, or for an export the key of this
/// epoch; it refuses an empty context, a stale handle, a set wrapped under itself, a parent not
/// of the purpose the kind takes, a set or a parent of the wrong level, a set of a transfer
/// that has not ended or an export under a key that receives one, a set changed in this epoch
/// outside a change unless it is exported, and a failed source. Each draw the source answers is
/// counted once. Returns the outcome, the set as it was, and whether a change of epoch was
/// under way.
fn wrap_from(kind: Kind) -> (Result<(), Error>, Snapshot, bool) {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch = slots.epoch.number;
    let (set, parent) = (forged(id), forged(id));
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let original: [u8; LOCK_RECORD_LEN] = kani::any();
    let mut record = original;
    let mut entropy = AnyEntropy::new();
    let before = snapshots(&slots);
    let live = names_loaded(&before, &set) && names_loaded(&before, &parent);
    let (child, wrapping) = (
        snapshot_at(&before, set.index),
        snapshot_at(&before, parent.index),
    );

    let (epoch_key, next_key) = (*slots.epoch.key.bytes(), *slots.epoch.next.bytes());
    let count = slots.epoch.drawn;
    let result = if kind == Kind::Lock {
        slots.wrap_on_stack(set, parent, context, &mut entropy, Out::Lock(&mut record))
    } else {
        let mut plain: [u8; RECORD_LEN] = original[..RECORD_LEN].try_into().unwrap();
        let out = if kind == Kind::Record {
            Out::Record(&mut plain)
        } else {
            Out::Export(&mut plain)
        };
        let result = slots.wrap_on_stack(set, parent, context, &mut entropy, out);
        record[..RECORD_LEN].copy_from_slice(&plain);
        result
    };
    let in_epoch = kind != Kind::Export;
    let sealing = result.is_ok() && changing && in_epoch;
    let recording = result.is_ok() && !changing && kind == Kind::Record;
    let mut chained = wrapping;
    chained
        .chain
        .copy_from_slice(&record[NONCE_LEN + PLAINTEXT_LEN..RECORD_LEN]);
    chained.direction = Direction::Out;
    let mut held = child;
    held.recorded = true;
    let after = snapshots(&slots);
    kani::assert(
        if sealing {
            unchanged_but(&after, &before, set.index)
                && snapshot_at(&after, set.index) == marked(child, child.changed, true)
        } else if recording {
            unchanged_but(&after, &before, set.index) && snapshot_at(&after, set.index) == held
        } else if result.is_ok() && !in_epoch {
            unchanged_but(&after, &before, parent.index)
                && snapshot_at(&after, parent.index) == chained
        } else {
            unchanged_but(&after, &before, 2)
        },
        "a wrap changes no key or stage, a wrap or a lock marks the set wrapped for the next \
         epoch only when it succeeds during a change, a wrap outside one marks the set held by \
         a record of this epoch, and an export marks nothing and gives the chain of its key \
         the tag of its record",
    );
    kani::assert(
        slots.epoch.number == epoch
            && slots.epoch.changing == changing
            && *slots.epoch.key.bytes() == epoch_key
            && *slots.epoch.next.bytes() == next_key,
        "a wrap changes no epoch and no key of one",
    );
    kani::assert(
        slots.epoch.drawn == count.wrapping_add(u64::from(entropy.answered)),
        "a draw the source answers is counted once",
    );
    let lock = kind == Kind::Lock;
    let parent_purpose = if in_epoch {
        Purpose::Wrap
    } else {
        Purpose::Transfer
    };
    let level = if in_epoch {
        !child.unlocks
            && if lock {
                kept_in_a_lock(child.purpose)
            } else {
                kept_in_a_record(child.purpose)
            }
            && wrapping.unlocks == lock
    } else {
        child.purpose == Purpose::ExternalData
    };
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext)
        } else if !live {
            result == Err(Error::StaleHandle)
        } else if set.index == parent.index {
            result == Err(Error::SameKey)
        } else if wrapping.purpose != parent_purpose {
            result == Err(Error::WrongPurpose)
        } else if !level {
            result == Err(Error::WrongLevel)
        } else if child.pending.is_some() || (!in_epoch && wrapping.direction == Direction::In) {
            result == Err(Error::Unfinished)
        } else if in_epoch && child.changed && !changing {
            result == Err(Error::Unsaved)
        } else if in_epoch && changing && epoch == u64::MAX {
            result == Err(Error::EpochExhausted)
        } else if entropy.failed {
            result == Err(Error::EntropyFailed)
        } else {
            result.is_ok()
                || result == Err(Error::DerivationFailed)
                || result == Err(Error::CipherFailed)
        },
        "a wrap refuses a bad context, a stale handle, a set wrapping itself, a parent not of \
         the purpose it takes, a set or a parent of the wrong level, a set of an unfinished \
         transfer, an unsaved set outside a change unless it is exported and a failed source",
    );
    kani::cover!(
        result == Err(Error::WrongPurpose),
        "a parent of another purpose is refused"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && wrapping.purpose == Purpose::ArchiveWrap,
        "a stored key of the archive wraps no set"
    );
    kani::cover!(
        result == Err(Error::WrongLevel),
        "a set of the wrong level is refused"
    );
    let written = if lock { LOCK_RECORD_LEN } else { RECORD_LEN };
    kani::assert(
        if result.is_ok() {
            let mut drawn = [0; 12];
            drawn.copy_from_slice(&entropy.written[..12]);
            let mut salt = [0; 32];
            salt.copy_from_slice(
                &if changing && in_epoch {
                    next_key
                } else {
                    epoch_key
                }[..32],
            );
            let last = count
                .wrapping_add(u64::from(entropy.answered))
                .wrapping_sub(1);
            record[..12] == expected_hedge(&salt, last, Branch::HedgeNonce, &drawn)
        } else {
            same_bytes(&record[..written], &original[..written])
        },
        "a wrap writes the record only when it succeeds, starting with the nonce hedged from \
         the source's last bytes",
    );
    kani::assert(
        !any_failed() || result == Err(Error::DerivationFailed),
        "a wrap that a derivation fails fails with DerivationFailed",
    );
    kani::assert(
        (result == Err(Error::CipherFailed)) == seal::model::any_seal_failed(),
        "a wrap fails with CipherFailed exactly when a seal fails",
    );
    let (inner, layer) = (
        seal::model::sealed(seal::model::RECORD),
        seal::model::sealed(seal::model::LAYER),
    );
    let mut salt = [0; 32];
    salt.copy_from_slice(
        &if changing && in_epoch {
            next_key
        } else {
            epoch_key
        }[..32],
    );
    // What a check could fail on is worked out on every path, so that no proof of one kind
    // leaves a check of another unreached.
    let (length, head) = (wrapping.lengths[0], key_head(&wrapping));
    let record_key = match kind {
        Kind::Record => expected_wrap_key(&wrapping.keys.0, length, &salt),
        Kind::Lock => expected_lock_key(&wrapping.keys.0, length),
        Kind::Export | Kind::ArchiveKey => expected_export_key(&head),
    };
    let mut ciphertext = [0; 32];
    ciphertext.copy_from_slice(&record[NONCE_LEN..NONCE_LEN + 32]);
    let (mut tag_of_a_record, mut tag_of_a_lock) = ([0; TAG_LEN], [0; TAG_LEN]);
    tag_of_a_record.copy_from_slice(&record[RECORD_LEN - TAG_LEN..RECORD_LEN]);
    tag_of_a_lock.copy_from_slice(&record[LOCK_RECORD_LEN - TAG_LEN..]);
    let (outer, tag) = if lock {
        (layer, tag_of_a_lock)
    } else {
        (inner, tag_of_a_record)
    };
    let named = if changing {
        epoch.wrapping_add(1)
    } else {
        epoch
    };
    let (in_a_record, in_an_export) = (
        Bound::to(context),
        Bound::chained(b"lethewis key export", &wrapping.chain, context),
    );
    let bound = if in_epoch { in_a_record } else { in_an_export };
    kani::assert(
        result.is_err()
            || (seal::model::kept_at(seal::model::RECORD)
                && seal::model::kept_at(seal::model::LAYER) == lock
                && inner.key == record_key
                && Bound::kept(&inner) == bound
                && inner.given[1] == child.purpose as u8
                && inner.given[3..19] == wrapping.ids.0
                && inner.given[19..27]
                    == if kind == Kind::Record { named } else { 0 }.to_le_bytes()
                && (!lock
                    || (layer.key == expected_layer_key(&salt)
                        && Bound::kept(&layer) == Bound::to(context)
                        && layer.given[..8] == named.to_le_bytes()
                        && layer.given[8..20] == inner.nonce
                        && layer.given[20..32] == inner.written[..12]
                        && layer.given_end == inner.tag))
                && record[..NONCE_LEN] == outer.nonce
                && ciphertext == outer.written
                && tag == outer.tag),
        "a wrap seals the set, naming its purpose and its parent, under the key derived for its \
         kind and bound to its context, an export also to the chain of its key, and writes the \
         nonce, what the cipher wrote and the tag; a lock seals that record and the number of \
         its epoch under the key of that epoch",
    );
    kani::cover!(result.is_ok(), "a set is wrapped");
    kani::cover!(
        entropy.failed && entropy.written.iter().any(|&byte| byte != 0),
        "the source fails after writing bytes"
    );
    kani::cover!(result == Err(Error::CipherFailed), "the cipher fails");
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "the derivation fails"
    );
    (result, child, changing)
}

/// The wrap of a set for external data, of a key for transfers or of a key of a chat for its
/// archive.
#[kani::proof]
#[kani::unwind(234)]
fn a_wrap_changes_no_slot_and_writes_only_when_it_succeeds() {
    let (result, child, changing) = wrap_from(Kind::Record);
    kani::cover!(
        result == Err(Error::Unsaved),
        "a changed set is not wrapped in its epoch"
    );
    kani::cover!(
        result.is_ok() && changing && child.changed,
        "a changed set is wrapped for the next epoch"
    );
    kani::cover!(
        result.is_ok() && child.purpose == Purpose::Transfer,
        "a key for transfers is wrapped"
    );
    kani::cover!(
        result.is_ok() && child.purpose == Purpose::ArchiveSeal,
        "a key of a chat for its archive is wrapped"
    );
    kani::cover!(
        result.is_ok() && !changing && child.purpose == Purpose::Data,
        "a set for data is wrapped and held by a record"
    );
    kani::cover!(
        result == Err(Error::WrongLevel) && child.purpose == Purpose::ArchiveWrap,
        "a stored key of the archive is refused by a plain record"
    );
    kani::cover!(
        result == Err(Error::Unfinished),
        "a set of an unfinished transfer is not wrapped"
    );
}

/// The lock of a stored key, for wrapping or of the archive.
#[kani::proof]
#[kani::unwind(270)]
fn a_lock_changes_no_slot_and_writes_only_when_it_succeeds() {
    let (result, child, changing) = wrap_from(Kind::Lock);
    kani::cover!(
        result.is_ok() && changing,
        "a stored key is locked for the next epoch"
    );
    kani::cover!(
        result.is_ok() && child.purpose == Purpose::ArchiveWrap,
        "a stored key of the archive is locked"
    );
    kani::cover!(
        result == Err(Error::WrongLevel) && child.purpose == Purpose::ArchiveSeal,
        "a key of a chat for its archive is refused by a lock record"
    );
}

/// The export of a set for external data.
#[kani::proof]
#[kani::unwind(234)]
fn an_export_changes_no_set_and_writes_only_when_it_succeeds() {
    let (result, child, changing) = wrap_from(Kind::Export);
    kani::cover!(
        result.is_ok() && changing && child.changed,
        "a changed set is exported during a change of epoch"
    );
    kani::cover!(
        result == Err(Error::Unfinished),
        "a set of an unfinished transfer is not exported"
    );
    kani::cover!(
        result == Err(Error::WrongLevel) && child.purpose == Purpose::ArchiveSeal,
        "a key of a chat for its archive is not exported"
    );
}

/// From any state of two slots and of the epoch, with a change to the next under way or not,
/// for any lock record, any output buffer and any context of up to two bytes, whatever the
/// platform's source and the cipher do: a carry changes no slot and no epoch but its count of
/// draws. It refuses an empty context and a missing change before it decrypts, then opens the
/// record once, under the key derived from the key of this epoch and with the record's nonce,
/// and refuses it as `StaleRecord`, asking the source nothing, unless the cipher accepts it
/// and it names this epoch. It writes the output only when it succeeds, starting with the nonce
/// the source gave, hedged with the key of the next epoch.
#[kani::proof]
#[kani::unwind(270)]
fn a_carry_changes_no_slot_and_writes_only_when_it_succeeds() {
    let mut memory = [any_slot(), any_slot()];
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (number, epoch_key, next_key) = (
        slots.epoch.number,
        first_half(&slots.epoch.key),
        first_half(&slots.epoch.next),
    );
    let count = slots.epoch.drawn;
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let from: [u8; LOCK_RECORD_LEN] = kani::any();
    let original: [u8; LOCK_RECORD_LEN] = kani::any();
    let mut to = original;
    let mut entropy = AnyEntropy::new();
    let mut layer = AnyCipher::<LAYER_LEN>::new();
    let before = snapshots(&slots);

    let result = slots.carry_on_stack(
        context,
        &mut entropy,
        &from,
        &mut to,
        opening(|key, nonce, aad, buffer, tag| layer.open_bound(key, nonce, aad, buffer, tag)),
    );
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && slots.epoch.number == number
            && slots.epoch.changing == changing
            && first_half(&slots.epoch.key) == epoch_key
            && first_half(&slots.epoch.next) == next_key
            && slots.epoch.drawn == count.wrapping_add(u64::from(entropy.answered)),
        "a carry changes no slot and no epoch, and counts once each draw the source answers",
    );
    let current = layer.accepted && layer.written[..8] == number.to_le_bytes();
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext) && layer.calls == 0
        } else if !changing {
            result == Err(Error::NoEpochChange) && layer.calls == 0
        } else if number == u64::MAX {
            result == Err(Error::EpochExhausted) && layer.calls == 0
        } else if layer.calls == 0 {
            result == Err(Error::DerivationFailed) && any_failed()
        } else if !current {
            result == Err(Error::StaleRecord) && entropy.calls == 0
        } else if entropy.failed {
            result == Err(Error::EntropyFailed)
        } else {
            result.is_ok()
                || result == Err(Error::DerivationFailed)
                || result == Err(Error::CipherFailed)
        },
        "a carry refuses a bad context and a missing change, a failed derivation, a record that \
         does not open in this epoch and a failed source",
    );
    kani::assert(
        !any_failed() || result == Err(Error::DerivationFailed),
        "a carry that a derivation fails fails with DerivationFailed",
    );
    kani::assert(
        layer.calls <= 1
            && (layer.calls == 0
                || (layer.key == expected_layer_key(&epoch_key)
                    && layer.nonce[..] == from[..NONCE_LEN]
                    && layer.aad == Bound::to(context))),
        "the record is opened once, under the key of this epoch, with its own nonce and bound \
         to its context",
    );
    kani::assert(
        (result == Err(Error::CipherFailed)) == seal::model::any_seal_failed(),
        "a carry fails with CipherFailed exactly when its seal fails",
    );
    let carried = seal::model::sealed(seal::model::LAYER);
    kani::assert(
        result.is_err()
            || (seal::model::kept_at(seal::model::LAYER)
                && carried.key == expected_layer_key(&next_key)
                && Bound::kept(&carried) == Bound::to(context)
                && carried.given[..8] == number.wrapping_add(1).to_le_bytes()
                && carried.given[8..] == layer.written[8..32]
                && carried.given_end[..] == layer.written[LAYER_LEN - TAG_LEN..]
                && to[..NONCE_LEN] == carried.nonce
                && to[NONCE_LEN..NONCE_LEN + 32] == carried.written
                && to[LOCK_RECORD_LEN - TAG_LEN..] == carried.tag),
        "a carry seals the record it opened with the number of the next epoch, under the key of \
         that epoch and bound to its context, and writes the nonce, what the cipher wrote and \
         the tag",
    );
    kani::assert(
        if result.is_ok() {
            let mut drawn = [0; 12];
            drawn.copy_from_slice(&entropy.written[..12]);
            to[..12] == expected_hedge(&next_key, count, Branch::HedgeNonce, &drawn)
        } else {
            same(&to, &original)
        },
        "a carry writes its output only when it succeeds, starting with the nonce hedged with \
         the key of the next epoch",
    );
    kani::cover!(result.is_ok(), "a lock record is carried");
    kani::cover!(
        result == Err(Error::StaleRecord) && layer.accepted,
        "a lock record of another epoch is refused"
    );
    kani::cover!(
        result == Err(Error::NoEpochChange),
        "nothing is carried outside a change"
    );
    kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
}

/// From any state of two slots and of the epoch, for handles of these slots naming any slots
/// and generations, any context of up to two bytes and any record of an archive key: a load
/// refuses an empty context, then a stale handle, then a store not of the archive or a profile
/// not for wrapping, then a key from a secret as the profile, and when it refuses none of them,
/// finds no free slot. It decrypts nothing and changes no slot.
#[kani::proof]
#[kani::unwind(1530)]
fn a_load_of_an_archive_key_refuses_its_parents_before_it_decrypts() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let epoch_before = epoch_snapshot(&slots);
    let (store, profile) = (forged(id), forged(id));
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let record: [u8; ARCHIVE_KEY_RECORD_LEN] = kani::any();

    let result = slots.load_archive_key_on_stack(
        store,
        profile,
        context,
        &record,
        &xwing::KNOWN,
        seal::model::refuse,
        seal::model::refuse,
    );
    let (archive, stored) = (
        snapshot_at(&before, store.index),
        snapshot_at(&before, profile.index),
    );
    let refusal = if context.is_empty() {
        Error::InvalidContext
    } else if !names_loaded(&before, &store) || !names_loaded(&before, &profile) {
        Error::StaleHandle
    } else if archive.purpose != Purpose::ArchiveWrap || stored.purpose != Purpose::Wrap {
        Error::WrongPurpose
    } else if stored.unlocks {
        Error::WrongLevel
    } else {
        Error::NoFreeSlot
    };
    kani::assert(
        result.err() == Some(refusal)
            && !seal::model::asked()
            && unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == epoch_before,
        "a load refuses a bad context, a stale handle, keys of other purposes and a key from a \
         secret, then finds no free slot, before it decrypts, and changes no slot and no epoch",
    );
    kani::cover!(
        result == Err(Error::StaleHandle),
        "a stale handle is refused"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose),
        "a key of another purpose is refused"
    );
    kani::cover!(
        result == Err(Error::WrongLevel),
        "a key from a secret opens no archive key"
    );
    kani::cover!(result == Err(Error::NoFreeSlot), "a load needs a free slot");
}

/// The associated data a cipher was given, as far as a context of up to two bytes reaches: its
/// first bytes, zero past its end, and its length.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Bound {
    bytes: [u8; seal::model::AAD_HEAD],
    length: usize,
}

impl Bound {
    const fn none() -> Self {
        Self {
            bytes: [0; seal::model::AAD_HEAD],
            length: 0,
        }
    }

    fn of(aad: &[u8]) -> Self {
        Self {
            bytes: core::array::from_fn(|at| aad.get(at).copied().unwrap_or(0)),
            length: aad.len(),
        }
    }

    /// The associated data of a record bound to `context`, of up to two bytes, written out from
    /// the layout: the label, the version, the length of the context, and the context.
    fn to(context: &[u8]) -> Self {
        let mut bytes = [0; seal::model::AAD_HEAD];
        bytes[..19].copy_from_slice(b"lethewis key record");
        bytes[19] = 1;
        bytes[20] = u8::try_from(context.len()).unwrap_or(0);
        bytes[21] = context.first().copied().unwrap_or(0);
        bytes[22] = context.get(1).copied().unwrap_or(0);
        Self {
            bytes,
            length: context.len().wrapping_add(21),
        }
    }

    /// The associated data of a record of an export or of its end, `label`, bound to `context`,
    /// of up to two bytes, and chained to `chain`, written out from the layout: the label, the
    /// version, the length of the context, the chain, and the context.
    fn chained(label: &[u8; 19], chain: &[u8; TAG_LEN], context: &[u8]) -> Self {
        let mut bytes = [0; seal::model::AAD_HEAD];
        bytes[..19].copy_from_slice(label);
        bytes[19] = 1;
        bytes[20] = u8::try_from(context.len()).unwrap_or(0);
        bytes[21..37].copy_from_slice(chain);
        bytes[37] = context.first().copied().unwrap_or(0);
        bytes[38] = context.get(1).copied().unwrap_or(0);
        Self {
            bytes,
            length: context.len().wrapping_add(21 + TAG_LEN),
        }
    }

    /// The associated data a seal of the model of the cipher was given, as the model keeps it.
    fn kept(sealed: &seal::model::Sealed) -> Self {
        Self {
            bytes: sealed.aad,
            length: sealed.aad_len,
        }
    }
}

/// Any cipher sealing a plaintext of `N` bytes: it writes any bytes and gives any tag, or
/// fails at will, and keeps what it was given.
struct AnySeal<const N: usize> {
    calls: usize,
    key: [u8; CIPHER_KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: Bound,
    given: [u8; N],
    written: [u8; N],
    tag: [u8; TAG_LEN],
    failed: bool,
}

impl<const N: usize> AnySeal<N> {
    fn new() -> Self {
        Self {
            calls: 0,
            key: [0; CIPHER_KEY_LEN],
            nonce: [0; NONCE_LEN],
            aad: Bound::none(),
            given: [0; N],
            written: [0; N],
            tag: [0; TAG_LEN],
            failed: false,
        }
    }

    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8; N],
    ) -> Result<[u8; TAG_LEN], SealFailed> {
        (self.key, self.nonce, self.aad, self.given) = (*key, *nonce, Bound::of(aad), *buffer);
        let (written, tag, failed): ([u8; N], [u8; TAG_LEN], bool) =
            (kani::any(), kani::any(), kani::any());
        *buffer = written;
        (self.written, self.tag, self.failed) = (written, tag, failed);
        self.calls = self.calls.saturating_add(1);
        if failed { Err(SealFailed) } else { Ok(tag) }
    }

    /// [`AnySeal::seal`], as the stand-in for the cipher it is in the proofs: one closure for
    /// every proof, so that one that seals reaches it for one that never does.
    fn sealing(
        &mut self,
    ) -> impl FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8; N],
    ) -> Result<[u8; TAG_LEN], SealFailed>
    + '_ {
        |key, nonce, aad, buffer| self.seal(key, nonce, aad, buffer)
    }
}

/// Any source, which keeps what it gave the first time.
struct FirstKept {
    source: AnyEntropy,
    first: Bytes,
}

impl FirstKept {
    fn new() -> Self {
        Self {
            source: AnyEntropy::new(),
            first: [0; 64],
        }
    }
}

impl Entropy for FirstKept {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        let filled = self.source.fill(dest);
        if self.source.calls == 1 {
            self.first = self.source.written;
        }
        filled
    }
}

/// The first 32 bytes of the first key of `snapshot`.
fn key_head(snapshot: &Snapshot) -> [u8; 32] {
    let mut key = [0; 32];
    key.copy_from_slice(&snapshot.keys.0[..32]);
    key
}

/// From any state of two slots and of the epoch, for a handle of these slots naming any slot
/// and generation, any record of an archive key and any context of up to two bytes, whatever
/// the cipher does: reading the public key of an archive key changes no slot and no epoch. It
/// refuses an empty context, a stale handle, a set not for wrapping and a key from a secret, in
/// that order, before it decrypts. It opens the record once, under the key of the profile and
/// this epoch, with the record's nonce, ciphertext and tag and the associated data of the
/// context, and refuses it as `StaleRecord` unless the cipher accepts it and it names this
/// epoch; then it gives the identifier and the public key the record holds, for these slots
/// and this epoch.
#[kani::proof]
#[kani::unwind(1530)]
fn a_public_key_is_read_from_its_record() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (number, epoch_key) = (slots.epoch.number, first_half(&slots.epoch.key));
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let profile = forged(id);
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let record: [u8; ARCHIVE_KEY_RECORD_LEN] = kani::any();
    let mut layer = AnyCipher::<ARCHIVE_LAYER_LEN>::new();

    let result = slots.archive_public_key_on_stack(
        profile,
        context,
        &record,
        opening(|key, nonce, aad, buffer, tag| layer.open_bound(key, nonce, aad, buffer, tag)),
    );
    kani::assert(
        unchanged_except(&slots, &before, 2) && epoch_snapshot(&slots) == epoch_before,
        "reading a public key changes no slot and no epoch",
    );
    let stored = snapshot_at(&before, profile.index);
    let refusal = if context.is_empty() {
        Some(Error::InvalidContext)
    } else if !names_loaded(&before, &profile) {
        Some(Error::StaleHandle)
    } else if stored.purpose != Purpose::Wrap {
        Some(Error::WrongPurpose)
    } else if stored.unlocks {
        Some(Error::WrongLevel)
    } else {
        None
    };
    let current = layer.accepted && layer.written[..8] == number.to_le_bytes();
    let failed = result.as_ref().err().copied();
    kani::assert(
        if let Some(error) = refusal {
            failed == Some(error) && layer.calls == 0
        } else if any_failed() {
            failed == Some(Error::DerivationFailed) && layer.calls == 0
        } else if !current {
            failed == Some(Error::StaleRecord)
        } else {
            result.is_ok()
        },
        "reading a public key refuses a bad context, a stale handle, a set not for wrapping and \
         a key from a secret before it decrypts, then a failed derivation and a record that \
         does not open in this epoch",
    );
    kani::assert(
        layer.calls <= 1
            && (layer.calls == 0
                || (layer.key
                    == expected_archive_layer_key(&stored.keys.0, stored.lengths[0], &epoch_key)
                    && layer.nonce[..] == record[..NONCE_LEN]
                    && same_bytes(
                        &layer.given,
                        &record[NONCE_LEN..NONCE_LEN + ARCHIVE_LAYER_LEN],
                    )
                    && layer.tag[..] == record[NONCE_LEN + ARCHIVE_LAYER_LEN..]
                    && layer.aad == Bound::to(context))),
        "the record is opened once, under the key of the profile and this epoch, with its \
         nonce, ciphertext and tag and the associated data of the context",
    );
    if let Ok(public) = &result {
        kani::assert(
            public.id[..] == layer.written[8..8 + ID_LEN]
                && same_bytes(
                    &public.public,
                    &layer.written[8 + ID_LEN..8 + ID_LEN + PUBLIC_LEN],
                )
                && public.slots == id
                && public.epoch == number,
            "the identifier and the public key are the ones the record holds, for these slots \
             and this epoch",
        );
    }
    kani::cover!(result.is_ok(), "a public key is read");
    kani::cover!(
        failed == Some(Error::StaleRecord) && layer.accepted,
        "a record of another epoch gives no public key"
    );
    kani::cover!(
        failed == Some(Error::WrongLevel),
        "a key from a secret reads no public key"
    );
    kani::cover!(
        failed == Some(Error::DerivationFailed),
        "a derivation fails"
    );
}

/// From any state of two slots and of the epoch, with a change to the next under way or not,
/// for a handle of these slots naming any slot and generation, any public key read for any slots
/// and epoch, any context of up to two bytes and any outputs, whatever the platform's source,
/// X-Wing and the cipher do: archiving changes no slot and no epoch but its count of draws. It
/// refuses an empty context, a stale handle, a set not of a chat for its archive, a public key of
/// other slots or another epoch and a wrong answer of X-Wing before it draws, then a failed
/// source; `DerivationFailed` is a failed derivation, `RecordRejected` a public key X-Wing
/// refuses and `CipherFailed` a failed seal, each and only that. It writes its outputs only when
/// it succeeds: after two draws, the randomness given to X-Wing with the public key is the hedge
/// of the first under the key of this epoch, derived under the key of the chat, and the key of
/// the batch is derived from the shared secret, with the ciphertext as the salt.
#[kani::proof]
#[kani::unwind(1181)]
fn an_archive_writes_only_when_it_succeeds() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let (number, key, next, _, _) = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let seal = forged(id);
    let public = ArchivePublic {
        id: kani::any(),
        public: kani::any(),
        slots: kani::any(),
        epoch: kani::any(),
        memory: PhantomData,
    };
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let original: [u8; ARCHIVE_RECORD_LEN] = kani::any();
    let original_key: [u8; 32] = kani::any();
    let (mut record, mut data_key) = (original, original_key);
    let mut entropy = FirstKept::new();
    let mut sealer = AnySeal::<ARCHIVED_LEN>::new();

    let result = slots.archive_on_stack(
        seal,
        &public,
        context,
        &mut entropy,
        (&mut record, &mut data_key),
        &xwing::KNOWN,
        sealing(|key, nonce, aad, buffer| sealer.seal(key, nonce, aad, buffer)),
    );
    let draws = count.wrapping_add(u64::from(entropy.source.answered));
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == (number, key, next, changing, draws),
        "archiving changes no slot and no epoch, and counts once each draw the source answers",
    );
    let chat = snapshot_at(&before, seal.index);
    let asked = entropy.source.calls;
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext) && asked == 0
        } else if !names_loaded(&before, &seal) {
            result == Err(Error::StaleHandle) && asked == 0
        } else if chat.purpose != Purpose::ArchiveSeal {
            result == Err(Error::WrongPurpose) && asked == 0
        } else if public.slots != id || public.epoch != number {
            result == Err(Error::StaleRecord) && asked == 0
        } else if !xwing_answered() {
            result == Err(Error::CipherFailed) && asked == 0
        } else if entropy.source.failed {
            result == Err(Error::EntropyFailed)
        } else if any_failed() {
            result == Err(Error::DerivationFailed)
        } else if xwing::model::refused() {
            result == Err(Error::RecordRejected) && sealer.calls == 0
        } else if sealer.failed {
            result == Err(Error::CipherFailed)
        } else {
            result.is_ok()
        },
        "archiving refuses a bad context, a stale handle, a set not of a chat for its archive, \
         a public key of other slots or another epoch and a wrong answer of X-Wing before it \
         draws, then a failed source, a failed derivation, a refused public key and a failed seal",
    );
    if result.is_ok() {
        let hedged = expected_hedge(&epoch_key, count, Branch::HedgeEncaps, &entropy.first);
        let mut drawn = [0; 12];
        drawn.copy_from_slice(&entropy.source.written[..12]);
        let (shared, ciphertext) = (xwing::model::shared(), xwing::model::ciphertext_head());
        kani::assert(
            asked == 2
                && xwing::model::randomness()
                    == expected_archive_randomness(&key_head(&chat), &hedged)
                && xwing::model::public_head()[..] == public.public[..32]
                && data_key == expected_archive_data(&shared, &ciphertext),
            "an archive encapsulates to its public key with the randomness hedged with the key \
             of this epoch and derived under the key of the chat, and gives the key of the \
             batch derived from the shared secret and the ciphertext",
        );
    } else {
        kani::assert(
            same(&record, &original) && data_key == original_key,
            "an archive that fails writes nothing",
        );
    }
    kani::cover!(result.is_ok(), "a batch is archived");
    kani::cover!(
        result.is_ok() && changing,
        "a batch is archived during a change of epoch"
    );
    kani::cover!(
        result == Err(Error::StaleRecord),
        "a public key of another epoch archives nothing"
    );
    kani::cover!(
        result == Err(Error::RecordRejected),
        "X-Wing refuses the public key"
    );
    kani::cover!(
        result == Err(Error::CipherFailed) && sealer.failed,
        "the seal fails"
    );
    kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
    kani::cover!(result == Err(Error::DerivationFailed), "a derivation fails");
}

/// From the same states as the proof above, a successful archive seals, under the key of the
/// chat, with the nonce of its second draw hedged with the key of this epoch and with the
/// associated data of the context, the identifier of the archive key, the ciphertext X-Wing gave
/// and the check of its shared secret; and its record holds that nonce, what the cipher wrote
/// and its tag.
#[kani::proof]
#[kani::unwind(1181)]
fn an_archive_seals_its_identifier_ciphertext_and_check() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let before = snapshots(&slots);
    let seal = forged(id);
    let public = ArchivePublic {
        id: kani::any(),
        public: kani::any(),
        slots: kani::any(),
        epoch: kani::any(),
        memory: PhantomData,
    };
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let original: [u8; ARCHIVE_RECORD_LEN] = kani::any();
    let original_key: [u8; 32] = kani::any();
    let (mut record, mut data_key) = (original, original_key);
    let mut entropy = FirstKept::new();
    let mut sealer = AnySeal::<ARCHIVED_LEN>::new();

    let result = slots.archive_on_stack(
        seal,
        &public,
        context,
        &mut entropy,
        (&mut record, &mut data_key),
        &xwing::KNOWN,
        sealing(|key, nonce, aad, buffer| sealer.seal(key, nonce, aad, buffer)),
    );
    let chat = snapshot_at(&before, seal.index);
    if result.is_ok() {
        let mut drawn = [0; 12];
        drawn.copy_from_slice(&entropy.source.written[..12]);
        let (shared, ciphertext) = (xwing::model::shared(), xwing::model::ciphertext_head());
        kani::assert(
            sealer.calls == 1
                && sealer.key == expected_archive_seal_key(&key_head(&chat))
                && sealer.nonce
                    == expected_hedge(
                        &epoch_key,
                        count.wrapping_add(1),
                        Branch::HedgeNonce,
                        &drawn,
                    )
                && sealer.aad == Bound::to(context)
                && sealer.given[..ID_LEN] == public.id
                && sealer.given[ID_LEN..ID_LEN + 32] == ciphertext
                && sealer.given[ID_LEN + CIPHERTEXT_LEN..]
                    == expected_archive_check(&shared, &ciphertext)
                && record[..NONCE_LEN] == sealer.nonce
                && same_bytes(
                    &record[NONCE_LEN..NONCE_LEN + ARCHIVED_LEN],
                    &sealer.written,
                )
                && record[NONCE_LEN + ARCHIVED_LEN..] == sealer.tag,
            "the record seals, under the key of the chat, with a nonce hedged likewise and the \
             associated data of the context, the identifier, the ciphertext and the check of \
             the shared secret, and holds that nonce, what the cipher wrote and its tag",
        );
    }
    kani::cover!(result.is_ok(), "a batch is archived");
    kani::cover!(
        result.is_ok() && changing,
        "a batch is archived during a change of epoch"
    );
}

/// From any state of two slots and of the epoch, for handles of these slots naming any slots
/// and generations, any record of an archive, any context of up to two bytes and any output,
/// whatever X-Wing and the cipher do: opening a record of an archive changes no slot and no
/// epoch. It refuses an empty context, then for each handle in turn a stale one and a set not
/// of its purpose, then a wrong answer of X-Wing, before it decrypts. It opens the record once,
/// under the key of the chat, with the record's nonce, ciphertext and tag and the associated
/// data of the context, as `RecordRejected` unless the cipher accepts it, and as
/// `WrongArchiveKey`, decapsulating nothing, unless it names the archive key. Then it gives the
/// seed and the ciphertext to X-Wing, refuses as `PublicKeyMismatch` a check that is not the
/// shared secret's, and writes the key of the batch only when it succeeds.
#[kani::proof]
#[kani::unwind(1181)]
fn an_opened_archive_gives_its_key_only_under_its_archive_key() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (archive, seal) = (forged(id), forged(id));
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let record: [u8; ARCHIVE_RECORD_LEN] = kani::any();
    let original_key: [u8; 32] = kani::any();
    let mut data_key = original_key;
    let mut cipher = AnyCipher::<ARCHIVED_LEN>::new();

    let result = slots.open_archive_on_stack(
        (archive, seal),
        context,
        (&record, &mut data_key),
        &xwing::KNOWN,
        opening(|key, nonce, aad, buffer, tag| cipher.open_bound(key, nonce, aad, buffer, tag)),
    );
    kani::assert(
        unchanged_except(&slots, &before, 2) && epoch_snapshot(&slots) == epoch_before,
        "opening a record of an archive changes no slot and no epoch",
    );
    let (archived, chat) = (
        snapshot_at(&before, archive.index),
        snapshot_at(&before, seal.index),
    );
    let refusal = |handle: &Handle<'_>, purpose| {
        if !names_loaded(&before, handle) {
            Some(Error::StaleHandle)
        } else if snapshot_at(&before, handle.index).purpose != purpose {
            Some(Error::WrongPurpose)
        } else {
            None
        }
    };
    let refused =
        refusal(&archive, Purpose::Archive).or_else(|| refusal(&seal, Purpose::ArchiveSeal));
    let named = cipher.accepted && cipher.written[..ID_LEN] == archived.ids.0;
    let mut ciphertext = [0; 32];
    ciphertext.copy_from_slice(&cipher.written[ID_LEN..ID_LEN + 32]);
    let shared = xwing::model::shared();
    let checked =
        cipher.written[ID_LEN + CIPHERTEXT_LEN..] == expected_archive_check(&shared, &ciphertext);
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext) && cipher.calls == 0
        } else if let Some(error) = refused {
            result == Err(error) && cipher.calls == 0
        } else if !xwing_answered() {
            result == Err(Error::CipherFailed) && cipher.calls == 0
        } else if cipher.calls == 0 {
            result == Err(Error::DerivationFailed)
        } else if !cipher.accepted {
            result == Err(Error::RecordRejected) && !xwing::model::decapsulated()
        } else if !named {
            result == Err(Error::WrongArchiveKey) && !xwing::model::decapsulated()
        } else if any_failed() {
            result == Err(Error::DerivationFailed)
        } else if !checked {
            result == Err(Error::PublicKeyMismatch)
        } else {
            result.is_ok()
        },
        "opening refuses a bad context, stale handles, sets of other purposes and a wrong \
         answer of X-Wing before it decrypts, then a record the key of the chat does not \
         open, one of another archive key, a failed derivation and a check not of the shared \
         secret",
    );
    kani::assert(
        cipher.calls <= 1
            && (cipher.calls == 0
                || (cipher.key == expected_archive_seal_key(&key_head(&chat))
                    && cipher.nonce[..] == record[..NONCE_LEN]
                    && same_bytes(&cipher.given, &record[NONCE_LEN..NONCE_LEN + ARCHIVED_LEN])
                    && cipher.tag[..] == record[NONCE_LEN + ARCHIVED_LEN..]
                    && cipher.aad == Bound::to(context))),
        "the record is opened once, under the key of the chat, with its nonce, ciphertext and \
         tag and the associated data of the context",
    );
    if result.is_ok() {
        kani::assert(
            xwing::model::seed() == key_head(&archived)
                && xwing::model::ciphertext_head() == ciphertext
                && data_key == expected_archive_data(&shared, &ciphertext),
            "the key of the batch is derived from the shared secret the seed gives the \
             ciphertext of the record, with that ciphertext as the salt",
        );
    } else {
        kani::assert(
            data_key == original_key,
            "an opening that fails writes nothing",
        );
    }
    kani::cover!(result.is_ok(), "a batch is opened");
    kani::cover!(
        result == Err(Error::WrongArchiveKey),
        "a record of another archive key is refused"
    );
    kani::cover!(
        result == Err(Error::PublicKeyMismatch),
        "a batch archived to another public key is refused"
    );
    kani::cover!(
        result == Err(Error::RecordRejected),
        "a record the key of the chat does not open is refused"
    );
    kani::cover!(
        result == Err(Error::CipherFailed),
        "a wrong answer of X-Wing opens nothing"
    );
    kani::cover!(
        result == Err(Error::DerivationFailed) && cipher.calls == 1,
        "the derivation of the key of the batch fails"
    );
}

/// From any state of two slots and of the epoch, for handles of these slots naming any slots
/// and generations, any record of an archive, any context of up to two bytes and any output, with
/// a cipher that rejects every record: moving a record changes no slot and no epoch and writes
/// nothing. It refuses an empty context, then for each handle in turn a stale one and a set not of
/// a chat for its archive, before it decrypts. It opens the record at most once, under the key of
/// the first chat, with the record's nonce, ciphertext and tag and the associated data of the
/// context, and refuses it as `RecordRejected`, asking the source nothing.
#[kani::proof]
#[kani::unwind(1181)]
fn a_reseal_refuses_what_it_cannot_move() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (from, to) = (forged(id), forged(id));
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let record: [u8; ARCHIVE_RECORD_LEN] = kani::any();
    let original: [u8; ARCHIVE_RECORD_LEN] = kani::any();
    let mut out = original;
    let mut entropy = AnyEntropy::new();
    let mut cipher = AnyCipher::<ARCHIVED_LEN>::answering(false);
    let mut sealer = AnySeal::<ARCHIVED_LEN>::new();

    let result = slots.reseal_archive_on_stack(
        (from, to),
        context,
        &mut entropy,
        (&record, &mut out),
        opening(|key, nonce, aad, buffer, tag| cipher.open_bound(key, nonce, aad, buffer, tag)),
        sealer.sealing(),
    );
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == epoch_before
            && same(&out, &original),
        "a refused move changes no slot and no epoch and writes nothing",
    );
    let refusal = |handle: &Handle<'_>| {
        if !names_loaded(&before, handle) {
            Some(Error::StaleHandle)
        } else if snapshot_at(&before, handle.index).purpose != Purpose::ArchiveSeal {
            Some(Error::WrongPurpose)
        } else {
            None
        }
    };
    let refused = refusal(&from).or_else(|| refusal(&to));
    kani::assert(
        entropy.calls == 0
            && sealer.calls == 0
            && if context.is_empty() {
                result == Err(Error::InvalidContext) && cipher.calls == 0
            } else if let Some(error) = refused {
                result == Err(error) && cipher.calls == 0
            } else if cipher.calls == 0 {
                result == Err(Error::DerivationFailed)
            } else {
                result == Err(Error::RecordRejected)
            },
        "moving a record refuses a bad context, stale handles and sets not of a chat for its \
         archive before it decrypts, then a record the first key does not open, asking the source \
         nothing",
    );
    kani::assert(
        cipher.calls <= 1
            && (cipher.calls == 0
                || (cipher.key
                    == expected_archive_seal_key(&key_head(&snapshot_at(&before, from.index)))
                    && cipher.nonce[..] == record[..NONCE_LEN]
                    && same_bytes(&cipher.given, &record[NONCE_LEN..NONCE_LEN + ARCHIVED_LEN])
                    && cipher.tag[..] == record[NONCE_LEN + ARCHIVED_LEN..]
                    && cipher.aad == Bound::to(context))),
        "the record is opened once, under the key of the first chat, with its nonce, \
         ciphertext and tag and the associated data of the context",
    );
    kani::cover!(
        result == Err(Error::RecordRejected),
        "a record the first key does not open is refused"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose),
        "a set not of a chat for its archive is refused"
    );
}

/// From any state of two slots and of the epoch, for handles that name sets of chats for their
/// archive held there now, any record of an archive, any context of one or two bytes and any
/// output, whatever the platform's source does and with a cipher that accepts every record:
/// moving a record changes no slot and no epoch but its count of draws. It opens the record once,
/// under the key of the first chat, with the record's nonce, ciphertext and tag and the associated
/// data of the context, unless the derivation of that key fails. On success it has drawn once and
/// seals what the record held, under the key of the second chat, with the nonce the source gave,
/// hedged with the key of this epoch, and the same associated data; otherwise it fails as the
/// source, a derivation or the seal failed, and writes nothing.
#[kani::proof]
#[kani::unwind(1181)]
fn a_reseal_seals_what_the_record_held() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let (number, key, next, _, _) = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (from, to) = (forged(id), forged(id));
    let of_a_chat = |handle: &Handle<'_>| {
        names_loaded(&before, handle)
            && snapshot_at(&before, handle.index).purpose == Purpose::ArchiveSeal
    };
    kani::assume(of_a_chat(&from) && of_a_chat(&to));
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    kani::assume(!context.is_empty());
    let record: [u8; ARCHIVE_RECORD_LEN] = kani::any();
    let original: [u8; ARCHIVE_RECORD_LEN] = kani::any();
    let mut out = original;
    let mut entropy = AnyEntropy::new();
    let mut cipher = AnyCipher::<ARCHIVED_LEN>::answering(true);
    let mut sealer = AnySeal::<ARCHIVED_LEN>::new();

    let result = slots.reseal_archive_on_stack(
        (from, to),
        context,
        &mut entropy,
        (&record, &mut out),
        opening(|key, nonce, aad, buffer, tag| cipher.open_bound(key, nonce, aad, buffer, tag)),
        sealer.sealing(),
    );
    let draws = count.wrapping_add(u64::from(entropy.answered));
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == (number, key, next, changing, draws),
        "moving a record changes no slot and no epoch, and counts once each draw the source \
         answers",
    );
    kani::assert(
        if cipher.calls == 0 {
            result == Err(Error::DerivationFailed)
        } else if entropy.failed {
            result == Err(Error::EntropyFailed)
        } else if any_failed() {
            result == Err(Error::DerivationFailed)
        } else if sealer.failed {
            result == Err(Error::CipherFailed)
        } else {
            result.is_ok()
        },
        "moving a record that opens fails only for a failed source, a failed derivation or a \
         failed seal",
    );
    kani::assert(
        cipher.calls <= 1
            && (cipher.calls == 0
                || (cipher.key
                    == expected_archive_seal_key(&key_head(&snapshot_at(&before, from.index)))
                    && cipher.nonce[..] == record[..NONCE_LEN]
                    && same_bytes(&cipher.given, &record[NONCE_LEN..NONCE_LEN + ARCHIVED_LEN])
                    && cipher.tag[..] == record[NONCE_LEN + ARCHIVED_LEN..]
                    && cipher.aad == Bound::to(context))),
        "the record is opened once, under the key of the first chat, with its nonce, \
         ciphertext and tag and the associated data of the context",
    );
    if result.is_ok() {
        let mut drawn = [0; 12];
        drawn.copy_from_slice(&entropy.written[..12]);
        kani::assert(
            entropy.calls == 1
                && sealer.calls == 1
                && sealer.key
                    == expected_archive_seal_key(&key_head(&snapshot_at(&before, to.index)))
                && sealer.nonce == expected_hedge(&epoch_key, count, Branch::HedgeNonce, &drawn)
                && sealer.aad == Bound::to(context)
                && same(&sealer.given, &cipher.written)
                && out[..NONCE_LEN] == sealer.nonce
                && same_bytes(&out[NONCE_LEN..NONCE_LEN + ARCHIVED_LEN], &sealer.written)
                && out[NONCE_LEN + ARCHIVED_LEN..] == sealer.tag,
            "a moved record seals what the record held under the key of the second chat, with \
             a nonce hedged with the key of this epoch and the same associated data, and holds \
             that nonce, what the cipher wrote and its tag",
        );
    } else {
        kani::assert(same(&out, &original), "a move that fails writes nothing");
    }
    kani::cover!(result.is_ok(), "a record is moved");
    kani::cover!(
        result.is_ok() && from.index != to.index,
        "a record is moved to another key"
    );
    kani::cover!(result == Err(Error::CipherFailed), "the seal fails");
    kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
}

/// For three slots, the first a loaded stored key of the archive, the second a loaded key for
/// wrapping that is not from a secret and the third free, all else about them and the epoch
/// any, for handles of these slots naming either of the first two and any generation, any
/// context of up to two bytes and any record of an archive key, whatever X-Wing and the cipher
/// do: a load refuses an empty context, a stale handle, a store not of the archive or a profile
/// not for wrapping and a wrong answer of X-Wing before it decrypts. It opens the outer layer
/// once, under the key of the profile and this epoch, and refuses it as `StaleRecord` unless the
/// cipher accepts it and it names this epoch; then it opens the seed once under the store, and
/// refuses it as `RecordRejected` unless the cipher accepts it, it names the store, and it is
/// one seed of an archive key of epoch zero; then the identifier and the public key of the outer
/// layer must be the seed's, or `PublicKeyMismatch`, and the seed held nowhere, or
/// `DuplicateKey`. A refusal changes no slot; a success loads the seed into the third slot as a
/// set of one for the archive, stored, in no transfer, with its identifier.
#[kani::proof]
#[kani::unwind(1530)]
fn a_load_of_an_archive_key_checks_its_public_key() {
    let mut memory = [
        any_slot_in(Occupancy::Loaded),
        any_slot_in(Occupancy::Loaded),
        any_slot_in(Occupancy::Free),
    ];
    kani::assume(
        memory[0].purpose == Purpose::ArchiveWrap
            && memory[1].purpose == Purpose::Wrap
            && !memory[1].unlocks,
    );
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (number, epoch_key) = (slots.epoch.number, first_half(&slots.epoch.key));
    let epoch_before = epoch_snapshot(&slots);
    let before = [
        snapshot(&slots.memory[0]),
        snapshot(&slots.memory[1]),
        snapshot(&slots.memory[2]),
    ];
    let named = [before[0], before[1]];
    let (store, profile) = (forged(id), forged(id));
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let record: [u8; ARCHIVE_KEY_RECORD_LEN] = kani::any();
    let mut layer = AnyCipher::<ARCHIVE_LAYER_LEN>::new();
    let mut cipher = AnyCipher::<PLAINTEXT_LEN>::new();

    let result = slots.load_archive_key_on_stack(
        store,
        profile,
        context,
        &record,
        &xwing::KNOWN,
        opening(|key, nonce, aad, buffer, tag| layer.open_bound(key, nonce, aad, buffer, tag)),
        opening(|key, nonce, aad, buffer, tag| cipher.open_bound(key, nonce, aad, buffer, tag)),
    );
    let (archive, stored) = (
        snapshot_at(&named, store.index),
        snapshot_at(&named, profile.index),
    );
    let current = layer.accepted && layer.written[..8] == number.to_le_bytes();
    let body = &layer.written[8..];
    let inner_named = cipher.accepted && cipher.written[3..19] == archive.ids.0;
    let parsed = crate::keyset::parse(&cipher.written).map(|(_, stages, _)| stages);
    let one_seed = parsed.is_ok_and(|stages| stages.is_one())
        && cipher.written[1] == 4
        && cipher.written[19..27] == [0; 8];
    let mut seed = [0; 64];
    seed[..32].copy_from_slice(&cipher.written[37..69]);
    let seed_id = expected_key_id(&seed, KeyLength::Bytes32);
    let given = body[..ID_LEN] == seed_id
        && body[ID_LEN..ID_LEN + 32] == seed[..32]
        && same_bytes(
            &body[ID_LEN + 32..ID_LEN + PUBLIC_LEN],
            &[0; PUBLIC_LEN - 32],
        );
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext)
        } else if !names_loaded(&named, &store) || !names_loaded(&named, &profile) {
            result == Err(Error::StaleHandle)
        } else if archive.purpose != Purpose::ArchiveWrap || stored.purpose != Purpose::Wrap {
            result == Err(Error::WrongPurpose)
        } else if !xwing_answered() {
            result == Err(Error::CipherFailed) && layer.calls == 0
        } else if any_failed() {
            result == Err(Error::DerivationFailed)
        } else if !current {
            result == Err(Error::StaleRecord) && cipher.calls == 0
        } else if !inner_named || !one_seed {
            result == Err(Error::RecordRejected)
        } else if !given {
            result == Err(Error::PublicKeyMismatch)
        } else if held(&named, &seed_id) {
            result == Err(Error::DuplicateKey)
        } else {
            result.is_ok()
        },
        "a load refuses a bad context, a stale handle, keys of other purposes and a wrong answer \
         of X-Wing before it decrypts, then a record that does not open in this epoch, a seed \
         that does not open under the store or is not one seed, a public key or identifier not \
         the seed's, and a seed held already",
    );
    kani::assert(
        layer.calls <= 1
            && (layer.calls == 0
                || layer.key
                    == expected_archive_layer_key(&stored.keys.0, stored.lengths[0], &epoch_key)),
        "the outer layer is opened once, under the key of the profile and this epoch",
    );
    kani::assert(
        layer.calls == 0
            || (layer.nonce[..] == record[..NONCE_LEN]
                && same_bytes(
                    &layer.given,
                    &record[NONCE_LEN..NONCE_LEN + ARCHIVE_LAYER_LEN],
                )
                && layer.tag[..] == record[NONCE_LEN + ARCHIVE_LAYER_LEN..]
                && layer.aad == Bound::to(context)),
        "the outer layer is opened with the nonce, the ciphertext and the tag of the record, \
         bound to its context",
    );
    kani::assert(
        cipher.calls <= 1
            && (cipher.calls == 0
                || cipher.key == {
                    let mut key = [0; 32];
                    key.copy_from_slice(&archive.keys.0[..32]);
                    expected_archive_key(&key)
                }),
        "the seed is opened once, under the key of the store",
    );
    let inner = &body[ID_LEN + PUBLIC_LEN..];
    kani::assert(
        cipher.calls == 0
            || (cipher.nonce[..] == inner[..NONCE_LEN]
                && same_bytes(&cipher.given, &inner[NONCE_LEN..NONCE_LEN + PLAINTEXT_LEN])
                && cipher.tag[..] == inner[NONCE_LEN + PLAINTEXT_LEN..]
                && cipher.aad == Bound::to(context)),
        "the seed is opened with the nonce, the ciphertext and the tag of the inner layer, \
         bound to its context",
    );
    kani::assert(
        epoch_snapshot(&slots) == epoch_before,
        "a load changes no epoch",
    );
    let after = [
        snapshot(&slots.memory[0]),
        snapshot(&slots.memory[1]),
        snapshot(&slots.memory[2]),
    ];
    let mut loaded = before[2];
    loaded.occupancy = Occupancy::Loaded;
    loaded.purpose = Purpose::Archive;
    loaded.stages = Stages::one();
    loaded.lengths = [KeyLength::Bytes32; MEMBERS];
    loaded.keys = (seed, [0; 64], [0; 64]);
    loaded.ids = (seed_id, [0; ID_LEN], [0; ID_LEN]);
    loaded.unlocks = false;
    kani::assert(
        after[0] == before[0]
            && after[1] == before[1]
            && match result {
                Ok(handle) => {
                    handle.index == 2
                        && handle.generation == before[2].generation
                        && after[2] == loaded
                }
                Err(_) => after[2] == before[2],
            },
        "a refused load changes no slot, and one that succeeds only the free slot, which holds \
         the seed as a stored set of one for the archive with its identifier, in no transfer",
    );
    kani::cover!(result.is_ok(), "an archive key is loaded");
    kani::cover!(
        result == Err(Error::PublicKeyMismatch),
        "a changed public key is found"
    );
    kani::cover!(
        result == Err(Error::RecordRejected) && inner_named,
        "a record that holds no seed is refused"
    );
    kani::cover!(
        result == Err(Error::StaleRecord) && layer.accepted,
        "a record of another epoch is refused"
    );
    kani::cover!(
        result == Err(Error::CipherFailed),
        "a wrong answer of X-Wing loads nothing"
    );
    kani::cover!(
        result == Err(Error::DuplicateKey),
        "a seed held already is refused"
    );
}

/// From any state of two slots and of the epoch, with a change to the next under way or not,
/// for handles of these slots naming any slots and generations, any context of up to two bytes
/// and any output buffer, whatever the platform's source, X-Wing and the cipher do: a creation
/// of an archive key changes no slot and no epoch but its count of draws, and writes the record
/// only when it succeeds, starting with the nonce the source gave last, hedged with the key of
/// the epoch it is written in. It refuses an empty context, a stale handle, a store not of the
/// archive or a profile not for wrapping, a key from a secret as the profile, a change to the
/// last epoch and a wrong answer of X-Wing before it asks the source, then a failed source, and
/// a new key pair that does not agree with itself before it draws again.
#[kani::proof]
#[kani::unwind(1530)]
fn a_creation_of_an_archive_key_changes_no_slot_and_writes_only_when_it_succeeds() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (number, epoch_key, next_key) = (
        slots.epoch.number,
        first_half(&slots.epoch.key),
        first_half(&slots.epoch.next),
    );
    let count = slots.epoch.drawn;
    let (store, profile) = (forged(id), forged(id));
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let original: [u8; ARCHIVE_KEY_RECORD_LEN] = kani::any();
    let mut record = original;
    let mut entropy = AnyEntropy::new();
    let before = snapshots(&slots);

    let result = slots.create_archive_key_on_stack(
        store,
        profile,
        context,
        &mut entropy,
        &mut record,
        &xwing::KNOWN,
    );
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && slots.epoch.number == number
            && slots.epoch.changing == changing
            && first_half(&slots.epoch.key) == epoch_key
            && first_half(&slots.epoch.next) == next_key
            && slots.epoch.drawn == count.wrapping_add(u64::from(entropy.answered)),
        "a creation changes no slot and no epoch, and counts once each draw the source answers",
    );
    let (archive, stored) = (
        snapshot_at(&before, store.index),
        snapshot_at(&before, profile.index),
    );
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext) && entropy.calls == 0
        } else if !names_loaded(&before, &store) || !names_loaded(&before, &profile) {
            result == Err(Error::StaleHandle) && entropy.calls == 0
        } else if archive.purpose != Purpose::ArchiveWrap || stored.purpose != Purpose::Wrap {
            result == Err(Error::WrongPurpose) && entropy.calls == 0
        } else if stored.unlocks {
            result == Err(Error::WrongLevel) && entropy.calls == 0
        } else if changing && number == u64::MAX {
            result == Err(Error::EpochExhausted) && entropy.calls == 0
        } else if !xwing_answered() {
            result == Err(Error::CipherFailed) && entropy.calls == 0
        } else if entropy.failed {
            result == Err(Error::EntropyFailed)
        } else {
            result.is_ok()
                || result == Err(Error::DerivationFailed)
                || result == Err(Error::CipherFailed)
        },
        "a creation refuses a bad context, a stale handle, keys of other purposes, a key from \
         a secret, a change to the last epoch and a wrong answer of X-Wing before it asks the \
         source, and then a failed source",
    );
    kani::assert(
        any_failed() == (result == Err(Error::DerivationFailed))
            && (result.is_err() || !seal::model::any_seal_failed()),
        "a creation fails with DerivationFailed exactly when a derivation fails, and succeeds \
         only when every seal does",
    );
    let (paired, agreed) = (xwing::model::paired(), xwing::model::agreed());
    let (pair_seed, pair_public) = xwing::model::pair();
    kani::assert(
        if result.is_ok() {
            paired && agreed
        } else {
            !paired || agreed || (result == Err(Error::CipherFailed) && entropy.calls == 1)
        },
        "a creation succeeds only when its new key pair agrees with itself, and fails as \
         CipherFailed before it draws again when it does not",
    );
    kani::assert(
        !paired || pair_public == pair_seed,
        "the key pair checked is a seed and the public key it gives",
    );
    let writing = if changing { next_key } else { epoch_key };
    kani::assert(
        if result.is_ok() {
            let mut drawn = [0; 12];
            drawn.copy_from_slice(&entropy.written[..12]);
            entropy.calls == 3
                && record[..12]
                    == expected_hedge(&writing, count.wrapping_add(2), Branch::HedgeNonce, &drawn)
        } else {
            same(&record, &original)
        },
        "a creation writes its record only when it succeeds, after three draws: the seed, the \
         nonce of its inner layer and the nonce it starts with, hedged with the key of the epoch \
         it is written in",
    );
    kani::assert(
        !seal::model::any_seal_failed() || result == Err(Error::CipherFailed),
        "a creation fails with CipherFailed when a seal fails",
    );
    kani::assert(
        result != Err(Error::CipherFailed)
            || seal::model::any_seal_failed()
            || !xwing_answered()
            || (paired && !agreed),
        "a creation fails with CipherFailed only when a seal fails, X-Wing gives a wrong answer \
         or the new key pair does not agree with itself",
    );
    let (inner, layer) = (
        seal::model::sealed(seal::model::RECORD),
        seal::model::sealed(seal::model::LAYER),
    );
    let written_in = if changing {
        number.wrapping_add(1)
    } else {
        number
    };
    kani::assert(
        result.is_err()
            || (seal::model::kept_at(seal::model::RECORD)
                && seal::model::kept_at(seal::model::LAYER)
                && inner.key == expected_archive_key(&key_head(&archive))
                && Bound::kept(&inner) == Bound::to(context)
                && inner.given[1] == Purpose::Archive as u8
                && inner.given[3..19] == archive.ids.0
                && inner.given[19..27] == [0; 8]
                && layer.key
                    == expected_archive_layer_key(&stored.keys.0, stored.lengths[0], &writing)
                && Bound::kept(&layer) == Bound::to(context)
                && layer.given[..8] == written_in.to_le_bytes()
                && layer.given_end == inner.tag
                && record[..NONCE_LEN] == layer.nonce
                && record[NONCE_LEN..NONCE_LEN + 32] == layer.written
                && record[ARCHIVE_KEY_RECORD_LEN - TAG_LEN..] == layer.tag),
        "a creation seals the seed, as a set of the archive of epoch zero naming its store, \
         under the key of the store, and then the layer that names the epoch it is written in \
         under the key of the profile and that epoch, both bound to the context, and writes the \
         nonce, what the cipher wrote and the tag",
    );
    kani::cover!(result.is_ok(), "an archive key is created");
    kani::cover!(
        result.is_ok() && changing,
        "an archive key is created for the next epoch"
    );
    kani::cover!(
        result == Err(Error::WrongLevel),
        "a key from a secret takes no archive key"
    );
    kani::cover!(
        result == Err(Error::CipherFailed) && !xwing_answered(),
        "a wrong answer of X-Wing creates nothing"
    );
    kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
    kani::cover!(result == Err(Error::DerivationFailed), "a derivation fails");
    kani::cover!(
        paired && !agreed,
        "a key pair that does not agree with itself creates nothing"
    );
}

/// From any state of two slots and of the epoch, with a change to the next under way or not,
/// for handles of these slots naming any slots and generations, any record of an archive key,
/// any output buffer and any context of up to two bytes, whatever the platform's source and the
/// cipher do: a carry of the record of an archive key changes no slot and no epoch but its
/// count of draws. It refuses an empty context, then for each handle in turn a stale one, a set
/// not for wrapping and a key from a secret, then a missing change, before it decrypts. It
/// opens the record once, under the key derived from the first stored key and the key of this
/// epoch and with the record's nonce, and refuses it as `StaleRecord`, asking the source
/// nothing, unless the cipher accepts it and it names this epoch. It writes the output only
/// when it succeeds, starting with the nonce the source gave, hedged with the key of the next
/// epoch.
#[kani::proof]
#[kani::unwind(1530)]
fn a_carry_of_an_archive_key_changes_no_slot_and_writes_only_when_it_succeeds() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (number, epoch_key, next_key) = (
        slots.epoch.number,
        first_half(&slots.epoch.key),
        first_half(&slots.epoch.next),
    );
    let count = slots.epoch.drawn;
    let (profile, next_profile) = (forged(id), forged(id));
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let from: [u8; ARCHIVE_KEY_RECORD_LEN] = kani::any();
    let original: [u8; ARCHIVE_KEY_RECORD_LEN] = kani::any();
    let mut to = original;
    let mut entropy = AnyEntropy::new();
    let mut layer = AnyCipher::<ARCHIVE_LAYER_LEN>::new();
    let before = snapshots(&slots);

    let result = slots.carry_archive_key_on_stack(
        profile,
        next_profile,
        context,
        &mut entropy,
        (&from, &mut to),
        opening(|key, nonce, aad, buffer, tag| layer.open_bound(key, nonce, aad, buffer, tag)),
    );
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && slots.epoch.number == number
            && slots.epoch.changing == changing
            && first_half(&slots.epoch.key) == epoch_key
            && first_half(&slots.epoch.next) == next_key
            && slots.epoch.drawn == count.wrapping_add(u64::from(entropy.answered)),
        "a carry of an archive key changes no slot and no epoch, and counts once each draw \
         the source answers",
    );
    let refusal = |handle: &Handle<'_>| {
        let named = snapshot_at(&before, handle.index);
        if !names_loaded(&before, handle) {
            Some(Error::StaleHandle)
        } else if named.purpose != Purpose::Wrap {
            Some(Error::WrongPurpose)
        } else if named.unlocks {
            Some(Error::WrongLevel)
        } else {
            None
        }
    };
    let refused = refusal(&profile).or_else(|| refusal(&next_profile));
    let stored = snapshot_at(&before, profile.index);
    let current = layer.accepted && layer.written[..8] == number.to_le_bytes();
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext) && layer.calls == 0
        } else if let Some(error) = refused {
            result == Err(error) && layer.calls == 0
        } else if !changing {
            result == Err(Error::NoEpochChange) && layer.calls == 0
        } else if number == u64::MAX {
            result == Err(Error::EpochExhausted) && layer.calls == 0
        } else if layer.calls == 0 {
            result == Err(Error::DerivationFailed) && any_failed()
        } else if !current {
            result == Err(Error::StaleRecord) && entropy.calls == 0
        } else if entropy.failed {
            result == Err(Error::EntropyFailed)
        } else {
            result.is_ok()
                || result == Err(Error::DerivationFailed)
                || result == Err(Error::CipherFailed)
        },
        "a carry of an archive key refuses a bad context, a stale handle, a set not for \
         wrapping or a key from a secret, a missing change, a failed derivation, a record \
         that does not open in this epoch and a failed source",
    );
    kani::assert(
        any_failed() == (result == Err(Error::DerivationFailed))
            && (result.is_err() || !seal::model::any_seal_failed()),
        "a carry fails with DerivationFailed exactly when a derivation fails, and succeeds only \
         when the seal does",
    );
    kani::assert(
        layer.calls <= 1
            && (layer.calls == 0
                || (layer.key
                    == expected_archive_layer_key(&stored.keys.0, stored.lengths[0], &epoch_key)
                    && layer.nonce[..] == from[..NONCE_LEN]
                    && layer.aad == Bound::to(context))),
        "the record is opened once, under the key of the first stored key and this epoch, with \
         its own nonce and bound to its context",
    );
    kani::assert(
        (result == Err(Error::CipherFailed)) == seal::model::any_seal_failed(),
        "a carry of an archive key fails with CipherFailed exactly when its seal fails",
    );
    let next_stored = snapshot_at(&before, next_profile.index);
    let carried = seal::model::sealed(seal::model::LAYER);
    kani::assert(
        result.is_err()
            || (seal::model::kept_at(seal::model::LAYER)
                && carried.key
                    == expected_archive_layer_key(
                        &next_stored.keys.0,
                        next_stored.lengths[0],
                        &next_key,
                    )
                && Bound::kept(&carried) == Bound::to(context)
                && carried.given[..8] == number.wrapping_add(1).to_le_bytes()
                && carried.given[8..] == layer.written[8..32]
                && carried.given_end[..] == layer.written[ARCHIVE_LAYER_LEN - TAG_LEN..]
                && to[..NONCE_LEN] == carried.nonce
                && to[NONCE_LEN..NONCE_LEN + 32] == carried.written
                && to[ARCHIVE_KEY_RECORD_LEN - TAG_LEN..] == carried.tag),
        "a carry of an archive key seals what it opened with the number of the next epoch, \
         under the key of the second stored key and that epoch and bound to its context, and \
         writes the nonce, what the cipher wrote and the tag",
    );
    kani::assert(
        if result.is_ok() {
            let mut drawn = [0; 12];
            drawn.copy_from_slice(&entropy.written[..12]);
            to[..12] == expected_hedge(&next_key, count, Branch::HedgeNonce, &drawn)
        } else {
            same(&to, &original)
        },
        "a carry writes its output only when it succeeds, starting with the nonce hedged with \
         the key of the next epoch",
    );
    kani::cover!(result.is_ok(), "the record of an archive key is carried");
    kani::cover!(
        result.is_ok() && profile.index != next_profile.index,
        "it is carried to another stored key"
    );
    kani::cover!(
        result == Err(Error::StaleRecord) && layer.accepted,
        "a record of another epoch is refused"
    );
    kani::cover!(
        result == Err(Error::WrongLevel),
        "a key from a secret carries nothing"
    );
    kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
}

/// `before` as an end of the export under the key for transfers in slot `transfer`, whose
/// generation is `generation`, leaves it: that key idle with a chain of zero, and, when the end
/// is received, every set received under that key and generation free to be wrapped again.
fn ended(
    before: Snapshot,
    index: usize,
    transfer: usize,
    generation: u64,
    received: bool,
) -> Snapshot {
    let mut after = before;
    if received && before.pending == Some((transfer, generation)) {
        after.pending = None;
    }
    if index == transfer {
        after.chain = [0; TAG_LEN];
        after.direction = Direction::Idle;
    }
    after
}

/// From any state of two slots and of the epoch, with a change to the next under way or not,
/// for a handle of this set naming any slot and generation, any context of up to two bytes and
/// any end, whatever the platform's source and the cipher do: ending an export, or receiving
/// the end of one when `receiving` says so, refuses an empty context, a stale handle, a set that
/// is not a key for transfers, a key that carries no export (`NoTransfer`) and one that carries
/// an export the other way (`Unfinished`), in that order, before anything else. The end of an
/// export
/// is written only when it succeeds, starting with the nonce the source gave, hedged with the
/// key of this epoch, and each draw the source answers is counted once; the end received is
/// opened once, under the key the key for transfers derives, with its own nonce and tag, and
/// rejected as `RecordRejected` unless the cipher accepts it. Either succeeds exactly then, and
/// then leaves the key idle with a chain of zero, and a receipt lets every set received under
/// that key and its generation be wrapped again; nothing else changes, no epoch either, and a
/// failure changes no slot. Returns the outcome, the set in the slot other than the one the handle names, and the
/// handle.
fn end_from(receiving: bool) -> (Result<(), Error>, Snapshot, Handle<'static>) {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let transfer = forged(id);
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let before = snapshots(&slots);
    let live = names_loaded(&before, &transfer);
    let named = snapshot_at(&before, transfer.index);
    let serving = live && named.purpose == Purpose::Transfer;
    let way = if receiving {
        Direction::In
    } else {
        Direction::Out
    };
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let (number, keys) = (
        slots.epoch.number,
        (*slots.epoch.key.bytes(), *slots.epoch.next.bytes()),
    );
    let original: [u8; END_RECORD_LEN] = kani::any();
    let mut end = original;
    let mut entropy = AnyEntropy::new();
    let mut cipher = AnyCipher::<0>::new();

    let result = if receiving {
        slots.end_receive_on_stack(
            transfer,
            context,
            &end,
            opening(|key, nonce, aad, buffer, tag| cipher.open_bound(key, nonce, aad, buffer, tag)),
        )
    } else {
        slots.end_export_on_stack(transfer, context, &mut entropy, &mut end)
    };
    let refused_before = context.is_empty() || !serving || named.direction != way;
    kani::assert(
        if context.is_empty() {
            result == Err(Error::InvalidContext)
        } else if !live {
            result == Err(Error::StaleHandle)
        } else if !serving {
            result == Err(Error::WrongPurpose)
        } else if named.direction == Direction::Idle {
            result == Err(Error::NoTransfer)
        } else if named.direction != way {
            result == Err(Error::Unfinished)
        } else if receiving {
            if any_failed() {
                result == Err(Error::DerivationFailed)
            } else if cipher.accepted {
                result.is_ok()
            } else {
                result == Err(Error::RecordRejected)
            }
        } else if entropy.failed {
            result == Err(Error::EntropyFailed)
        } else {
            result.is_ok()
                || result == Err(Error::DerivationFailed)
                || result == Err(Error::CipherFailed)
        },
        "an end refuses a bad context, a stale handle, a key not for transfers, one that carries \
         no export and one that carries an export the other way; a receipt succeeds exactly \
         when the cipher accepts the end, and an export's end fails as its source, derivation \
         or cipher do",
    );
    kani::assert(
        refused_before || !any_failed() || result == Err(Error::DerivationFailed),
        "an end that a derivation fails fails with DerivationFailed",
    );
    kani::assert(
        slots.epoch.drawn == count.wrapping_add(u64::from(entropy.answered))
            && slots.epoch.number == number
            && slots.epoch.changing == changing
            && (*slots.epoch.key.bytes(), *slots.epoch.next.bytes()) == keys,
        "an end changes no epoch and no key of one, and counts once each draw the source \
         answers",
    );
    let mut key = [0; 32];
    key.copy_from_slice(&named.keys.0[..32]);
    kani::assert(
        !receiving
            || if refused_before || any_failed() {
                cipher.calls == 0
            } else {
                cipher.calls == 1
                    && cipher.key == expected_export_key(&key)
                    && cipher.nonce[..] == end[..NONCE_LEN]
                    && cipher.tag[..] == end[NONCE_LEN..]
                    && cipher.aad == Bound::chained(b"lethewis export end", &named.chain, context)
            },
        "an end is opened once, under the key the key for transfers derives, with its own nonce \
         and tag, bound to its context and chained to its key",
    );
    kani::assert(
        (result == Err(Error::CipherFailed)) == seal::model::any_seal_failed(),
        "an end fails with CipherFailed exactly when its seal fails",
    );
    let sealed = seal::model::sealed(seal::model::RECORD);
    kani::assert(
        receiving
            || result.is_err()
            || (seal::model::kept_at(seal::model::RECORD)
                && sealed.key == expected_export_key(&key)
                && Bound::kept(&sealed)
                    == Bound::chained(b"lethewis export end", &named.chain, context)
                && end[..NONCE_LEN] == sealed.nonce
                && end[NONCE_LEN..] == sealed.tag),
        "an end of an export is sealed under the key the key for transfers derives, bound to its \
         context and chained to its key, and writes the nonce and the tag",
    );
    // Worked out for a receipt too, so that its proof leaves no check of the export unreached.
    let mut drawn = [0; 12];
    drawn.copy_from_slice(&entropy.written[..12]);
    let hedged = expected_hedge(&epoch_key, count, Branch::HedgeNonce, &drawn);
    kani::assert(
        if result.is_ok() && !receiving {
            end[..NONCE_LEN] == hedged
        } else {
            end == original
        },
        "an end is written only when it succeeds, starting with the nonce hedged with the key \
         of this epoch",
    );
    if result.is_ok() {
        for index in 0..2 {
            kani::assert(
                snapshot(slot_at(&slots, index))
                    == ended(
                        snapshot_at(&before, index),
                        index,
                        transfer.index,
                        transfer.generation,
                        receiving,
                    ),
                "an end sets the chain and the direction of its key back, a receipt lets go \
                 the sets of its export, and nothing else changes",
            );
        }
    } else {
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a failed end changes no slot",
        );
    }
    kani::cover!(
        result == Err(Error::WrongPurpose),
        "a key not for transfers ends nothing"
    );
    kani::cover!(
        result == Err(Error::NoTransfer),
        "a key that carries no export ends none"
    );
    kani::cover!(
        result == Err(Error::Unfinished),
        "a key that carries an export the other way does not end it"
    );
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "the derivation fails"
    );
    (
        result,
        snapshot_at(&before, 1 - transfer.index.min(1)),
        transfer,
    )
}

/// The end of an export. The seal checks the cipher on a record first, so the unwinding is that
/// of a wrap.
#[kani::proof]
#[kani::unwind(234)]
fn an_end_of_an_export_is_written_only_when_it_succeeds() {
    let (result, _, _) = end_from(false);
    kani::cover!(result.is_ok(), "an export is ended");
    kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
    kani::cover!(result == Err(Error::CipherFailed), "the cipher fails");
}

/// The receipt of the end of an export.
#[kani::proof]
#[kani::unwind(65)]
fn an_end_received_lets_go_only_the_sets_of_its_export() {
    let (result, other, transfer) = end_from(true);
    let own = Some((transfer.index, transfer.generation));
    kani::cover!(
        result.is_ok() && other.pending == own,
        "a received set is let go"
    );
    kani::cover!(
        result.is_ok() && other.pending.is_some() && other.pending != own,
        "a set received under another key or generation waits"
    );
    kani::cover!(
        result == Err(Error::RecordRejected),
        "an end that does not open is rejected"
    );
}

/// From any state of three slots, for handles of this set naming any slots and generations: the
/// check a combination starts with refuses a stale handle, one set twice, a set not for
/// wrapping, one that is not a key from a secret, a salt not of 32 bytes and a want of a free
/// slot, in that order, and passes otherwise. What follows the check,
/// `a_combination_loads_its_key_and_releases_both` proves.
#[kani::proof]
#[kani::unwind(65)]
fn a_combination_refuses_in_order() {
    let mut memory = [any_slot(), any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (key, salt) = (forged(id), forged(id));
    let before = [
        snapshot(&slots.memory[0]),
        snapshot(&slots.memory[1]),
        snapshot(&slots.memory[2]),
    ];
    let named = |handle: &Handle<'_>| match handle.index {
        0 => before[0],
        1 => before[1],
        _ => before[2],
    };
    let live = |handle: &Handle<'_>| {
        handle.index < 3
            && named(handle).occupancy == Occupancy::Loaded
            && named(handle).generation == handle.generation
    };
    let result = slots.combinable(key, salt);
    let (first, second) = (named(&key), named(&salt));
    let expected = if !live(&key) || !live(&salt) {
        Err(Error::StaleHandle)
    } else if key.index == salt.index {
        Err(Error::SameKey)
    } else if first.purpose != Purpose::Wrap || second.purpose != Purpose::Wrap {
        Err(Error::WrongPurpose)
    } else if !first.unlocks || !second.unlocks {
        Err(Error::WrongLevel)
    } else if second.lengths[0] != KeyLength::Bytes32 {
        Err(Error::WrongLength)
    } else if before.iter().all(|slot| slot.occupancy != Occupancy::Free) {
        Err(Error::NoFreeSlot)
    } else {
        Ok((key.index, salt.index))
    };
    kani::assert(
        result == expected,
        "a combination is checked for the first reason to refuse it, and otherwise passes",
    );
    kani::cover!(
        result == Err(Error::StaleHandle),
        "a stale handle is refused"
    );
    kani::cover!(
        result == Err(Error::SameKey),
        "a set is not combined with itself"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose),
        "a set for external data is not combined"
    );
    kani::cover!(
        result == Err(Error::WrongLevel),
        "a stored key is not combined"
    );
    kani::cover!(result == Err(Error::WrongLength), "a long salt is refused");
    kani::cover!(result == Err(Error::NoFreeSlot), "no slot is free");
    kani::cover!(
        result.is_ok(),
        "two keys from a secret pass with a slot free"
    );
}

/// A loaded slot of any generation that holds a key from a secret of `length`, any bytes, with
/// any identifier.
fn any_secret(length: KeyLength) -> Slot {
    let mut slot = Slot::empty();
    slot.generation = kani::any();
    slot.occupancy = Occupancy::Loaded;
    slot.unlocks = true;
    let [first, ..] = &mut slot.keys;
    any_key(first);
    kani::assume(first.length() == length);
    slot.ids[0] = id_from_bytes(kani::any());
    slot
}

/// With keys from a secret of 32 bytes in the first two slots and the third free: combining them
/// through their live handles succeeds exactly when every derivation succeeds and neither holds
/// the new key. It then loads into the third slot a set of one 32-byte key from a secret, the
/// derivation of the first key with the second as the salt, with its identifier, and releases
/// both: their slots hold nothing and are past their generation. A refusal changes no slot.
/// Without a free slot the check before refuses, as `a_combination_refuses_in_order` proves;
/// other places of the three sets, the whole of a 64-byte key, and which key is the salt, which
/// the model of the derivation does not tell apart, unit tests check.
#[kani::proof]
#[kani::unwind(65)]
fn a_combination_loads_its_key_and_releases_both() {
    let length = KeyLength::Bytes32;
    let mut memory = [
        any_secret(length),
        any_secret(length),
        any_slot_in(Occupancy::Free),
    ];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = [
        snapshot(&slots.memory[0]),
        snapshot(&slots.memory[1]),
        snapshot(&slots.memory[2]),
    ];
    let handle = |index: usize| Handle {
        slots: id,
        index,
        generation: before[index].generation,
        memory: PhantomData,
    };
    let result = slots.combine(handle(0), handle(1));
    let mut salt = [0; 32];
    salt.copy_from_slice(&before[1].keys.0[..32]);
    let mut expected = [0; 64];
    expected[..32].copy_from_slice(&expected_combined(&before[0].keys.0, length, &salt));
    let key_id = expected_key_id(&expected, KeyLength::Bytes32);
    let held = before.iter().any(|snapshot| {
        snapshot.occupancy == Occupancy::Loaded
            && (0..MEMBERS).any(|position| {
                snapshot.stages.stage(position).is_some() && pick(&snapshot.ids, position) == key_id
            })
    });
    kani::assert(
        if any_failed() {
            result == Err(Error::DerivationFailed)
        } else if held {
            result == Err(Error::DuplicateKey)
        } else {
            result.is_ok()
        },
        "a combination needs a free slot, every derivation and a key held nowhere",
    );
    if let Ok(combined) = result {
        let now = snapshot(&slots.memory[2]);
        kani::assert(
            combined.index == 2
                && combined.generation == before[2].generation
                && now.occupancy == Occupancy::Loaded
                && now.keys == (expected, [0; 64], [0; 64])
                && now.lengths[0] == KeyLength::Bytes32
                && now.ids == (key_id, [0; ID_LEN], [0; ID_LEN])
                && now.stages == Stages::one()
                && now.purpose == Purpose::Wrap
                && now.unlocks
                && !now.changed
                && !now.recorded,
            "the free slot holds the combined key from a secret alone, with its identifier, \
             held by no record",
        );
        for index in 0..2 {
            let slot = &slots.memory[index];
            let generation = before[index].generation;
            kani::assert(
                wiped(slot)
                    && match generation.checked_add(1) {
                        Some(next) => slot.occupancy == Occupancy::Free && slot.generation == next,
                        None => slot.occupancy == Occupancy::Retired,
                    },
                "both keys it took are released",
            );
            kani::cover!(
                slot.occupancy == Occupancy::Retired,
                "a key it took retires its slot"
            );
        }
    } else {
        kani::assert(
            (0..3).all(|index| snapshot(&slots.memory[index]) == before[index]),
            "a refused combination changes no slot",
        );
    }
    kani::cover!(result.is_ok(), "two keys are combined");
    kani::cover!(
        result == Err(Error::DuplicateKey),
        "the combined key is held"
    );
    kani::cover!(result == Err(Error::DerivationFailed), "a derivation fails");
}

/// From any state of two slots, for a handle of this set naming any slot and generation: a
/// challenge is written exactly from a live key from a secret, the derivation of its key, and
/// is otherwise refused as `StaleHandle`, `WrongPurpose`, `WrongLevel` or `DerivationFailed`,
/// in that order, writing nothing. No slot changes either way.
#[kani::proof]
#[kani::unwind(65)]
fn only_a_key_from_a_secret_gives_a_challenge() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let handle = forged(id);
    let before = snapshots(&slots);
    let original: [u8; 32] = kani::any();
    let mut out = original;
    let result = slots.challenge(handle, &mut out);
    let named = snapshot_at(&before, handle.index);
    let expected = if !names_loaded(&before, &handle) {
        Err(Error::StaleHandle)
    } else if named.purpose != Purpose::Wrap {
        Err(Error::WrongPurpose)
    } else if !named.unlocks {
        Err(Error::WrongLevel)
    } else if any_failed() {
        Err(Error::DerivationFailed)
    } else {
        Ok(())
    };
    kani::assert(
        result == expected,
        "a challenge comes from a live key from a secret, and is otherwise refused for the \
         first reason",
    );
    kani::assert(
        if result.is_ok() {
            out == expected_challenge(&named.keys.0, named.lengths[0])
        } else {
            out == original
        },
        "a challenge writes exactly the derivation of the key, or nothing",
    );
    kani::assert(
        unchanged_except(&slots, &before, 2),
        "a challenge changes no slot",
    );
    kani::cover!(result.is_ok(), "a challenge is given");
    kani::cover!(
        result == Err(Error::WrongLevel),
        "a stored key gives no challenge"
    );
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "the derivation fails"
    );
}

fn any_position() -> Position {
    match kani::any::<u8>() % 3 {
        0 => Position::First,
        1 => Position::Second,
        _ => Position::Third,
    }
}

/// Promotes, disables, enables or destroys the key at any position through `handle`, and returns
/// what the call gave, what the transition of the stages gave, and whether it destroyed.
fn any_change(
    slots: &mut Slots<'_>,
    handle: Handle<'static>,
    chosen: Position,
    expected: &mut Stages,
) -> (Result<(), Error>, Result<(), Error>, bool) {
    let destroying = kani::any::<u8>() % 4 == 3;
    let (result, outcome) = match kani::any::<u8>() % 3 {
        _ if destroying => (
            slots.destroy(handle, chosen),
            expected.destroy(chosen.index()),
        ),
        0 => (
            slots.promote(handle, chosen),
            expected.promote(chosen.index()),
        ),
        1 => (
            slots.disable(handle, chosen),
            expected.disable(chosen.index()),
        ),
        _ => (
            slots.enable(handle, chosen),
            expected.enable(chosen.index()),
        ),
    };
    (result, outcome.map_err(Error::from), destroying)
}

/// From `memory`, with the slot `index` loaded and any position: promoting, disabling, enabling
/// and destroying through the live handle of that slot are refused as `WrongPurpose` for a set
/// neither for external data nor for data, then as `EpochChanging` during a change of epoch,
/// then as `Unfinished` for a set of a transfer that has not ended, then as `Unsaved` if the
/// set has changed in this epoch, and otherwise change its stages exactly as the transition of
/// the stages gives, marking the set changed, not wrapped for the next epoch and held by no
/// record; a refusal changes nothing; a destroy wipes the key and the identifier at the
/// position and leaves every other key as it was; the slot keeps its generation and purpose,
/// and no other slot changes.
fn change_in(mut memory: [Slot; 2], index: usize) {
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let named = snapshot_at(&before, index);
    let handle = Handle {
        slots: id,
        index,
        generation: named.generation,
        memory: PhantomData,
    };
    let chosen = any_position();
    let mut expected = named.stages;
    let (result, outcome, destroying) = any_change(&mut slots, handle, chosen, &mut expected);
    let other_purpose = named.purpose != Purpose::ExternalData && named.purpose != Purpose::Data;
    let unfinished = named.pending.is_some();
    let refused = other_purpose || changing || unfinished || named.changed;
    kani::assert(
        result
            == if other_purpose {
                Err(Error::WrongPurpose)
            } else if changing {
                Err(Error::EpochChanging)
            } else if unfinished {
                Err(Error::Unfinished)
            } else if named.changed {
                Err(Error::Unsaved)
            } else {
                outcome
            },
        "a change of a set neither for external data nor for data, during a change of epoch, \
         of a set of an unfinished transfer, or of a set changed in this epoch is refused, and \
         otherwise succeeds exactly when the transition of the stages does, or fails as it \
         does",
    );
    let applied = result.is_ok();
    let now = snapshot(slot_at(&slots, index));
    kani::assert(
        now.stages == if refused { named.stages } else { expected }
            && now.occupancy == Occupancy::Loaded
            && now.generation == named.generation
            && now.purpose == named.purpose
            && now.changed == (named.changed || applied)
            && now.sealed == (named.sealed && !applied)
            && now.recorded == (named.recorded && !applied)
            && now.pending == named.pending
            && now.chain == named.chain
            && now.direction == named.direction,
        "the set keeps its slot, generation, purpose and transfer, its stages change as the \
         transition gives, and a change marks it changed, not wrapped for the next epoch and \
         held by no record",
    );
    let wiped = destroying && applied;
    for position in 0..MEMBERS {
        kani::assert(
            if wiped && position == chosen.index() {
                pick(&now.keys, position) == [0; 64]
                    && at(&now.lengths, position) == KeyLength::Bytes32
                    && pick(&now.ids, position) == [0; ID_LEN]
            } else {
                pick(&now.keys, position) == pick(&named.keys, position)
                    && at(&now.lengths, position) == at(&named.lengths, position)
                    && pick(&now.ids, position) == pick(&named.ids, position)
            },
            "a destroy wipes the key and identifier at its position, and no other key changes",
        );
    }
    kani::assert(
        unchanged_except(&slots, &before, index),
        "a change touches no other slot",
    );
    kani::cover!(
        wiped && chosen == Position::Third,
        "a key at the last position is destroyed"
    );
    kani::cover!(
        !destroying && result.is_ok() && now.stages.primary() == chosen.index(),
        "a key is promoted"
    );
    kani::cover!(
        result == Err(Error::PrimaryKey),
        "a change is refused for the primary"
    );
    kani::cover!(
        result == Err(Error::WrongStage),
        "a change finds the wrong stage"
    );
    kani::cover!(
        result == Err(Error::Unsaved),
        "a set changes once in an epoch"
    );
    kani::cover!(
        result == Err(Error::EpochChanging),
        "no set changes during a change of epoch"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && named.purpose == Purpose::Wrap,
        "a set for wrapping takes no change"
    );
    kani::cover!(
        result.is_ok() && named.purpose == Purpose::Data,
        "a set for data changes"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && named.purpose == Purpose::Transfer,
        "a key for transfers takes no change"
    );
    kani::cover!(
        result == Err(Error::Unfinished),
        "a set of an unfinished transfer takes no change"
    );
}

/// A change through the first slot; with the next, through either slot of two in any state.
#[kani::proof]
#[kani::unwind(65)]
fn a_change_of_stage_in_the_first_slot() {
    change_in([any_slot_in(Occupancy::Loaded), any_slot()], 0);
}

/// A change through the second slot.
#[kani::proof]
#[kani::unwind(65)]
fn a_change_of_stage_in_the_second_slot() {
    change_in([any_slot(), any_slot_in(Occupancy::Loaded)], 1);
}

/// From any state of two slots, a handle of this set that names no loaded slot with its
/// generation is refused by every change of stage, at any position, and no slot changes.
#[kani::proof]
#[kani::unwind(65)]
fn a_change_of_stage_with_a_stale_handle_changes_nothing() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let handle = forged(id);
    kani::assume(!live(&slots, id, &handle));
    let before = snapshots(&slots);
    let (result, _, _) = any_change(&mut slots, handle, any_position(), &mut Stages::one());
    let mut source: [u8; 32] = kani::any();
    let original = source;
    let added = slots.add32(handle, &mut source);
    kani::assert(
        result == Err(Error::StaleHandle)
            && added == Err(Error::StaleHandle)
            && source == original
            && unchanged_except(&slots, &before, 2),
        "a stale handle is refused by every change and addition, and changes nothing",
    );
    kani::cover!(
        handle.index < 2 && slot_at(&slots, handle.index).occupancy == Occupancy::Loaded,
        "the stale handle names a loaded slot"
    );
}

/// From `memory`, with the slot `index` loaded and no change of epoch under way: adding a key
/// of 32 bytes, any bytes, through its live handle puts it into the first empty position of
/// the set, enabled, with the identifier derived from its bytes and its length alone, marks the
/// set changed and not wrapped for the next epoch, and changes nothing else; it fails as
/// `WrongPurpose` for a set not for external data, as `Unfinished` for a set of a transfer that
/// has not ended, as `Unsaved` if the set has changed in this epoch, as
/// the transition of the stages does when no position is empty or the set is exhausted, and
/// otherwise with DerivationFailed when the derivation fails and with DuplicateKey exactly when
/// a loaded slot holds a key with that identifier, for any purpose; the source is wiped exactly
/// when the addition succeeds, and a failed addition changes no slot. A generation fills a key
/// as a load does, which the proofs of a load cover. Returns the outcome and the set's purpose.
fn add_in(mut memory: [Slot; 2], index: usize) -> (Result<Position, Error>, Purpose) {
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(false);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let named = snapshot_at(&before, index);
    let handle = Handle {
        slots: id,
        index,
        generation: named.generation,
        memory: PhantomData,
    };
    let mut expected = named.stages;
    let position = expected.add();
    let mut source: [u8; 32] = kani::any();
    let original = source;
    let result = slots.add32(handle, &mut source);
    kani::assert(
        source == if result.is_ok() { [0; 32] } else { original },
        "an addition wipes its source exactly when it succeeds",
    );
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&original);
    let length = KeyLength::Bytes32;
    let key_id = expected_key_id(&bytes, length);
    kani::assert(
        match position {
            _ if named.purpose != Purpose::ExternalData => result == Err(Error::WrongPurpose),
            _ if named.pending.is_some() => result == Err(Error::Unfinished),
            _ if named.changed => result == Err(Error::Unsaved),
            Err(refused) => result == Err(Error::from(refused)),
            Ok(at) => {
                if failed() {
                    result == Err(Error::DerivationFailed)
                } else if held(&before, &key_id) {
                    result == Err(Error::DuplicateKey)
                } else {
                    result.ok() == Position::at(at)
                }
            }
        },
        "an addition fails as WrongPurpose for a set not for external data, as Unfinished for a \
         set of an unfinished transfer, as Unsaved for a set changed in this epoch, as the \
         stages refuse it, then with DerivationFailed when the derivation \
         fails, with DuplicateKey when the key is held, and otherwise succeeds at the first \
         empty position",
    );
    if let (Ok(added), Ok(at)) = (result, position) {
        let now = snapshot(slot_at(&slots, index));
        kani::assert(
            added.index() == at
                && now.stages == expected
                && now.occupancy == Occupancy::Loaded
                && now.generation == named.generation
                && now.purpose == named.purpose
                && now.changed
                && !now.sealed
                && !now.recorded
                && now.pending.is_none()
                && now.chain == named.chain
                && now.direction == named.direction,
            "the set keeps its slot, generation, purpose and transfer, its stages gain the key, \
             and it is marked changed, not wrapped for the next epoch and held by no record",
        );
        for position in 0..MEMBERS {
            kani::assert(
                if position == at {
                    pick(&now.keys, position) == bytes
                        && at_length(&now.lengths, position) == length
                        && pick(&now.ids, position) == key_id
                } else {
                    pick(&now.keys, position) == pick(&named.keys, position)
                        && at_length(&now.lengths, position) == at_length(&named.lengths, position)
                        && pick(&now.ids, position) == pick(&named.ids, position)
                },
                "the added key and its identifier are at its position, and no other key changes",
            );
        }
        kani::assert(
            unchanged_except(&slots, &before, index),
            "an addition touches no other slot",
        );
        kani::cover!(at == 2, "a key is added last");
    } else {
        kani::assert(
            unchanged_except(&slots, &before, 2),
            "a failed addition changes no slot",
        );
    }
    kani::cover!(result == Err(Error::DuplicateKey), "the added key is held");
    kani::cover!(
        result == Err(Error::Unsaved),
        "a set changed in this epoch takes no key"
    );
    kani::cover!(result == Err(Error::SetFull), "the set is full");
    kani::cover!(
        result == Err(Error::WrongPurpose),
        "a set not for external data takes no key"
    );
    kani::cover!(
        result == Err(Error::WrongPurpose) && named.purpose == Purpose::Data,
        "a set for data takes no key the caller gives"
    );
    kani::cover!(
        result == Err(Error::Unfinished),
        "a set of an unfinished transfer takes no key"
    );
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "the derivation fails"
    );
    (result, named.purpose)
}

/// Stands in for the platform: switches the root or fails, as chosen when made, erases with any
/// outcome, and remembers what it was asked.
struct AnyRoot {
    switches: bool,
    answer: Erasure,
    switched: Option<u64>,
    erased: Option<u64>,
}

impl Root for AnyRoot {
    fn switch(&mut self, next: u64) -> Result<(), RootFailed> {
        self.switched = Some(next);
        if self.switches {
            Ok(())
        } else {
            Err(RootFailed)
        }
    }

    fn erase(&mut self, old: u64) -> Erasure {
        self.erased = Some(old);
        self.answer
    }
}

fn any_root() -> AnyRoot {
    AnyRoot {
        switches: kani::any(),
        answer: match kani::any::<u8>() % 3 {
            0 => Erasure::Guaranteed,
            1 => Erasure::BestEffort,
            _ => Erasure::NotErased,
        },
        switched: None,
        erased: None,
    }
}

/// `snapshot` with its marks of a change set to `changed` and `sealed`.
fn marked(snapshot: Snapshot, changed: bool, sealed: bool) -> Snapshot {
    let mut marked = snapshot;
    marked.changed = changed;
    marked.sealed = sealed;
    marked
}

/// `snapshot` after a commit: saved, and held by a record of the new epoch exactly when it was
/// wrapped for it.
fn committed(snapshot: Snapshot) -> Snapshot {
    let mut committed = marked(snapshot, false, false);
    committed.recorded = snapshot.sealed;
    committed
}

/// From any state of two slots and of the epoch, with a change to the next under way or not:
/// beginning a change is refused while one is under way and in the last epoch, and otherwise
/// takes the key of the next epoch and wipes its source; abandoning, only while a change is
/// under way, wipes that key, has the platform erase the root made for it and forgets which
/// sets were wrapped for the next epoch; committing is refused without a change, while
/// a set changed in this epoch has not been wrapped for the next since, and when the platform
/// does not switch the root, and then changes nothing and asks the platform nothing more;
/// otherwise the next epoch with its key becomes this one, the old key is gone, every set
/// counts as saved and keeps its keys and stages, the platform is asked to switch to the next
/// epoch and then to erase the old, and its answer is returned.
#[kani::proof]
#[kani::unwind(65)]
fn an_epoch_changes_only_in_order() {
    let mut memory = [any_slot(), any_slot()];
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let (epoch, epoch_key, next_key) = (
        slots.epoch.number,
        *slots.epoch.key.bytes(),
        *slots.epoch.next.bytes(),
    );
    let unchanged = |slots: &Slots<'_>| {
        unchanged_except(slots, &before, 2)
            && slots.epoch.number == epoch
            && *slots.epoch.key.bytes() == epoch_key
            && *slots.epoch.next.bytes() == next_key
            && slots.epoch.changing == changing
    };
    match kani::any::<u8>() % 3 {
        0 => {
            let mut source: [u8; 32] = kani::any();
            let original = source;
            let result = slots.begin_epoch(&mut source);
            kani::assert(
                if changing {
                    result == Err(Error::EpochChanging)
                } else if epoch == u64::MAX {
                    result == Err(Error::EpochExhausted)
                } else {
                    result.is_ok()
                },
                "a change begins unless one is under way or this is the last epoch",
            );
            kani::assert(
                if result.is_ok() {
                    slots.epoch.changing
                        && first_half(&slots.epoch.next) == original
                        && slots.epoch.next.length() == KeyLength::Bytes32
                        && source == [0; 32]
                        && unchanged_except(&slots, &before, 2)
                        && slots.epoch.number == epoch
                        && *slots.epoch.key.bytes() == epoch_key
                } else {
                    source == original && unchanged(&slots)
                },
                "a change takes the key of the next epoch and wipes its source, and a refused \
                 one changes nothing",
            );
            kani::cover!(result.is_ok(), "a change begins");
        }
        1 => {
            let mut root = any_root();
            let result = slots.abandon_epoch(&mut root);
            let next = epoch.checked_add(1);
            kani::assert(
                if !changing {
                    result == Err(Error::NoEpochChange)
                } else if next.is_none() {
                    result == Err(Error::EpochExhausted)
                } else {
                    result == Ok(root.answer)
                },
                "a change is abandoned only while under way, returning how surely its root is \
                 erased",
            );
            kani::assert(
                if result.is_ok() {
                    !slots.epoch.changing
                        && *slots.epoch.next.bytes() == [0; 64]
                        && slots.epoch.number == epoch
                        && *slots.epoch.key.bytes() == epoch_key
                        && root.erased == next
                        && root.switched.is_none()
                        && (0..2).all(|index| {
                            snapshot(&slots.memory[index])
                                == marked(before[index], before[index].changed, false)
                        })
                } else {
                    unchanged(&slots) && root.erased.is_none()
                },
                "abandoning wipes the key of the next epoch, has the platform erase its root, \
                 forgets what was wrapped for it, and keeps this epoch and every set; a refusal \
                 changes nothing",
            );
            kani::cover!(result.is_ok(), "a change is abandoned");
        }
        _ => {
            let mut root = any_root();
            let unsaved = before.iter().any(|snapshot| {
                snapshot.occupancy == Occupancy::Loaded && snapshot.changed && !snapshot.sealed
            });
            let result = slots.commit_epoch(&mut root);
            let next = epoch.checked_add(1);
            kani::assert(
                if !changing {
                    result == Err(Error::NoEpochChange) && root.switched.is_none()
                } else if next.is_none() {
                    result == Err(Error::EpochExhausted) && root.switched.is_none()
                } else if unsaved {
                    result == Err(Error::Unsaved) && root.switched.is_none()
                } else if !root.switches {
                    result == Err(Error::RootFailed) && root.switched == next
                } else {
                    result == Ok(root.answer)
                },
                "a commit is refused without a change, with a set unsaved, and when the root \
                 is not switched, and otherwise returns how surely the old root is erased",
            );
            if result.is_ok() {
                kani::assert(
                    root.switched == next
                        && root.erased == Some(epoch)
                        && next == Some(slots.epoch.number)
                        && *slots.epoch.key.bytes() == next_key
                        && *slots.epoch.next.bytes() == [0; 64]
                        && !slots.epoch.changing
                        && (0..2).all(|index| {
                            snapshot(&slots.memory[index]) == committed(before[index])
                        }),
                    "a commit switches the root to the next epoch, erases the old, makes the \
                     next epoch and its key this one's, saves every set as it is, and leaves \
                     held by a record exactly the sets wrapped for the new epoch",
                );
            } else {
                kani::assert(
                    unchanged(&slots) && root.erased.is_none(),
                    "a refused commit changes nothing and erases nothing",
                );
            }
            kani::cover!(
                result.is_ok() && before.iter().any(|snapshot| snapshot.changed),
                "a change of a set is saved"
            );
            kani::cover!(result == Err(Error::Unsaved), "a set is not yet wrapped");
            kani::cover!(result == Err(Error::RootFailed), "the root is not switched");
        }
    }
}

fn at_length(lengths: &[KeyLength; MEMBERS], position: usize) -> KeyLength {
    at(lengths, position)
}

/// An addition through the first slot; with the next, an addition through either slot of two in
/// any state.
#[kani::proof]
#[kani::unwind(65)]
fn an_addition_in_the_first_slot() {
    let (result, purpose) = add_in([any_slot_in(Occupancy::Loaded), any_slot()], 0);
    kani::cover!(
        result.is_ok() && purpose == Purpose::ExternalData,
        "a key is added to a set of external data"
    );
}

/// An addition through the second slot.
#[kani::proof]
#[kani::unwind(65)]
fn an_addition_in_the_second_slot() {
    let (result, purpose) = add_in([any_slot(), any_slot_in(Occupancy::Loaded)], 1);
    kani::cover!(
        result.is_ok() && purpose == Purpose::ExternalData,
        "a key is added to a set of external data"
    );
}

/// With the first of two slots loaded, the second in any state and no change of epoch under
/// way: an addition of a key of either length, any bytes, through the live handle of the first,
/// by the code a generated addition runs, is refused as `WrongPurpose` for a set neither for
/// external data nor for data, as `Unfinished` for a set of a transfer that has not ended, as
/// `Unsaved` for a set changed in this epoch, and then as `WrongLength` exactly for a length
/// its purpose does not take, changing nothing; otherwise it fails only as the stages, the
/// source, the derivation or a key held already refuse it, and a success marks the set changed,
/// not wrapped for the next epoch and held by no record. No set takes an addition of 64 bytes.
#[kani::proof]
#[kani::unwind(65)]
fn a_long_addition_in_the_first_slot() {
    let mut memory = [any_slot_in(Occupancy::Loaded), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(false);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let before = snapshots(&slots);
    let handle = Handle {
        slots: id,
        index: 0,
        generation: before[0].generation,
        memory: PhantomData,
    };
    let length = any_length();
    let mut source = AnyEntropy::new();
    let result = slots.add(handle, length, false, |key, _| {
        key.fill(length, &mut source)
            .map_err(|EntropyError| Error::EntropyFailed)
    });
    let refusal =
        if before[0].purpose != Purpose::ExternalData && before[0].purpose != Purpose::Data {
            Some(Error::WrongPurpose)
        } else if before[0].pending.is_some() {
            Some(Error::Unfinished)
        } else if before[0].changed {
            Some(Error::Unsaved)
        } else if !allowed(before[0].purpose, length) {
            Some(Error::WrongLength)
        } else {
            None
        };
    kani::assert(
        match refusal {
            Some(refusal) => result == Err(refusal) && unchanged_except(&slots, &before, 2),
            None => {
                result.is_ok()
                    || [
                        Error::SetFull,
                        Error::SetExhausted,
                        Error::WrongStage,
                        Error::PrimaryKey,
                        Error::EntropyFailed,
                        Error::DerivationFailed,
                        Error::DuplicateKey,
                    ]
                    .iter()
                    .any(|&error| result == Err(error))
            }
        },
        "an addition is refused for the first reason, a length its purpose does not take among \
         them, and then changes nothing",
    );
    let now = snapshot(&slots.memory[0]);
    kani::assert(
        result.is_err() || (now.changed && !now.sealed && !now.recorded),
        "a set that takes a key is marked changed, not wrapped for the next epoch and held by no \
         record",
    );
    kani::cover!(
        result == Err(Error::WrongLength),
        "a set of external data refuses a long key"
    );
    kani::cover!(
        refusal.is_none() && result.is_ok(),
        "a key of a length its purpose takes is added"
    );
    kani::cover!(
        result.is_ok() && before[0].purpose == Purpose::Data,
        "a key for data is added"
    );
    kani::cover!(result == Err(Error::EntropyFailed), "the source fails");
}

/// From any state of two slots during a change of epoch, for a handle of this set naming any
/// slot and generation: every change of stage and an addition are refused, as `StaleHandle` if
/// the handle is not live, as `WrongPurpose` for a change of a set neither for external data
/// nor for data and for an addition of a key the caller gives to a set not for external data,
/// and as `EpochChanging` otherwise; the key given is left as it was, and nothing changes. A
/// generated key goes through the same code as the addition, which refuses before it fills the
/// slot.
#[kani::proof]
#[kani::unwind(65)]
fn no_set_changes_during_a_change_of_epoch() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(true);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let handle = forged(id);
    let live = live(&slots, id, &handle);
    let before = snapshots(&slots);
    let purpose = snapshot_at(&before, handle.index).purpose;
    let unstaged = live && purpose != Purpose::ExternalData && purpose != Purpose::Data;
    let wrapping = live && purpose != Purpose::ExternalData;
    let (result, _, _) = any_change(&mut slots, handle, any_position(), &mut Stages::one());
    let mut source: [u8; 32] = kani::any();
    let original = source;
    let added = slots.add32(handle, &mut source);
    let refusal = |other: bool| {
        if !live {
            Error::StaleHandle
        } else if other {
            Error::WrongPurpose
        } else {
            Error::EpochChanging
        }
    };
    kani::assert(
        result == Err(refusal(unstaged))
            && added == Err(refusal(wrapping))
            && source == original
            && unchanged_except(&slots, &before, 2)
            && slots.epoch.changing,
        "during a change of epoch no set changes or takes a key, and nothing changes",
    );
    kani::cover!(live && !wrapping, "a live set is refused");
}

/// The associated data of a chunk of a block bound to `context`, of up to two bytes, written
/// out from the layout: the label, the version, the length of the context, and the context.
fn data_bound(context: &[u8]) -> Bound {
    let mut bytes = [0; seal::model::AAD_HEAD];
    bytes[..19].copy_from_slice(b"lethewis data block");
    bytes[19] = 1;
    bytes[20] = u8::try_from(context.len()).unwrap_or(0);
    bytes[21] = context.first().copied().unwrap_or(0);
    bytes[22] = context.get(1).copied().unwrap_or(0);
    Bound {
        bytes,
        length: context.len().wrapping_add(21),
    }
}

/// The first 32 bytes of the key at `position` of `snapshot`.
fn key_head_at(snapshot: &Snapshot, position: usize) -> [u8; 32] {
    let mut key = [0; 32];
    key.copy_from_slice(&pick(&snapshot.keys, position)[..32]);
    key
}

/// The nonce of the chunk numbered `index`, written out from the layout: the number, least
/// significant byte first, three zero bytes, and 1 for the last chunk or 0.
fn nonce_of(index: u64, last: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    nonce[..8].copy_from_slice(&index.to_le_bytes());
    nonce[11] = u8::from(last);
    nonce
}

/// The first bytes of a chunk, zero past its end, read one by one.
fn chunk_head(chunk: &[u8]) -> [u8; 17] {
    core::array::from_fn(|at| chunk.get(at).copied().unwrap_or(0))
}

/// Any cipher on a chunk of any length: it writes any bytes, and gives any tag or fails, or
/// accepts or refuses, at will, and keeps what it was given.
struct AnyChunk {
    calls: usize,
    key: [u8; CIPHER_KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: Bound,
    given: [u8; 17],
    written: [u8; 17],
    tag: [u8; TAG_LEN],
    failed: bool,
}

impl AnyChunk {
    fn new() -> Self {
        Self {
            calls: 0,
            key: [0; CIPHER_KEY_LEN],
            nonce: [0; NONCE_LEN],
            aad: Bound::none(),
            given: [0; 17],
            written: [0; 17],
            tag: [0; TAG_LEN],
            failed: false,
        }
    }

    fn take(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) {
        (self.key, self.nonce, self.aad, self.given) =
            (*key, *nonce, Bound::of(aad), chunk_head(buffer));
        for byte in buffer.iter_mut() {
            *byte = kani::any();
        }
        self.written = chunk_head(buffer);
        self.failed = kani::any();
        self.calls = self.calls.saturating_add(1);
    }

    fn seal(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SealFailed> {
        self.take(key, nonce, aad, buffer);
        self.tag = kani::any();
        if self.failed {
            Err(SealFailed)
        } else {
            Ok(self.tag)
        }
    }

    fn open(
        &mut self,
        key: &[u8; CIPHER_KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Rejected> {
        self.take(key, nonce, aad, buffer);
        self.tag = *tag;
        if self.failed { Err(Rejected) } else { Ok(()) }
    }

    /// [`AnyChunk::open`], as the stand-in for the cipher it is in the proofs: one closure for
    /// every proof, so that one that opens reaches it for one that never does.
    fn opening(
        &mut self,
    ) -> impl FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8],
        &[u8; TAG_LEN],
    ) -> Result<(), Rejected>
    + '_ {
        |key, nonce, aad, buffer, tag| self.open(key, nonce, aad, buffer, tag)
    }

    /// [`AnyChunk::seal`], as the stand-in for the cipher it is in the proofs, one closure for
    /// every proof.
    fn sealing(
        &mut self,
    ) -> impl FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8],
    ) -> Result<[u8; TAG_LEN], SealFailed>
    + '_ {
        |key, nonce, aad, buffer| self.seal(key, nonce, aad, buffer)
    }
}

/// `seal`, as the stand-in for the cipher of a chunk it is in the proofs.
fn chunk_sealing<F>(seal: F) -> F
where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8],
    ) -> Result<[u8; TAG_LEN], SealFailed>,
{
    seal
}

/// `open`, as the stand-in for the cipher of a chunk it is in the proofs.
fn chunk_opening<F>(open: F) -> F
where
    F: FnMut(
        &[u8; CIPHER_KEY_LEN],
        &[u8; NONCE_LEN],
        &[u8],
        &mut [u8],
        &[u8; TAG_LEN],
    ) -> Result<(), Rejected>,
{
    open
}

/// Any context of one or two bytes, as a block under way was begun with.
fn any_block_context(bytes: &[u8; 2]) -> &[u8] {
    let length: usize = kani::any();
    kani::assume(length == 1 || length == 2);
    &bytes[..length]
}

/// From any state of two slots and of the epoch, for a handle of these slots naming any slot and
/// generation, any context of up to two bytes and any header, whatever the platform's source does:
/// beginning a block changes no slot, and the epoch only by the count of the draws the source
/// answers. It refuses an empty context, a stale handle, a set not for data, one of an unfinished
/// transfer and one no record of this epoch holds as it is, in that order, before it draws; then a
/// failed source and a failed derivation. A block begun writes into its header the salt, the hedge
/// of the one draw under the key of this epoch, and the check derived from the primary key of the
/// set and that salt; it names the set, the primary's position, the set's revision, the salt and
/// the associated data of the context, from the first chunk. A refused one writes nothing.
#[kani::proof]
#[kani::unwind(65)]
fn a_block_begins_under_the_primary_of_a_recorded_set() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let (number, key, next, _, _) = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let set = forged(id);
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let original: [u8; BLOCK_HEADER_LEN] = kani::any();
    let mut header = original;
    let mut entropy = FirstKept::new();

    let result = slots.begin_seal_in(set, context, &mut entropy, &mut header);
    let draws = count.wrapping_add(u64::from(entropy.source.answered));
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == (number, key, next, changing, draws),
        "beginning a block changes no slot and no epoch, and counts once each draw the source \
         answers",
    );
    let named = snapshot_at(&before, set.index);
    let asked = entropy.source.calls;
    let error = result.as_ref().err().copied();
    kani::assert(
        if context.is_empty() {
            error == Some(Error::InvalidContext) && asked == 0
        } else if !names_loaded(&before, &set) {
            error == Some(Error::StaleHandle) && asked == 0
        } else if named.purpose != Purpose::Data {
            error == Some(Error::WrongPurpose) && asked == 0
        } else if named.pending.is_some() {
            error == Some(Error::Unfinished) && asked == 0
        } else if !named.recorded {
            error == Some(Error::Unsaved) && asked == 0
        } else if entropy.source.failed {
            error == Some(Error::EntropyFailed) && asked == 1
        } else if any_failed() {
            error == Some(Error::DerivationFailed) && asked == 1
        } else {
            result.is_ok() && asked == 1
        },
        "a block refuses a bad context, a stale handle, a set not for data and one no record \
         holds before it draws, then a failed source and a failed derivation, and draws at \
         most once",
    );
    if let Ok(sealing) = &result {
        let mut drawn = [0; SALT_LEN];
        drawn.copy_from_slice(&entropy.first[..SALT_LEN]);
        let salt = expected_hedge(&epoch_key, count, Branch::HedgeSalt, &drawn);
        let primary = named.stages.primary();
        kani::assert(
            header[..SALT_LEN] == salt
                && header[SALT_LEN..] == expected_data_check(&key_head_at(&named, primary), &salt),
            "the header holds the salt hedged from the one draw and the check of the primary \
             key and the salt",
        );
        kani::assert(
            sealing.set == set
                && sealing.at.index() == primary
                && sealing.revision == named.stages.revision()
                && sealing.salt == salt
                && Bound::of(sealing.associated.bytes()) == data_bound(context)
                && sealing.next == 0,
            "the block names the set, its primary, its revision, the salt and the associated \
             data of the context, from the first chunk",
        );
    } else {
        kani::assert(header == original, "a refused beginning writes nothing");
    }
    kani::cover!(result.is_ok(), "a block begins");
    kani::cover!(
        result.is_ok() && changing && named.stages.primary() == 2,
        "a block begins under a primary at the last position during a change of epoch"
    );
    kani::cover!(
        error == Some(Error::Unfinished),
        "a set of an unfinished transfer begins no block"
    );
    kani::cover!(
        error == Some(Error::Unsaved),
        "a set no record holds begins no block"
    );
    kani::cover!(
        error == Some(Error::WrongPurpose),
        "a set not for data begins no block"
    );
    kani::cover!(error == Some(Error::EntropyFailed), "the source fails");
    kani::cover!(error == Some(Error::DerivationFailed), "a derivation fails");
}

/// A block under way in any state: any handle of these slots, position, revision, salt and
/// next chunk, and the associated data of `context`. Only a beginning makes one, which the
/// proof above covers; this covers every state one can be in afterwards, but for its set,
/// which a proof takes to be for data while the slot it names is loaded with its generation:
/// a beginning names only a set for data, and a set keeps its purpose until it is released,
/// which gives its slot another generation.
fn any_sealing(id: usize, context: &[u8]) -> Sealing<'static> {
    Sealing {
        set: forged(id),
        at: any_position(),
        revision: kani::any(),
        salt: kani::any(),
        associated: AssociatedData::of_data(context).unwrap(),
        next: kani::any(),
    }
}

/// From any state of two slots and of the epoch, any block under way and any chunk of up to 17
/// bytes, the last or one of a full 16, whatever the cipher does: sealing a chunk changes no
/// slot and no epoch. It refuses a last chunk longer than a chunk or empty after others, a set
/// that is not held, one that has changed since the block began and one no record holds, and a
/// block that has run out of numbers, before it derives; then a failed derivation, before it
/// seals. It seals once, under the key derived from the key at the block's position and its
/// salt, with the nonce of the chunk's number and mark of the last and the associated data the
/// block was begun with, and then writes the tag and moves on to the next chunk; a refused or
/// failed chunk writes no tag and keeps the block where it was.
#[kani::proof]
#[kani::unwind(65)]
fn a_chunk_is_sealed_under_the_key_its_block_began_with() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let context_bytes: [u8; 2] = kani::any();
    let context = any_block_context(&context_bytes);
    let mut sealing = any_sealing(id, context);
    let named = snapshot_at(&before, sealing.set.index);
    kani::assume(!names_loaded(&before, &sealing.set) || named.purpose == Purpose::Data);
    let (set, at, revision, salt, next) = (
        sealing.set,
        sealing.at,
        sealing.revision,
        sealing.salt,
        sealing.next,
    );
    let bound = Bound::of(sealing.associated.bytes());
    let last: bool = kani::any();
    let length: usize = if last { kani::any() } else { 16 };
    kani::assume(length <= 17);
    let original: [u8; 17] = kani::any();
    let mut buffer = original;
    let original_tag: [u8; TAG_LEN] = kani::any();
    let mut tag = original_tag;
    let mut cipher = AnyChunk::new();
    let seal_with = chunk_sealing(|key, nonce, aad, buffer| cipher.seal(key, nonce, aad, buffer));

    let result = if last {
        slots.seal_last_in::<16>(&mut sealing, &mut buffer[..length], &mut tag, seal_with)
    } else {
        slots.seal_chunk_on_stack(
            &mut sealing,
            &mut buffer[..length],
            false,
            &mut tag,
            seal_with,
        )
    };
    kani::assert(
        unchanged_except(&slots, &before, 2) && epoch_snapshot(&slots) == epoch_before,
        "sealing a chunk changes no slot and no epoch",
    );
    kani::assert(
        if last && (length > 16 || (length == 0 && next != 0)) {
            result == Err(Error::WrongChunk) && cipher.calls == 0
        } else if !names_loaded(&before, &set) || named.stages.revision() != revision {
            result == Err(Error::StaleHandle) && cipher.calls == 0
        } else if !named.recorded {
            result == Err(Error::Unsaved) && cipher.calls == 0
        } else if next == u64::MAX {
            result == Err(Error::WrongChunk) && cipher.calls == 0
        } else if any_failed() {
            result == Err(Error::DerivationFailed) && cipher.calls == 0
        } else if cipher.failed {
            result == Err(Error::CipherFailed)
        } else {
            result.is_ok()
        },
        "a chunk is refused for its length, a set not held or changed, one no record holds and \
         a block out of numbers, then for a failed derivation, before the cipher runs, and \
         then fails exactly when the cipher does",
    );
    kani::assert(
        cipher.calls == 0
            || (cipher.calls == 1
                && cipher.key == expected_data_chunk(&key_head_at(&named, at.index()), &salt)
                && cipher.nonce == nonce_of(next, last)
                && cipher.aad == data_bound(context)
                && cipher.given == chunk_head(&original[..length])),
        "the chunk is sealed once, under the key of its position and salt, with its nonce and \
         the associated data of the block",
    );
    kani::assert(
        sealing.set == set
            && sealing.at == at
            && sealing.revision == revision
            && sealing.salt == salt
            && Bound::of(sealing.associated.bytes()) == bound,
        "a chunk changes nothing of its block but the next number",
    );
    if result.is_ok() {
        kani::assert(
            tag == cipher.tag
                && chunk_head(&buffer[..length]) == cipher.written
                && sealing.next == next.wrapping_add(1),
            "a sealed chunk holds what the cipher wrote, its tag is written, and the block \
             moves on",
        );
    } else {
        kani::assert(
            tag == original_tag
                && sealing.next == next
                && (cipher.calls != 0 || buffer == original),
            "a refused or failed chunk writes no tag, keeps the block where it was, and is \
             left as it was unless the cipher ran",
        );
    }
    kani::cover!(
        result.is_ok() && last && length == 16,
        "a full last chunk is sealed"
    );
    kani::cover!(
        result.is_ok() && last && length == 0 && next == 0,
        "the empty data are sealed"
    );
    kani::cover!(
        result.is_ok() && !last && at == Position::Third,
        "a chunk is sealed under the last position"
    );
    kani::cover!(
        result == Err(Error::WrongChunk) && last && length == 0,
        "an empty last chunk after others is refused"
    );
    kani::cover!(
        result == Err(Error::WrongChunk) && length == 17,
        "a last chunk longer than a chunk is refused"
    );
    kani::cover!(
        result == Err(Error::WrongChunk) && next == u64::MAX && length <= 16,
        "a block out of numbers is refused"
    );
    kani::cover!(
        result == Err(Error::StaleHandle) && names_loaded(&before, &set),
        "a set changed since the block began is refused"
    );
    kani::cover!(
        result == Err(Error::Unsaved),
        "a set no record holds is refused"
    );
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "the derivation fails"
    );
    kani::cover!(result == Err(Error::CipherFailed), "the cipher fails");
}

/// From any state of two slots and of the epoch, for a handle of these slots naming any slot and
/// generation, any context of up to two bytes, any header and any length of a block, beginning to
/// read a block changes no slot and no epoch. It refuses an empty context, a stale handle, a set
/// not for data, one of an unfinished transfer and a length no block has, in that order, before it
/// derives; it then derives the check of the key at every position the set fills, one derivation
/// each, with the salt of the header, and refuses a failed one. It reads the block under the first
/// position whose check is the header's, as `KeyDisabled` if that key is disabled, and as
/// `RecordRejected` if none is: an empty position matches nothing, though the header hold the check
/// of an empty key. The block it reads names the set, the position, the revision, the salt and the
/// associated data of the context, from the first chunk, and holds as many chunks as the length
/// gives.
#[kani::proof]
#[kani::unwind(65)]
fn a_block_opens_only_under_the_key_its_header_names() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let set = forged(id);
    let context_bytes: [u8; 2] = kani::any();
    let context = any_context(&context_bytes);
    let header: [u8; BLOCK_HEADER_LEN] = kani::any();
    let block: u64 = kani::any();
    let runs_before = runs();

    let result = slots.begin_open_in::<16>(set, context, &header, block);
    let derived = runs().wrapping_sub(runs_before);
    kani::assert(
        unchanged_except(&slots, &before, 2) && epoch_snapshot(&slots) == epoch_before,
        "beginning to read a block changes no slot and no epoch",
    );
    let named = snapshot_at(&before, set.index);
    let mut salt = [0; SALT_LEN];
    salt.copy_from_slice(&header[..SALT_LEN]);
    let stages = [
        named.stages.stage(0),
        named.stages.stage(1),
        named.stages.stage(2),
    ];
    let filled = stages.map(|stage| stage.is_some());
    let matches = [0, 1, 2].map(|position| {
        at(&filled, position)
            && header[SALT_LEN..] == expected_data_check(&key_head_at(&named, position), &salt)
    });
    let found = (0..MEMBERS).find(|&position| at(&matches, position));
    let len = data_len_in::<16>(block);
    let error = result.as_ref().err().copied();
    kani::assert(
        if context.is_empty() {
            error == Some(Error::InvalidContext) && derived == 0
        } else if !names_loaded(&before, &set) {
            error == Some(Error::StaleHandle) && derived == 0
        } else if named.purpose != Purpose::Data {
            error == Some(Error::WrongPurpose) && derived == 0
        } else if named.pending.is_some() {
            error == Some(Error::Unfinished) && derived == 0
        } else if len.is_none() {
            error == Some(Error::RecordRejected) && derived == 0
        } else if any_failed() {
            error == Some(Error::DerivationFailed)
        } else {
            derived == filled.iter().map(|&full| u8::from(full)).sum::<u8>()
                && match found {
                    None => error == Some(Error::RecordRejected),
                    Some(position) if at(&stages, position) == Some(Status::Disabled) => {
                        error == Some(Error::KeyDisabled)
                    }
                    Some(position) => result
                        .as_ref()
                        .is_ok_and(|opening| opening.at.index() == position),
                }
        },
        "reading refuses a bad context, a stale handle, a set not for data and a length no \
         block has before it derives, then derives the check of every key of the set, and \
         reads under the first whose check the header holds, refusing a disabled one, and none",
    );
    if let (Ok(opening), Some(len)) = (&result, len) {
        let (chunks, last) = chunks_in::<16>(len);
        kani::assert(
            opening.set == set
                && opening.revision == named.stages.revision()
                && opening.salt == salt
                && Bound::of(opening.associated.bytes()) == data_bound(context)
                && opening.next == 0
                && opening.chunks == chunks
                && opening.last == last,
            "the block read names the set, its revision, the salt and the associated data of \
             the context, from the first chunk, and holds the chunks of its length",
        );
    }
    kani::cover!(
        result.is_ok() && found == Some(1),
        "a block opens under the second position"
    );
    kani::cover!(
        result.is_ok() && found.is_some_and(|position| position != named.stages.primary()),
        "a block opens under a key that is not the primary"
    );
    kani::cover!(
        error == Some(Error::KeyDisabled),
        "a block under a disabled key is refused"
    );
    kani::cover!(
        error == Some(Error::Unfinished),
        "a block under a set of an unfinished transfer is not read"
    );
    kani::cover!(
        error == Some(Error::RecordRejected)
            && len.is_some()
            && !at(&filled, 2)
            && header[SALT_LEN..] == expected_data_check(&[0; 32], &salt),
        "an empty position does not match the check of an empty key"
    );
    kani::cover!(
        error == Some(Error::RecordRejected) && len.is_none() && block > 64,
        "a length no block has is refused"
    );
    kani::cover!(error == Some(Error::DerivationFailed), "a derivation fails");
}

/// A block being read in any state: any handle of these slots, position, revision, salt, next
/// chunk, count of chunks and length of the last, and the associated data of `context`. Only a
/// beginning makes one, which the proof above covers; this covers every state one can be in
/// afterwards, its set taken to be for data as for a block under way.
fn any_opening(id: usize, context: &[u8]) -> Opening<'static> {
    Opening {
        set: forged(id),
        at: any_position(),
        revision: kani::any(),
        salt: kani::any(),
        associated: AssociatedData::of_data(context).unwrap(),
        next: kani::any(),
        chunks: kani::any(),
        last: kani::any(),
    }
}

/// From any state of two slots and of the epoch, any block being read and any chunk of up to
/// 17 bytes, the last or one of a full 16, whatever the cipher does: opening a chunk changes no
/// slot and no epoch. It refuses a last chunk where more are due or of another length than the
/// block's last, another where the last is due, a set that is not held and one that has
/// changed since the block began to be read, before it derives; then a failed derivation,
/// before it opens. It opens once, under the key derived from the key at the block's position
/// and its salt, with the nonce of the chunk's number and mark of the last, the associated data
/// of the block and the tag given, refuses what the cipher refuses, and moves on to the next
/// chunk only when the chunk opens.
#[kani::proof]
#[kani::unwind(65)]
fn a_chunk_opens_only_as_the_next_of_its_block() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let context_bytes: [u8; 2] = kani::any();
    let context = any_block_context(&context_bytes);
    let mut opening = any_opening(id, context);
    let named = snapshot_at(&before, opening.set.index);
    kani::assume(!names_loaded(&before, &opening.set) || named.purpose == Purpose::Data);
    let (set, at, revision, salt, next, chunks, last_len) = (
        opening.set,
        opening.at,
        opening.revision,
        opening.salt,
        opening.next,
        opening.chunks,
        opening.last,
    );
    let last: bool = kani::any();
    let length: usize = if last { kani::any() } else { 16 };
    kani::assume(length <= 17);
    let original: [u8; 17] = kani::any();
    let mut buffer = original;
    let tag: [u8; TAG_LEN] = kani::any();
    let mut cipher = AnyChunk::new();
    let open_with =
        chunk_opening(|key, nonce, aad, buffer, tag| cipher.open(key, nonce, aad, buffer, tag));

    let result = if last {
        slots.open_last_in(&mut opening, &mut buffer[..length], &tag, open_with)
    } else {
        slots.open_next_in(&mut opening, &mut buffer[..length], &tag, open_with)
    };
    kani::assert(
        unchanged_except(&slots, &before, 2) && epoch_snapshot(&slots) == epoch_before,
        "opening a chunk changes no slot and no epoch",
    );
    // In numbers of 128 bits, apart from the code: the chunk after `next` is the last when it
    // is the count's last.
    let after = u128::from(next) + 1;
    let out_of_order = if last {
        after != u128::from(chunks) || u64::try_from(length) != Ok(last_len)
    } else {
        after >= u128::from(chunks)
    };
    let bound = Bound::of(opening.associated.bytes());
    kani::assert(
        if out_of_order {
            result == Err(Error::WrongChunk) && cipher.calls == 0
        } else if !names_loaded(&before, &set) || named.stages.revision() != revision {
            result == Err(Error::StaleHandle) && cipher.calls == 0
        } else if any_failed() {
            result == Err(Error::DerivationFailed) && cipher.calls == 0
        } else if cipher.failed {
            result == Err(Error::RecordRejected)
        } else {
            result.is_ok()
        },
        "a chunk out of the order or length of its block, and one of a set not held or \
         changed, is refused before anything is derived, a failed derivation before the cipher \
         runs, and then a chunk the cipher refuses",
    );
    kani::assert(
        cipher.calls == 0
            || (cipher.calls == 1
                && cipher.key == expected_data_chunk(&key_head_at(&named, at.index()), &salt)
                && cipher.nonce == nonce_of(next, last)
                && cipher.aad == data_bound(context)
                && cipher.given == chunk_head(&original[..length])
                && cipher.tag == tag),
        "the chunk is opened once, under the key of its position and salt, with its nonce, the \
         associated data of the block and its tag",
    );
    kani::assert(
        opening.set == set
            && opening.at == at
            && opening.revision == revision
            && opening.salt == salt
            && opening.chunks == chunks
            && opening.last == last_len
            && Bound::of(opening.associated.bytes()) == bound,
        "a chunk changes nothing of its block but the next number",
    );
    kani::assert(
        if result.is_ok() {
            u128::from(opening.next) == after && chunk_head(&buffer[..length]) == cipher.written
        } else {
            opening.next == next && (cipher.calls != 0 || buffer == original)
        },
        "an opened chunk holds what the cipher wrote and the block moves on; otherwise it \
         stays where it was, and the chunk is left as it was unless the cipher ran",
    );
    kani::cover!(result.is_ok() && last, "the last chunk opens");
    kani::cover!(
        result.is_ok() && !last && at == Position::Third,
        "a chunk opens under the last position"
    );
    kani::cover!(
        result == Err(Error::WrongChunk) && last && after == u128::from(chunks),
        "a last chunk of another length is refused"
    );
    kani::cover!(
        result == Err(Error::WrongChunk) && last && after < u128::from(chunks),
        "a last chunk before the others is refused"
    );
    kani::cover!(
        result == Err(Error::WrongChunk) && !last,
        "a chunk where the last is due is refused"
    );
    kani::cover!(
        result == Err(Error::StaleHandle) && names_loaded(&before, &set),
        "a set changed since the block began to be read is refused"
    );
    kani::cover!(
        result == Err(Error::RecordRejected),
        "the cipher refuses the chunk"
    );
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "the derivation fails"
    );
}

/// The associated data of a chunk of a block carried under a key for transfers, after `chain`,
/// for the export's `context` of up to two bytes, written out from the layout: the label, the
/// version, the length of the context, the chain, and the context.
fn carry_bound(chain: &[u8; TAG_LEN], context: &[u8]) -> Bound {
    Bound::chained(b"lethewis data carry", chain, context)
}

/// A block being carried out in any state: any block being read, for `context`, any handle of
/// these slots as the key for transfers, any chain and salt, and the associated data of the
/// export's `export` after that chain. Only a beginning makes one; this covers every state one
/// can be in afterwards, its sets taken to be for data and for transfers.
fn any_exporting(id: usize, context: &[u8], export: &[u8]) -> Exporting<'static> {
    let chain: [u8; TAG_LEN] = kani::any();
    Exporting {
        source: any_opening(id, context),
        transfer: forged(id),
        chain,
        salt: kani::any(),
        associated: AssociatedData::of_data(export)
            .unwrap()
            .chained(CARRY_LABEL, &chain),
    }
}

/// Chunks in their place, the last if `last` says so, from any state of two slots and of the
/// epoch, any block being carried out and any chunk, whatever the ciphers do.
fn carry_out(last: bool) {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (context_bytes, export_bytes): ([u8; 2], [u8; 2]) = (kani::any(), kani::any());
    let context = any_block_context(&context_bytes);
    let export = any_block_context(&export_bytes);
    let mut exporting = any_exporting(id, context, export);
    let (set, transfer) = (exporting.source.set, exporting.transfer);
    let (source, carrier) = (
        snapshot_at(&before, set.index),
        snapshot_at(&before, transfer.index),
    );
    kani::assume(!names_loaded(&before, &set) || source.purpose == Purpose::Data);
    kani::assume(!names_loaded(&before, &transfer) || carrier.purpose == Purpose::Transfer);
    let (at, revision, salt, next, chunks, last_len) = (
        exporting.source.at,
        exporting.source.revision,
        exporting.source.salt,
        exporting.source.next,
        exporting.source.chunks,
        exporting.source.last,
    );
    let (chain, carried_salt) = (exporting.chain, exporting.salt);
    let length: usize = if last { kani::any() } else { 16 };
    kani::assume(length <= 17);
    let out_of_place = if last {
        next.checked_add(1) != Some(chunks) || u64::try_from(length).ok() != Some(last_len)
    } else {
        next.checked_add(1).is_none_or(|after| after >= chunks)
    };
    let stale = !names_loaded(&before, &set)
        || !names_loaded(&before, &transfer)
        || source.stages.revision() != revision
        || u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(chain);
    kani::assume(!out_of_place && !stale && carrier.direction != Direction::In);
    let original: [u8; 17] = kani::any();
    let mut buffer = original;
    let tag: [u8; TAG_LEN] = kani::any();
    let original_out: [u8; TAG_LEN] = kani::any();
    let mut out = original_out;
    let (mut opener, mut sealer) = (AnyChunk::new(), AnyChunk::new());
    let (open_with, seal_with) = (opener.opening(), sealer.sealing());

    let chunk = &mut buffer[..length];
    let result = if last {
        slots.export_last_in(
            &mut exporting,
            chunk,
            (&tag, &mut out),
            open_with,
            seal_with,
        )
    } else {
        slots.export_next_in(
            &mut exporting,
            chunk,
            (&tag, &mut out),
            open_with,
            seal_with,
        )
    };
    let after = snapshots(&slots);
    let moved = Snapshot {
        chain: sealer.tag,
        direction: Direction::Out,
        ..carrier
    };
    kani::assert(
        epoch_snapshot(&slots) == epoch_before
            && if result.is_ok() && last {
                unchanged_but(&after, &before, transfer.index)
                    && snapshot_at(&after, transfer.index) == moved
            } else {
                unchanged_but(&after, &before, 2)
            },
        "carrying a chunk out changes no slot and no epoch, but the last one moves the chain of \
         the key for transfers to its tag and marks the key as writing an export",
    );
    if any_failed() {
        kani::assert(
            result == Err(Error::DerivationFailed) && opener.calls == 0,
            "a failed derivation is refused before the ciphers run",
        );
    } else if opener.failed {
        kani::assert(
            result == Err(Error::RecordRejected) && sealer.calls == 0,
            "a chunk that does not open is refused before it is sealed",
        );
    } else {
        kani::assert(
            if sealer.failed {
                result == Err(Error::CipherFailed)
            } else {
                result.is_ok()
            },
            "a chunk that opens fails exactly when the seal does",
        );
    }
    kani::assert(
        opener.calls == 0
            || (opener.calls == 1
                && opener.key == expected_data_chunk(&key_head_at(&source, at.index()), &salt)
                && opener.nonce == nonce_of(next, last)
                && opener.aad == data_bound(context)
                && opener.given == chunk_head(&original[..length])
                && opener.tag == tag),
        "the chunk is opened once, under the key of its position and salt, with its nonce, the \
         associated data of the block and the tag given",
    );
    kani::assert(
        sealer.calls == 0
            || (sealer.calls == 1
                && opener.calls == 1
                && !opener.failed
                && sealer.key == expected_carry_chunk(&key_head_at(&carrier, 0), &carried_salt)
                && sealer.nonce == nonce_of(next, last)
                && sealer.aad == carry_bound(&chain, export)
                && sealer.given == opener.written),
        "what opened is sealed once, under the key of the key for transfers and the carried \
         salt, with the same nonce and the associated data of the export after the chain",
    );
    kani::assert(
        exporting.source.set == set
            && exporting.source.at == at
            && exporting.source.revision == revision
            && exporting.source.salt == salt
            && exporting.source.chunks == chunks
            && exporting.source.last == last_len
            && Bound::of(exporting.source.associated.bytes()) == data_bound(context)
            && exporting.transfer == transfer
            && exporting.chain == chain
            && exporting.salt == carried_salt
            && Bound::of(exporting.associated.bytes()) == carry_bound(&chain, export),
        "a chunk changes nothing of its block but the next number",
    );
    if result.is_ok() {
        kani::assert(
            out == sealer.tag
                && chunk_head(&buffer[..length]) == sealer.written
                && exporting.source.next == next.wrapping_add(1),
            "a carried chunk holds what the seal wrote, its new tag is written, and the block \
             moves on",
        );
    } else {
        kani::assert(
            out == original_out
                && exporting.source.next == next
                && (opener.calls != 0 || buffer == original),
            "a refused or failed chunk writes no tag, keeps the block where it was, and is left \
             as it was unless a cipher ran",
        );
    }
    kani::cover!(result.is_ok(), "a chunk is carried out");
    kani::cover!(
        result == Err(Error::RecordRejected),
        "a chunk that does not open is refused"
    );
    kani::cover!(result == Err(Error::CipherFailed), "the seal fails");
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "a failed derivation is refused"
    );
}

/// From any state of two slots and of the epoch, any block being carried out and any chunk of up
/// to 17 bytes, the last or one of a full 16, out of its place in the block, with a set not held,
/// a set for data that has changed or a key for transfers whose chain has moved since the block
/// began, or a key that receives an export: carrying it out is refused, in that order, before any
/// derivation and before the ciphers run, and changes no slot, no epoch, no tag, no chunk and no
/// block.
#[kani::proof]
#[kani::unwind(65)]
fn a_chunk_carried_out_of_its_place_or_stream_is_refused() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (context_bytes, export_bytes): ([u8; 2], [u8; 2]) = (kani::any(), kani::any());
    let context = any_block_context(&context_bytes);
    let export = any_block_context(&export_bytes);
    let mut exporting = any_exporting(id, context, export);
    let (set, transfer) = (exporting.source.set, exporting.transfer);
    let (source, carrier) = (
        snapshot_at(&before, set.index),
        snapshot_at(&before, transfer.index),
    );
    kani::assume(!names_loaded(&before, &set) || source.purpose == Purpose::Data);
    kani::assume(!names_loaded(&before, &transfer) || carrier.purpose == Purpose::Transfer);
    let (next, chunks, last_len) = (
        exporting.source.next,
        exporting.source.chunks,
        exporting.source.last,
    );
    let last: bool = kani::any();
    let length: usize = if last { kani::any() } else { 16 };
    kani::assume(length <= 17);
    let out_of_place = if last {
        next.checked_add(1) != Some(chunks) || u64::try_from(length).ok() != Some(last_len)
    } else {
        next.checked_add(1).is_none_or(|after| after >= chunks)
    };
    let stale = !names_loaded(&before, &set)
        || !names_loaded(&before, &transfer)
        || source.stages.revision() != exporting.source.revision
        || u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(exporting.chain);
    let turned = carrier.direction == Direction::In;
    kani::assume(out_of_place || stale || turned);
    let original: [u8; 17] = kani::any();
    let mut buffer = original;
    let tag: [u8; TAG_LEN] = kani::any();
    let original_out: [u8; TAG_LEN] = kani::any();
    let mut out = original_out;
    let (open_with, seal_with) = (seal::model::refuse_chunk, seal::model::fail_chunk);

    let chunk = &mut buffer[..length];
    let result = if last {
        slots.export_last_in(
            &mut exporting,
            chunk,
            (&tag, &mut out),
            open_with,
            seal_with,
        )
    } else {
        slots.export_next_in(
            &mut exporting,
            chunk,
            (&tag, &mut out),
            open_with,
            seal_with,
        )
    };
    kani::assert(
        result
            == Err(if out_of_place {
                Error::WrongChunk
            } else if stale {
                Error::StaleHandle
            } else {
                Error::Unfinished
            })
            && !seal::model::asked()
            && runs() == 0,
        "a chunk out of its place, then a set not held or changed and a chain that has moved, then \
         a key that receives an export, are refused before any derivation and before the ciphers \
         run",
    );
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == epoch_before
            && out == original_out
            && buffer == original
            && exporting.source.next == next,
        "a refused chunk changes no slot, no epoch, no tag, no chunk and no block",
    );
    kani::cover!(
        result == Err(Error::StaleHandle)
            && names_loaded(&before, &transfer)
            && u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(exporting.chain),
        "a chunk after another element of the export is refused"
    );
    kani::cover!(
        result == Err(Error::WrongChunk) && last,
        "a last chunk out of its place is refused"
    );
}

/// From the same states, a chunk in its place and not the last, under live sets: carrying it out
/// changes no slot and no epoch. A failed derivation is refused before the ciphers run. The chunk
/// opens once, under the key of its position and salt, with its nonce, the associated data of the
/// block and the tag given, and is refused where it does not; what opened is sealed once, under
/// the key derived from the key for transfers and the carried salt, with the same nonce and the
/// associated data of the export after the chain. A success writes the new tag and moves the
/// block on; a failure writes no tag and keeps the block where it was.
#[kani::proof]
#[kani::unwind(65)]
fn a_chunk_is_carried_out_under_the_key_for_transfers() {
    carry_out(false);
}

/// From the same states, the last chunk, in its place, under live sets: as any other chunk, and a
/// success moves the chain of the key for transfers to the new tag and marks the key as writing
/// an export, which nothing else changes.
#[kani::proof]
#[kani::unwind(65)]
fn the_last_chunk_carried_out_moves_the_chain_of_the_export() {
    carry_out(true);
}

/// A carried block being received in any state: any handle of these slots as the key for
/// transfers, any chain, salt, count of chunks and length of the last, the associated data of the
/// export's `export` after that chain; any handle as the set it is written under, any position,
/// salt and next chunk, and the associated data of `context`. Only a beginning makes one; this
/// covers every state one can be in afterwards, its sets taken to be for transfers and for data.
fn any_receiving(id: usize, export: &[u8], context: &[u8]) -> Receiving<'static> {
    let chain: [u8; TAG_LEN] = kani::any();
    Receiving {
        receipt: Receipt {
            transfer: forged(id),
            chain,
            salt: kani::any(),
            associated: AssociatedData::of_data(export)
                .unwrap()
                .chained(CARRY_LABEL, &chain),
            chunks: kani::any(),
            last: kani::any(),
        },
        set: forged(id),
        at: any_position(),
        salt: kani::any(),
        associated: AssociatedData::of_data(context).unwrap(),
        next: kani::any(),
    }
}

/// Chunks received in their place, the last if `last` says so, from any state of two slots and of
/// the epoch, any carried block being received and any chunk, whatever the ciphers do.
fn receive_in(last: bool) {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (export_bytes, context_bytes): ([u8; 2], [u8; 2]) = (kani::any(), kani::any());
    let export = any_block_context(&export_bytes);
    let context = any_block_context(&context_bytes);
    let mut receiving = any_receiving(id, export, context);
    let (transfer, set) = (receiving.receipt.transfer, receiving.set);
    let (carrier, target) = (
        snapshot_at(&before, transfer.index),
        snapshot_at(&before, set.index),
    );
    kani::assume(!names_loaded(&before, &transfer) || carrier.purpose == Purpose::Transfer);
    kani::assume(!names_loaded(&before, &set) || target.purpose == Purpose::Data);
    let (chain, carried_salt, chunks, last_len) = (
        receiving.receipt.chain,
        receiving.receipt.salt,
        receiving.receipt.chunks,
        receiving.receipt.last,
    );
    let (at, salt, next) = (receiving.at, receiving.salt, receiving.next);
    let length: usize = if last { kani::any() } else { 16 };
    kani::assume(length <= 17);
    let out_of_place = if last {
        next.checked_add(1) != Some(chunks) || u64::try_from(length).ok() != Some(last_len)
    } else {
        next.checked_add(1).is_none_or(|after| after >= chunks)
    };
    let stale = !names_loaded(&before, &transfer)
        || !names_loaded(&before, &set)
        || u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(chain)
        || target.pending != Some((transfer.index, carrier.generation));
    kani::assume(!out_of_place && !stale && carrier.direction != Direction::Out);
    let original: [u8; 17] = kani::any();
    let mut buffer = original;
    let tag: [u8; TAG_LEN] = kani::any();
    let original_out: [u8; TAG_LEN] = kani::any();
    let mut out = original_out;
    let (mut opener, mut sealer) = (AnyChunk::new(), AnyChunk::new());
    let (open_with, seal_with) = (opener.opening(), sealer.sealing());

    let chunk = &mut buffer[..length];
    let result = if last {
        slots.receive_last_in(
            &mut receiving,
            chunk,
            (&tag, &mut out),
            open_with,
            seal_with,
        )
    } else {
        slots.receive_next_in(
            &mut receiving,
            chunk,
            (&tag, &mut out),
            open_with,
            seal_with,
        )
    };
    let after = snapshots(&slots);
    let moved = Snapshot {
        chain: tag,
        direction: Direction::In,
        ..carrier
    };
    kani::assert(
        epoch_snapshot(&slots) == epoch_before
            && if result.is_ok() && last {
                unchanged_but(&after, &before, transfer.index)
                    && snapshot_at(&after, transfer.index) == moved
            } else {
                unchanged_but(&after, &before, 2)
            },
        "receiving a chunk changes no slot and no epoch, but the last one moves the chain of the \
         key for transfers to the tag it came with and marks the key as receiving an export",
    );
    if any_failed() {
        kani::assert(
            result == Err(Error::DerivationFailed) && opener.calls == 0,
            "a failed derivation is refused before the ciphers run",
        );
    } else if opener.failed {
        kani::assert(
            result == Err(Error::RecordRejected) && sealer.calls == 0,
            "a chunk that does not open is refused before it is sealed",
        );
    } else {
        kani::assert(
            if sealer.failed {
                result == Err(Error::CipherFailed)
            } else {
                result.is_ok()
            },
            "a chunk that opens fails exactly when the seal does",
        );
    }
    kani::assert(
        opener.calls == 0
            || (opener.calls == 1
                && opener.key == expected_carry_chunk(&key_head_at(&carrier, 0), &carried_salt)
                && opener.nonce == nonce_of(next, last)
                && opener.aad == carry_bound(&chain, export)
                && opener.given == chunk_head(&original[..length])
                && opener.tag == tag),
        "the chunk is opened once, under the key of the key for transfers and the carried salt, \
         with its nonce, the associated data of the export after the chain and the tag given",
    );
    kani::assert(
        sealer.calls == 0
            || (sealer.calls == 1
                && opener.calls == 1
                && !opener.failed
                && sealer.key == expected_data_chunk(&key_head_at(&target, at.index()), &salt)
                && sealer.nonce == nonce_of(next, last)
                && sealer.aad == data_bound(context)
                && sealer.given == opener.written),
        "what opened is sealed once, under the key of its position in the set for data and the \
         block's salt, with the same nonce and the associated data of the block",
    );
    kani::assert(
        receiving.receipt.transfer == transfer
            && receiving.receipt.chain == chain
            && receiving.receipt.salt == carried_salt
            && receiving.receipt.chunks == chunks
            && receiving.receipt.last == last_len
            && Bound::of(receiving.receipt.associated.bytes()) == carry_bound(&chain, export)
            && receiving.set == set
            && receiving.at == at
            && receiving.salt == salt
            && Bound::of(receiving.associated.bytes()) == data_bound(context),
        "a chunk changes nothing of its block but the next number",
    );
    if result.is_ok() {
        kani::assert(
            out == sealer.tag
                && chunk_head(&buffer[..length]) == sealer.written
                && receiving.next == next.wrapping_add(1),
            "a received chunk holds what the seal wrote, its new tag is written, and the block \
             moves on",
        );
    } else {
        kani::assert(
            out == original_out
                && receiving.next == next
                && (opener.calls != 0 || buffer == original),
            "a refused or failed chunk writes no tag, keeps the block where it was, and is left \
             as it was unless a cipher ran",
        );
    }
    kani::cover!(result.is_ok(), "a chunk is received");
    kani::cover!(
        result == Err(Error::RecordRejected),
        "a chunk that does not open is refused"
    );
    kani::cover!(result == Err(Error::CipherFailed), "the seal fails");
    kani::cover!(
        result == Err(Error::DerivationFailed),
        "a failed derivation is refused"
    );
}

/// From any state of two slots and of the epoch, any carried block being received and any chunk
/// of up to 17 bytes, the last or one of a full 16, out of its place in the block, with a set not
/// held or no longer waiting for the end of this transfer, or a key for transfers whose chain has
/// moved since the block began, or that writes an export: receiving it is refused, in that order,
/// before any derivation and before the ciphers run, and changes no slot, no epoch, no tag, no
/// chunk and no block.
#[kani::proof]
#[kani::unwind(65)]
fn a_chunk_received_out_of_its_place_or_stream_is_refused() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (export_bytes, context_bytes): ([u8; 2], [u8; 2]) = (kani::any(), kani::any());
    let export = any_block_context(&export_bytes);
    let context = any_block_context(&context_bytes);
    let mut receiving = any_receiving(id, export, context);
    let (transfer, set) = (receiving.receipt.transfer, receiving.set);
    let carrier = snapshot_at(&before, transfer.index);
    kani::assume(!names_loaded(&before, &transfer) || carrier.purpose == Purpose::Transfer);
    kani::assume(
        !names_loaded(&before, &set) || snapshot_at(&before, set.index).purpose == Purpose::Data,
    );
    let (chunks, last_len, next) = (
        receiving.receipt.chunks,
        receiving.receipt.last,
        receiving.next,
    );
    let last: bool = kani::any();
    let length: usize = if last { kani::any() } else { 16 };
    kani::assume(length <= 17);
    let out_of_place = if last {
        next.checked_add(1) != Some(chunks) || u64::try_from(length).ok() != Some(last_len)
    } else {
        next.checked_add(1).is_none_or(|after| after >= chunks)
    };
    let stale = !names_loaded(&before, &transfer)
        || !names_loaded(&before, &set)
        || u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(receiving.receipt.chain)
        || snapshot_at(&before, set.index).pending != Some((transfer.index, carrier.generation));
    let turned = carrier.direction == Direction::Out;
    kani::assume(out_of_place || stale || turned);
    let original: [u8; 17] = kani::any();
    let mut buffer = original;
    let tag: [u8; TAG_LEN] = kani::any();
    let original_out: [u8; TAG_LEN] = kani::any();
    let mut out = original_out;
    let (open_with, seal_with) = (seal::model::refuse_chunk, seal::model::fail_chunk);

    let chunk = &mut buffer[..length];
    let result = if last {
        slots.receive_last_in(
            &mut receiving,
            chunk,
            (&tag, &mut out),
            open_with,
            seal_with,
        )
    } else {
        slots.receive_next_in(
            &mut receiving,
            chunk,
            (&tag, &mut out),
            open_with,
            seal_with,
        )
    };
    kani::assert(
        result
            == Err(if out_of_place {
                Error::WrongChunk
            } else if stale {
                Error::StaleHandle
            } else {
                Error::Unfinished
            })
            && !seal::model::asked()
            && runs() == 0,
        "a chunk out of its place, then a set not held or no longer waiting for this transfer and \
         a chain that has moved, then a key that writes an export, are refused before any \
         derivation and before the ciphers run",
    );
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == epoch_before
            && out == original_out
            && buffer == original
            && receiving.next == next,
        "a refused chunk changes no slot, no epoch, no tag, no chunk and no block",
    );
    kani::cover!(
        result == Err(Error::StaleHandle)
            && names_loaded(&before, &transfer)
            && u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(receiving.receipt.chain),
        "a chunk after another element of the export is refused"
    );
    kani::cover!(
        result == Err(Error::WrongChunk) && last,
        "a last chunk out of its place is refused"
    );
}

/// From the same states, a chunk in its place and not the last, under live sets: receiving it
/// changes no slot and no epoch. A failed derivation is refused before the ciphers run. The chunk
/// opens once, under the key derived from the key for transfers and the carried salt, with its
/// nonce, the associated data of the export after the chain and the tag given, and is refused
/// where it does not; what opened is sealed once, under the key of its position in the set for
/// data and the block's salt, with the same nonce and the associated data of the block. A success
/// writes the new tag and moves the block on; a failure writes no tag and keeps the block where it
/// was.
#[kani::proof]
#[kani::unwind(65)]
fn a_chunk_is_received_under_the_set_it_is_written_to() {
    receive_in(false);
}

/// From the same states, the last chunk, in its place, under live sets: as any other chunk, and a
/// success moves the chain of the key for transfers to the tag the chunk came with and marks the
/// key as receiving an export, which nothing else changes.
#[kani::proof]
#[kani::unwind(65)]
fn the_last_chunk_received_moves_the_chain_of_the_export() {
    receive_in(true);
}

/// From any state of two slots and of the epoch, any block being read, a handle of these slots
/// naming any slot and generation as the key for transfers, any context of up to two bytes and
/// any header, whatever the platform's source does: beginning to carry a block out changes no
/// slot, and the epoch only by the count of the draws the source answers. It refuses an empty
/// context, a set for data not held or changed since the block began to be read, a key for
/// transfers not held or of another purpose, one that receives an export, and a block a chunk
/// has been read from, in that order, before it draws; then a failed source and a failed
/// derivation. A block begun writes into its header the salt, the hedge of the one draw under the
/// key of this epoch, and the check derived from the key for transfers and that salt; it holds the
/// block being read, the key for transfers, its chain, the salt and the associated data of the
/// export after that chain. A refused one writes nothing.
#[kani::proof]
#[kani::unwind(65)]
fn a_block_is_carried_out_after_the_chain_of_its_export() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let (number, key, next, _, _) = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (block_bytes, export_bytes): ([u8; 2], [u8; 2]) = (kani::any(), kani::any());
    let block_context = any_block_context(&block_bytes);
    let export = any_context(&export_bytes);
    let opening = any_opening(id, block_context);
    let source = snapshot_at(&before, opening.set.index);
    kani::assume(!names_loaded(&before, &opening.set) || source.purpose == Purpose::Data);
    let (set, at, revision, block_salt, read, chunks, last) = (
        opening.set,
        opening.at,
        opening.revision,
        opening.salt,
        opening.next,
        opening.chunks,
        opening.last,
    );
    let transfer = forged(id);
    let carrier = snapshot_at(&before, transfer.index);
    let original: [u8; BLOCK_HEADER_LEN] = kani::any();
    let mut header = original;
    let mut entropy = FirstKept::new();

    let result = slots.begin_export_block_in(opening, transfer, export, &mut entropy, &mut header);
    let draws = count.wrapping_add(u64::from(entropy.source.answered));
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == (number, key, next, changing, draws),
        "beginning to carry a block out changes no slot and no epoch, and counts once each draw \
         the source answers",
    );
    let asked = entropy.source.calls;
    let error = result.as_ref().err().copied();
    kani::assert(
        if export.is_empty() {
            error == Some(Error::InvalidContext) && asked == 0
        } else if !names_loaded(&before, &set)
            || source.stages.revision() != revision
            || !names_loaded(&before, &transfer)
        {
            error == Some(Error::StaleHandle) && asked == 0
        } else if carrier.purpose != Purpose::Transfer {
            error == Some(Error::WrongPurpose) && asked == 0
        } else if carrier.direction == Direction::In {
            error == Some(Error::Unfinished) && asked == 0
        } else if read != 0 {
            error == Some(Error::WrongChunk) && asked == 0
        } else if entropy.source.failed {
            error == Some(Error::EntropyFailed) && asked == 1
        } else if any_failed() {
            error == Some(Error::DerivationFailed) && asked == 1
        } else {
            result.is_ok() && asked == 1
        },
        "carrying a block out refuses a bad context, a stale set or key, a key not for transfers \
         or receiving and a block read from before it draws, then a failed source and a failed \
         derivation, and draws at most once",
    );
    if let Ok(exporting) = &result {
        let mut drawn = [0; SALT_LEN];
        drawn.copy_from_slice(&entropy.first[..SALT_LEN]);
        let salt = expected_hedge(&epoch_key, count, Branch::HedgeSalt, &drawn);
        kani::assert(
            header[..SALT_LEN] == salt
                && header[SALT_LEN..] == expected_carry_check(&key_head_at(&carrier, 0), &salt),
            "the header holds the salt hedged from the one draw and the check of the key for \
             transfers and the salt",
        );
        let source = &exporting.source;
        kani::assert(
            source.set == set
                && source.at == at
                && source.revision == revision
                && source.salt == block_salt
                && source.next == 0
                && source.chunks == chunks
                && source.last == last
                && Bound::of(source.associated.bytes()) == data_bound(block_context),
            "the block is read on from its first chunk, as it was begun to be read",
        );
        kani::assert(
            exporting.transfer == transfer
                && u128::from_ne_bytes(exporting.chain) == u128::from_ne_bytes(carrier.chain)
                && exporting.salt == salt
                && Bound::of(exporting.associated.bytes()) == carry_bound(&carrier.chain, export),
            "the carried block holds the key for transfers, its chain, the salt and the \
             associated data of the export after that chain",
        );
    } else {
        kani::assert(header == original, "a refused beginning writes nothing");
    }
    kani::cover!(result.is_ok(), "a block begins to be carried out");
    kani::cover!(
        result.is_ok() && carrier.direction == Direction::Out,
        "a block is carried after another element of the export"
    );
    kani::cover!(
        error == Some(Error::Unfinished),
        "a key that receives an export carries no block out"
    );
    kani::cover!(
        error == Some(Error::WrongChunk),
        "a block a chunk was read from is not carried"
    );
    kani::cover!(
        error == Some(Error::StaleHandle)
            && names_loaded(&before, &set)
            && source.stages.revision() != revision,
        "a set changed since the block began to be read is refused"
    );
    kani::cover!(error == Some(Error::EntropyFailed), "the source fails");
    kani::cover!(error == Some(Error::DerivationFailed), "a derivation fails");
}

/// From any state of two slots and of the epoch, for a handle of these slots naming any slot and
/// generation, any context of up to two bytes, any header and any length of a block: beginning to
/// receive a carried block changes no slot and no epoch. It refuses an empty context, a stale
/// handle, a key not for transfers, one that writes an export and a length no block has, in that
/// order, before it derives; it then derives the check of the key for transfers once, with the
/// salt of the header, refuses a failed derivation, and refuses as `RecordRejected` a header that
/// does not hold that check. A receipt holds the key, its chain, the salt, the associated data of
/// the export after that chain, and as many chunks as the length gives.
#[kani::proof]
#[kani::unwind(65)]
fn a_carried_block_is_received_only_under_the_key_its_header_names() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let mut epoch = any_epoch(kani::any());
    let slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let epoch_before = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let transfer = forged(id);
    let context_bytes: [u8; 2] = kani::any();
    let export = any_context(&context_bytes);
    let header: [u8; BLOCK_HEADER_LEN] = kani::any();
    let block: u64 = kani::any();
    let runs_before = runs();

    let result = slots.begin_receive_block_in::<16>(transfer, export, &header, block);
    let derived = runs().wrapping_sub(runs_before);
    kani::assert(
        unchanged_except(&slots, &before, 2) && epoch_snapshot(&slots) == epoch_before,
        "beginning to receive a block changes no slot and no epoch",
    );
    let carrier = snapshot_at(&before, transfer.index);
    let len = data_len_in::<16>(block);
    let mut salt = [0; SALT_LEN];
    salt.copy_from_slice(&header[..SALT_LEN]);
    let error = result.as_ref().err().copied();
    kani::assert(
        if export.is_empty() {
            error == Some(Error::InvalidContext) && derived == 0
        } else if !names_loaded(&before, &transfer) {
            error == Some(Error::StaleHandle) && derived == 0
        } else if carrier.purpose != Purpose::Transfer {
            error == Some(Error::WrongPurpose) && derived == 0
        } else if carrier.direction == Direction::Out {
            error == Some(Error::Unfinished) && derived == 0
        } else if len.is_none() {
            error == Some(Error::RecordRejected) && derived == 0
        } else if any_failed() {
            error == Some(Error::DerivationFailed) && derived == 1
        } else if header[SALT_LEN..] != expected_carry_check(&key_head_at(&carrier, 0), &salt) {
            error == Some(Error::RecordRejected) && derived == 1
        } else {
            result.is_ok() && derived == 1
        },
        "a receipt refuses a bad context, a stale key, one not for transfers or writing and a \
         length no block has before it derives, then derives the check once and refuses a failed \
         derivation and a header without that check",
    );
    if let Ok(receipt) = &result {
        let (chunks, last) = chunks_in::<16>(len.unwrap_or(0));
        kani::assert(
            receipt.transfer == transfer
                && u128::from_ne_bytes(receipt.chain) == u128::from_ne_bytes(carrier.chain)
                && receipt.salt == salt
                && Bound::of(receipt.associated.bytes()) == carry_bound(&carrier.chain, export)
                && receipt.chunks == chunks
                && receipt.last == last,
            "a receipt holds the key, its chain, the salt, the associated data of the export \
             after that chain, and the chunks the length gives",
        );
    }
    kani::cover!(result.is_ok(), "a carried block begins to be received");
    kani::cover!(
        error == Some(Error::RecordRejected) && len.is_some(),
        "a header of another key is refused"
    );
    kani::cover!(
        error == Some(Error::Unfinished),
        "a key that writes an export receives no block"
    );
    kani::cover!(
        error == Some(Error::DerivationFailed),
        "the derivation fails"
    );
}

/// From any state of two slots and of the epoch, any receipt, a handle of these slots naming any
/// slot and generation as the set, any context of up to two bytes and any header, whatever the
/// platform's source does: giving a receipt a set that came in its transfer changes no slot, and
/// the epoch only by the count of the draws the source answers. It refuses an empty context, a key
/// for transfers not held or whose chain has moved since the receipt began, a set not held or not
/// for data and one that did not come in this transfer, in that order, before it draws; then a
/// failed source and a failed derivation. A block begun writes into its header the salt, the hedge
/// of the one draw under the key of this epoch, and the check derived from the primary key of the
/// set and that salt; it receives into that set from the first chunk. A refused one writes
/// nothing.
#[kani::proof]
#[kani::unwind(65)]
fn a_received_block_is_written_under_a_set_of_its_transfer() {
    let mut memory = [any_slot(), any_slot()];
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let (number, key, next, _, _) = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (export_bytes, context_bytes): ([u8; 2], [u8; 2]) = (kani::any(), kani::any());
    let export = any_block_context(&export_bytes);
    let context = any_context(&context_bytes);
    let receipt = any_receiving(id, export, context.get(..1).unwrap_or(b"x")).receipt;
    let transfer = receipt.transfer;
    let carrier = snapshot_at(&before, transfer.index);
    kani::assume(!names_loaded(&before, &transfer) || carrier.purpose == Purpose::Transfer);
    let (chain, carried_salt, chunks, last) =
        (receipt.chain, receipt.salt, receipt.chunks, receipt.last);
    let set = forged(id);
    let named = snapshot_at(&before, set.index);
    let original: [u8; BLOCK_HEADER_LEN] = kani::any();
    let mut header = original;
    let mut entropy = FirstKept::new();

    let result = slots.receive_into_in(receipt, Some(set), context, &mut entropy, &mut header);
    let draws = count.wrapping_add(u64::from(entropy.source.answered));
    kani::assert(
        unchanged_except(&slots, &before, 2)
            && epoch_snapshot(&slots) == (number, key, next, changing, draws),
        "giving a receipt a set of its transfer changes no slot and no epoch, and counts once \
         each draw the source answers",
    );
    let asked = entropy.source.calls;
    let error = result.as_ref().err().copied();
    kani::assert(
        if context.is_empty() {
            error == Some(Error::InvalidContext) && asked == 0
        } else if !names_loaded(&before, &transfer)
            || u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(chain)
            || !names_loaded(&before, &set)
        {
            error == Some(Error::StaleHandle) && asked == 0
        } else if named.purpose != Purpose::Data {
            error == Some(Error::WrongPurpose) && asked == 0
        } else if named.pending != Some((transfer.index, carrier.generation)) {
            error == Some(Error::NotReceived) && asked == 0
        } else if entropy.source.failed {
            error == Some(Error::EntropyFailed) && asked == 1
        } else if any_failed() {
            error == Some(Error::DerivationFailed) && asked == 1
        } else {
            result.is_ok() && asked == 1
        },
        "a receipt refuses a bad context, a stale key or set, a set not for data and one of \
         another transfer before it draws, then a failed source and a failed derivation, and \
         draws at most once",
    );
    if let Ok((receiving, handle)) = &result {
        let mut drawn = [0; SALT_LEN];
        drawn.copy_from_slice(&entropy.first[..SALT_LEN]);
        let salt = expected_hedge(&epoch_key, count, Branch::HedgeSalt, &drawn);
        let primary = named.stages.primary();
        kani::assert(
            header[..SALT_LEN] == salt
                && header[SALT_LEN..] == expected_data_check(&key_head_at(&named, primary), &salt),
            "the header holds the salt hedged from the one draw and the check of the primary \
             key and the salt",
        );
        kani::assert(
            *handle == set
                && receiving.set == set
                && receiving.at.index() == primary
                && receiving.salt == salt
                && Bound::of(receiving.associated.bytes()) == data_bound(context)
                && receiving.next == 0
                && receiving.receipt.transfer == transfer
                && u128::from_ne_bytes(receiving.receipt.chain) == u128::from_ne_bytes(chain)
                && receiving.receipt.salt == carried_salt
                && receiving.receipt.chunks == chunks
                && receiving.receipt.last == last,
            "the block is received into the set, under its primary, from the first chunk, as the \
             receipt began",
        );
    } else {
        kani::assert(header == original, "a refused beginning writes nothing");
    }
    kani::cover!(
        result.is_ok(),
        "a block is received into a set of its transfer"
    );
    kani::cover!(
        error == Some(Error::NotReceived),
        "a set of another transfer takes no block"
    );
    kani::cover!(
        error == Some(Error::StaleHandle)
            && names_loaded(&before, &transfer)
            && u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(chain),
        "a receipt after another element of the export is refused"
    );
    kani::cover!(error == Some(Error::EntropyFailed), "the source fails");
    kani::cover!(error == Some(Error::DerivationFailed), "a derivation fails");
}

/// A new set given to a receipt, with the free slot at `free_at`, or none: from any state of two
/// slots otherwise and of the epoch, any receipt, any context of up to two bytes and any header,
/// whatever the platform's source does.
fn into_new(free_at: Option<usize>) {
    // Past the first slot it holds the key for transfers, a set of one: where the new set goes
    // past other sets, and the want of a free slot, are the load's, which the proofs of loads
    // cover.
    let mut memory = match free_at {
        Some(0) => [any_slot_in(Occupancy::Free), any_slot()],
        Some(_) => [any_slot_in(Occupancy::Loaded), any_slot_in(Occupancy::Free)],
        None => [
            any_slot_in(Occupancy::Loaded),
            any_slot_in(Occupancy::Retired),
        ],
    };
    if free_at != Some(0) {
        kani::assume(memory[0].purpose == Purpose::Transfer);
    }
    let id = memory.as_ptr().addr();
    let changing = kani::any();
    let mut epoch = any_epoch(changing);
    let mut slots = Slots {
        memory: &mut memory,
        epoch: &mut epoch,
    };
    let (epoch_key, count) = (first_half(&slots.epoch.key), slots.epoch.drawn);
    let (number, key, next, _, _) = epoch_snapshot(&slots);
    let before = snapshots(&slots);
    let (export_bytes, context_bytes): ([u8; 2], [u8; 2]) = (kani::any(), kani::any());
    let export = any_block_context(&export_bytes);
    let context = any_context(&context_bytes);
    let receipt = any_receiving(id, export, b"x").receipt;
    let transfer = receipt.transfer;
    let carrier = snapshot_at(&before, transfer.index);
    kani::assume(!names_loaded(&before, &transfer) || carrier.purpose == Purpose::Transfer);
    let (chain, carried_salt, chunks, last) =
        (receipt.chain, receipt.salt, receipt.chunks, receipt.last);
    let original: [u8; BLOCK_HEADER_LEN] = kani::any();
    let mut header = original;
    let mut entropy = FirstKept::new();

    let result = slots.receive_into_in(receipt, None, context, &mut entropy, &mut header);
    let after = snapshots(&slots);
    let draws = count.wrapping_add(u64::from(entropy.source.answered));
    kani::assert(
        epoch_snapshot(&slots) == (number, key, next, changing, draws),
        "a new set changes no epoch but the count of the draws the source answers",
    );
    let free = first_free(&before);
    kani::assert(free == free_at, "the free slot is where it was made");
    let changed = free.unwrap_or(2);
    kani::assert(
        unchanged_but(&after, &before, changed),
        "a new set changes no slot but the first free one",
    );
    let refused = context.is_empty()
        || !names_loaded(&before, &transfer)
        || u128::from_ne_bytes(carrier.chain) != u128::from_ne_bytes(chain);
    let error = result.as_ref().err().copied();
    if refused {
        kani::assert(
            error
                == Some(if context.is_empty() {
                    Error::InvalidContext
                } else {
                    Error::StaleHandle
                })
                && entropy.source.calls == 0
                && after == before,
            "a bad context, then a stale key or a chain that has moved, are refused before any \
             draw",
        );
    } else if let Ok((receiving, handle)) = &result {
        let new = snapshot_at(&after, changed);
        let mut drawn = [0; SALT_LEN];
        drawn.copy_from_slice(&entropy.first[..SALT_LEN]);
        let salt = expected_hedge(&epoch_key, count, Branch::HedgeSalt, &drawn);
        kani::assert(
            free.is_some()
                && new.occupancy == Occupancy::Loaded
                && new.purpose == Purpose::Data
                && new.stages.stage(0) == Some(Status::Enabled)
                && new.stages.stage(1).is_none()
                && new.stages.stage(2).is_none()
                && new.stages.primary() == 0
                && new.lengths[0] == KeyLength::Bytes32
                && !new.unlocks
                && new.pending == Some((transfer.index, carrier.generation))
                && handle.index == changed
                && handle.generation == snapshot_at(&before, changed).generation
                && entropy.source.calls == 2,
            "a new set of one enabled key of 32 bytes for data takes the first free slot, marked \
             as having come in the transfer of the receipt, after two draws",
        );
        let mut key_drawn = [0; 32];
        key_drawn.copy_from_slice(&entropy.source.written[..32]);
        kani::assert(
            key_head(&new)
                == expected_hedge(
                    &epoch_key,
                    count.wrapping_add(1),
                    Branch::HedgeKey,
                    &key_drawn,
                ),
            "the new key is the hedge of the second draw under the key of this epoch",
        );
        kani::assert(
            header[..SALT_LEN] == salt
                && header[SALT_LEN..] == expected_data_check(&key_head(&new), &salt),
            "the header holds the salt hedged from the first draw and the check of the new key \
             and the salt",
        );
        kani::assert(
            receiving.set == *handle
                && receiving.at == Position::First
                && receiving.salt == salt
                && Bound::of(receiving.associated.bytes()) == data_bound(context)
                && receiving.next == 0
                && receiving.receipt.transfer == transfer
                && u128::from_ne_bytes(receiving.receipt.chain) == u128::from_ne_bytes(chain)
                && receiving.receipt.salt == carried_salt
                && receiving.receipt.chunks == chunks
                && receiving.receipt.last == last,
            "the block is received into the new set, under its key, from the first chunk, as the \
             receipt began",
        );
    } else {
        let left = snapshot_at(&after, changed);
        kani::assert(
            header == original
                && (left == snapshot_at(&before, changed)
                    || (wiped(&slots.memory[changed.min(1)])
                        && (left.occupancy == Occupancy::Retired
                            || (left.occupancy == Occupancy::Free
                                && left.generation
                                    == snapshot_at(&before, changed).generation.wrapping_add(1))))),
            "a failed receipt writes nothing, and leaves the free slot as it was or releases the set \
             it made there",
        );
        kani::assert(
            if entropy.source.failed {
                error == Some(Error::EntropyFailed)
            } else if free.is_none() && !any_failed() {
                error == Some(Error::NoFreeSlot)
            } else {
                error == Some(Error::DerivationFailed) && any_failed()
                    || error == Some(Error::DuplicateKey)
            },
            "a new set fails only as the source, a free slot, a derivation or a key held already \
             fails it",
        );
    }
    match free_at {
        Some(0) => {
            kani::cover!(result.is_ok(), "a block is received into a new set");
            kani::cover!(
                error == Some(Error::DerivationFailed)
                    && entropy.source.calls == 2
                    && after != before,
                "a failed check releases the new set"
            );
            kani::cover!(
                error == Some(Error::DuplicateKey),
                "a new key held already makes no set"
            );
            kani::cover!(error == Some(Error::StaleHandle), "a stale key is refused");
        }
        Some(_) => {
            kani::cover!(result.is_ok(), "a new set takes the second slot");
        }
        None => {
            kani::cover!(
                error == Some(Error::NoFreeSlot),
                "a new set needs a free slot"
            );
        }
    }
}

/// With the first of two slots free and the second in any state, from any epoch, receipt, context
/// of up to two bytes and header, whatever the platform's source does: giving a receipt a new set
/// changes no slot but the first free one, and the epoch only by the count of the draws the source answers. It refuses
/// an empty context and a key for transfers not held or whose chain has moved since the receipt
/// began before it draws. It then draws the salt; a failed source, a want of a free slot and a
/// failed load change no slot, and a failed check after the load releases the new set. On success
/// the first free slot holds a set for data of one enabled key of 32 bytes, generated as any is,
/// marked as having come in the receipt's transfer; the header holds the salt hedged from the
/// first draw and the check of the new key and that salt; and the block is received into the new
/// set, under its key, from the first chunk, as the receipt began. A refused one writes nothing.
#[kani::proof]
#[kani::unwind(65)]
fn a_received_block_takes_a_new_set_in_the_first_slot() {
    into_new(Some(0));
}

/// From the same states with a key for transfers in the first slot and the second free: the new set
/// takes the second slot, as above.
#[kani::proof]
#[kani::unwind(65)]
fn a_received_block_takes_a_new_set_in_the_second_slot() {
    into_new(Some(1));
}

/// From the same states with a key for transfers in the first slot and the second retired: a new set
/// is refused as `NoFreeSlot` after the draw of the salt, unless a refusal or a failure comes first,
/// and changes no slot.
#[kani::proof]
#[kani::unwind(65)]
fn a_received_block_needs_a_free_slot_for_a_new_set() {
    into_new(None);
}

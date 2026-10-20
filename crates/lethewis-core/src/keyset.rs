// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::key::{CAPACITY, Key, KeyBytes};
use crate::record::{
    ID_LEN, Malformed, PLAINTEXT_LEN, Purpose, Status, VERSION, length_from_byte, length_to_byte,
};

/// The most keys a set holds: the primary, one on its way out, and one added before it becomes the
/// primary.
pub(crate) const MEMBERS: usize = 3;
/// A position of a set: the stage, the length and the key, zero past its length; all zero when the
/// position is empty.
const MEMBER_LEN: usize = 2 + CAPACITY;

const _: () = assert!(3 + ID_LEN + 8 + 8 + MEMBERS * MEMBER_LEN == PLAINTEXT_LEN);

/// What a set's record holds besides its keys and their stages.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(any(test, kani), derive(PartialEq, Eq))]
pub(crate) struct Header {
    pub(crate) purpose: Purpose,
    /// The identifier of the key the set is wrapped with.
    pub(crate) parent: [u8; ID_LEN],
    pub(crate) epoch: u64,
}

/// The stage of every position of a set, which position holds the primary key, and how many
/// transitions the set has gone through.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(any(test, kani), derive(PartialEq, Eq))]
pub(crate) struct Stages {
    /// `None` for an empty position.
    members: [Option<Status>; MEMBERS],
    primary: usize,
    revision: u64,
}

/// A position of a key set, each holding at most one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// The first position.
    First,
    /// The second position.
    Second,
    /// The third position.
    Third,
}

impl Position {
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::First => 0,
            Self::Second => 1,
            Self::Third => 2,
        }
    }

    pub(crate) const fn at(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::First),
            1 => Some(Self::Second),
            2 => Some(Self::Third),
            _ => None,
        }
    }
}

/// Why a transition was refused. Nothing has changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Every position holds a key.
    Full,
    /// The transition does not apply to the primary key.
    Primary,
    /// The position does not hold a key in the stage the transition starts from.
    Stage,
    /// The set has gone through as many transitions as its counter holds.
    Exhausted,
}

impl Stages {
    /// A set of one enabled key, which is the primary.
    pub(crate) const fn one() -> Self {
        Self {
            members: [Some(Status::Enabled), None, None],
            primary: 0,
            revision: 0,
        }
    }

    /// Whether this is a set of one enabled key, which is the primary, that has never changed.
    pub(crate) fn is_one(&self) -> bool {
        matches!(self.members, [Some(Status::Enabled), None, None])
            && self.primary == 0
            && self.revision == 0
    }

    /// Whether the primary position holds an enabled key.
    pub(crate) fn is_whole(&self) -> bool {
        self.members.get(self.primary) == Some(&Some(Status::Enabled))
    }

    /// The stage of the key at `at`, or `None` where the position is empty.
    pub(crate) fn stage(&self, at: usize) -> Option<Status> {
        self.members.get(at).copied().flatten()
    }

    /// The position of the primary key.
    #[cfg(any(test, kani))]
    pub(crate) const fn primary(&self) -> usize {
        self.primary
    }

    /// Stages as given, whole or not.
    #[cfg(test)]
    pub(crate) const fn from_parts(
        members: [Option<Status>; MEMBERS],
        primary: usize,
        revision: u64,
    ) -> Self {
        Self {
            members,
            primary,
            revision,
        }
    }
}

impl Stages {
    /// Adds an enabled key in the first empty position, which is returned. It is not the primary.
    pub(crate) fn add(&mut self) -> Result<usize, Refused> {
        let at = self
            .members
            .iter()
            .position(Option::is_none)
            .ok_or(Refused::Full)?;
        self.set(at, Some(Status::Enabled))?;
        Ok(at)
    }

    /// Makes the enabled key at `at` the primary. The former primary stays enabled.
    pub(crate) fn promote(&mut self, at: usize) -> Result<(), Refused> {
        self.require(at, Status::Enabled)?;
        self.revision = self.next()?;
        self.primary = at;
        Ok(())
    }

    /// Disables the enabled key at `at`, which is not the primary.
    pub(crate) fn disable(&mut self, at: usize) -> Result<(), Refused> {
        self.require(at, Status::Enabled)?;
        self.set(at, Some(Status::Disabled))
    }

    /// Enables the disabled key at `at` again.
    pub(crate) fn enable(&mut self, at: usize) -> Result<(), Refused> {
        self.require(at, Status::Disabled)?;
        self.set(at, Some(Status::Enabled))
    }

    /// Empties the position of the disabled key at `at`.
    pub(crate) fn destroy(&mut self, at: usize) -> Result<(), Refused> {
        self.require(at, Status::Disabled)?;
        self.set(at, None)
    }

    /// Refuses unless `at` is not the primary and holds a key in `stage`.
    fn require(&self, at: usize, stage: Status) -> Result<(), Refused> {
        if at == self.primary {
            return Err(Refused::Primary);
        }
        match self.members.get(at) {
            Some(&Some(found)) if found == stage => Ok(()),
            _ => Err(Refused::Stage),
        }
    }

    fn next(&self) -> Result<u64, Refused> {
        self.revision.checked_add(1).ok_or(Refused::Exhausted)
    }

    fn set(&mut self, at: usize, member: Option<Status>) -> Result<(), Refused> {
        let revision = self.next()?;
        let position = self.members.get_mut(at).ok_or(Refused::Stage)?;
        *position = member;
        self.revision = revision;
        Ok(())
    }
}

/// Writes the plaintext of a set. The key of a position the stages leave empty is not written;
/// every byte of `out` is.
pub(crate) fn build(
    header: &Header,
    stages: &Stages,
    keys: [&Key; MEMBERS],
    out: &mut [u8; PLAINTEXT_LEN],
) {
    let Some((control, rest)) = out.split_first_chunk_mut::<3>() else {
        return;
    };
    *control = [
        VERSION,
        header.purpose as u8,
        u8::try_from(stages.primary).unwrap_or(u8::MAX),
    ];
    let Some((parent, rest)) = rest.split_first_chunk_mut::<ID_LEN>() else {
        return;
    };
    *parent = header.parent;
    let Some((epoch, rest)) = rest.split_first_chunk_mut::<8>() else {
        return;
    };
    *epoch = header.epoch.to_le_bytes();
    let Some((revision, rest)) = rest.split_first_chunk_mut::<8>() else {
        return;
    };
    *revision = stages.revision.to_le_bytes();
    let Some((first, rest)) = rest.split_first_chunk_mut::<MEMBER_LEN>() else {
        return;
    };
    let Some((second, rest)) = rest.split_first_chunk_mut::<MEMBER_LEN>() else {
        return;
    };
    let Some((third, _)) = rest.split_first_chunk_mut::<MEMBER_LEN>() else {
        return;
    };
    let [first_stage, second_stage, third_stage] = stages.members;
    let [first_key, second_key, third_key] = keys;
    build_member(first_stage, first_key, first);
    build_member(second_stage, second_key, second);
    build_member(third_stage, third_key, third);
}

fn build_member(stage: Option<Status>, key: &Key, out: &mut [u8; MEMBER_LEN]) {
    let Some((control, bytes)) = out.split_first_chunk_mut::<2>() else {
        return;
    };
    let Ok(bytes) = <&mut [u8; CAPACITY]>::try_from(bytes) else {
        return;
    };
    if let Some(status) = stage {
        *control = [status as u8, length_to_byte(key.length())];
        key.write_into(bytes);
    } else {
        *control = [0; 2];
        bytes.fill(0);
    }
}

/// The identifier of the parent a set's plaintext names, read without parsing the rest.
pub(crate) fn parent_of(bytes: &[u8; PLAINTEXT_LEN]) -> &[u8; ID_LEN] {
    bytes
        .split_first_chunk::<3>()
        .and_then(|(_, rest)| rest.split_first_chunk::<ID_LEN>())
        .map_or(&[0; ID_LEN], |(parent, _)| parent)
}

/// What parsing a set's plaintext gives: its header, its stages, and the bytes of each key, `None`
/// where the position is empty.
pub(crate) type Parsed<'a> = (Header, Stages, [Option<KeyBytes<'a>>; MEMBERS]);

/// Reads the plaintext of a set. Anything [`build`] cannot write is refused, and so is a set whose
/// primary position does not hold an enabled key, or that holds a key of a length its purpose does
/// not take.
pub(crate) fn parse(bytes: &[u8; PLAINTEXT_LEN]) -> Result<Parsed<'_>, Malformed> {
    let Some((&[version, purpose, primary], rest)) = bytes.split_first_chunk::<3>() else {
        return Err(Malformed);
    };
    let Some((parent, rest)) = rest.split_first_chunk::<ID_LEN>() else {
        return Err(Malformed);
    };
    let Some((epoch, rest)) = rest.split_first_chunk::<8>() else {
        return Err(Malformed);
    };
    let Some((revision, rest)) = rest.split_first_chunk::<8>() else {
        return Err(Malformed);
    };
    let Some((first, rest)) = rest.split_first_chunk::<MEMBER_LEN>() else {
        return Err(Malformed);
    };
    let Some((second, rest)) = rest.split_first_chunk::<MEMBER_LEN>() else {
        return Err(Malformed);
    };
    let Some((third, rest)) = rest.split_first_chunk::<MEMBER_LEN>() else {
        return Err(Malformed);
    };
    let ([], Some(purpose)) = (rest, Purpose::from_byte(purpose)) else {
        return Err(Malformed);
    };
    let (first_stage, first_key) = parse_member(first, purpose)?;
    let (second_stage, second_key) = parse_member(second, purpose)?;
    let (third_stage, third_key) = parse_member(third, purpose)?;
    let stages = Stages {
        members: [first_stage, second_stage, third_stage],
        primary: usize::from(primary),
        revision: u64::from_le_bytes(*revision),
    };
    if version != VERSION || !stages.is_whole() {
        return Err(Malformed);
    }
    let header = Header {
        purpose,
        parent: *parent,
        epoch: u64::from_le_bytes(*epoch),
    };
    Ok((header, stages, [first_key, second_key, third_key]))
}

/// The stage and the key of one position of a set for `purpose`. An empty position is zero
/// throughout; reading it has no early exit.
fn parse_member(
    bytes: &[u8; MEMBER_LEN],
    purpose: Purpose,
) -> Result<(Option<Status>, Option<KeyBytes<'_>>), Malformed> {
    let Some((&[stage, length], key)) = bytes.split_first_chunk::<2>() else {
        return Err(Malformed);
    };
    let Ok(key) = <&[u8; CAPACITY]>::try_from(key) else {
        return Err(Malformed);
    };
    if stage == 0 {
        let empty = crate::record::lanes(key)
            .is_some_and(|[a, b, c, d]| u128::from(length) | a | b | c | d == 0);
        return if empty {
            Ok((None, None))
        } else {
            Err(Malformed)
        };
    }
    let (Some(status), Some(length)) = (Status::from_byte(stage), length_from_byte(length)) else {
        return Err(Malformed);
    };
    if !purpose.takes(length) || !crate::record::tail_is_zero(key, length) {
        return Err(Malformed);
    }
    Ok((Some(status), Some(KeyBytes::new(key, length))))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::{Header, MEMBERS, Malformed, PLAINTEXT_LEN, Refused, Stages, Status, build, parse};
    use crate::key::{Key, KeyLength};
    use crate::record::Purpose;

    const PARENT: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    fn counting(from: u8, length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| from.wrapping_add(u8::try_from(i).unwrap()))
            .collect()
    }

    /// The pieces, written out from the layout by hand, put one after another.
    fn laid_out(pieces: &[&[u8]]) -> [u8; PLAINTEXT_LEN] {
        pieces.concat().try_into().unwrap()
    }

    /// A set of one 32-byte key.
    fn one() -> [u8; PLAINTEXT_LEN] {
        laid_out(&[
            &[0x01, 0x01, 0x00], // version, purpose, primary position
            &PARENT,
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01], // epoch 0x0102030405060708
            &[0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21], // revision 0x2122232425262728
            &[0x01, 0x20],                                     // first position: enabled, 32 bytes
            &counting(0xa0, 32),
            &[0; 32],
            &[0; 66], // second position, empty
            &[0; 66], // third position, empty
        ])
    }

    /// A full set: a disabled 64-byte key, an enabled 32-byte key, and the primary, a 64-byte key
    /// in the third position.
    fn full() -> [u8; PLAINTEXT_LEN] {
        laid_out(&[
            &[0x01, 0x01, 0x02],
            &[0xf0; 16],
            &[0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // epoch 0xfffffffffffffffe
            &[0xff; 8],                                        // revision u64::MAX
            &[0x02, 0x40],
            &counting(0x40, 64),
            &[0x01, 0x20],
            &counting(0x80, 32),
            &[0; 32],
            &[0x01, 0x40],
            &counting(0xc0, 64),
        ])
    }

    /// The primary in the first position and a disabled 32-byte key in the third, with the second
    /// position empty between them.
    fn gap() -> [u8; PLAINTEXT_LEN] {
        laid_out(&[
            &[0x01, 0x01, 0x00],
            &PARENT,
            &[0; 8],
            &[0x05, 0, 0, 0, 0, 0, 0, 0],
            &[0x01, 0x20],
            &counting(0xa0, 32),
            &[0; 32],
            &[0; 66],
            &[0x02, 0x20],
            &counting(0x30, 32),
            &[0; 32],
        ])
    }

    fn key32(from: u8) -> Key {
        let mut key = Key::empty();
        key.load32(&mut counting(from, 32).try_into().unwrap());
        key
    }

    fn key64(from: u8) -> Key {
        let mut key = Key::empty();
        key.load64(&mut counting(from, 64).try_into().unwrap());
        key
    }

    struct Case {
        bytes: fn() -> [u8; PLAINTEXT_LEN],
        header: Header,
        stages: Stages,
        keys: [Option<(KeyLength, Vec<u8>)>; MEMBERS],
    }

    fn cases() -> [Case; 3] {
        [
            Case {
                bytes: one,
                header: Header {
                    purpose: Purpose::Wrap,
                    parent: PARENT,
                    epoch: 0x0102_0304_0506_0708,
                },
                stages: Stages {
                    members: [Some(Status::Enabled), None, None],
                    primary: 0,
                    revision: 0x2122_2324_2526_2728,
                },
                keys: [Some((KeyLength::Bytes32, counting(0xa0, 32))), None, None],
            },
            Case {
                bytes: full,
                header: Header {
                    purpose: Purpose::Wrap,
                    parent: [0xf0; 16],
                    epoch: 0xffff_ffff_ffff_fffe,
                },
                stages: Stages {
                    members: [
                        Some(Status::Disabled),
                        Some(Status::Enabled),
                        Some(Status::Enabled),
                    ],
                    primary: 2,
                    revision: u64::MAX,
                },
                keys: [
                    Some((KeyLength::Bytes64, counting(0x40, 64))),
                    Some((KeyLength::Bytes32, counting(0x80, 32))),
                    Some((KeyLength::Bytes64, counting(0xc0, 64))),
                ],
            },
            Case {
                bytes: gap,
                header: Header {
                    purpose: Purpose::Wrap,
                    parent: PARENT,
                    epoch: 0,
                },
                stages: Stages {
                    members: [Some(Status::Enabled), None, Some(Status::Disabled)],
                    primary: 0,
                    revision: 5,
                },
                keys: [
                    Some((KeyLength::Bytes32, counting(0xa0, 32))),
                    None,
                    Some((KeyLength::Bytes32, counting(0x30, 32))),
                ],
            },
        ]
    }

    fn keys_of(case: &Case) -> [Key; MEMBERS] {
        core::array::from_fn(|at| match &case.keys[at] {
            Some((KeyLength::Bytes32, bytes)) => key32(bytes[0]),
            Some((_, bytes)) => key64(bytes[0]),
            // A key the stages leave out is not written, whatever it holds.
            None => key64(0x99),
        })
    }

    type Read = (Header, Stages, [Option<(KeyLength, Vec<u8>)>; MEMBERS]);

    /// The header, the stages and each key as its length and bytes, or the error.
    fn read(bytes: &[u8; PLAINTEXT_LEN]) -> Result<Read, Malformed> {
        parse(bytes).map(|(header, stages, keys)| {
            let keys = keys.map(|key| {
                key.map(|key_bytes| {
                    let mut key = Key::empty();
                    key_bytes.load_into(&mut key);
                    let length = key.length();
                    (length, key.bytes()[..length.bytes()].to_vec())
                })
            });
            (header, stages, keys)
        })
    }

    #[test]
    fn each_set_is_written_as_the_layout_says() {
        for case in cases() {
            let keys = keys_of(&case);
            for old in [0x00, 0x55, 0xff] {
                let mut out = [old; PLAINTEXT_LEN];
                build(
                    &case.header,
                    &case.stages,
                    [&keys[0], &keys[1], &keys[2]],
                    &mut out,
                );
                assert_eq!(out, (case.bytes)());
            }
        }
    }

    #[test]
    fn each_set_is_read_as_the_layout_says() {
        for case in cases() {
            assert_eq!(
                read(&(case.bytes)()).unwrap(),
                (case.header, case.stages, case.keys)
            );
        }
    }

    /// The version is 1; the purpose is one of the three, and a set of external data or of a key
    /// for transfers holds only 32-byte keys, as [`gap`] does and [`full`] does not.
    #[test]
    fn the_version_is_one_and_the_purpose_takes_its_lengths() {
        for (position, bytes, accepted) in [
            (0, full(), &[1][..]),
            (0, gap(), &[1][..]),
            (1, full(), &[1][..]),
            (1, gap(), &[1, 2, 3][..]),
        ] {
            for value in 0..=u8::MAX {
                let mut changed = bytes;
                changed[position] = value;
                assert_eq!(
                    parse(&changed).is_ok(),
                    accepted.contains(&value),
                    "byte {position}, value {value}"
                );
            }
        }
    }

    #[test]
    fn the_primary_names_an_enabled_key() {
        for (bytes, enabled) in [(full(), &[1, 2][..]), (gap(), &[0][..]), (one(), &[0][..])] {
            for value in 0..=u8::MAX {
                let mut changed = bytes;
                changed[2] = value;
                assert_eq!(
                    parse(&changed).is_ok(),
                    enabled.contains(&value),
                    "value {value}"
                );
            }
        }
    }

    /// The offsets of the stage of each position, and which values each accepts in [`full`]: the
    /// primary in the third position may not be disabled, and no key may be marked empty.
    #[test]
    fn each_stage_accepts_only_its_values() {
        for (offset, accepted) in [(35, &[1, 2][..]), (101, &[1, 2]), (167, &[1])] {
            for value in 0..=u8::MAX {
                let mut bytes = full();
                bytes[offset] = value;
                assert_eq!(
                    parse(&bytes).is_ok(),
                    accepted.contains(&value),
                    "byte {offset}, value {value}"
                );
            }
        }
    }

    /// A 64-byte key may not be called 32 bytes long: its tail is not zero. A 32-byte key may be
    /// called 64 bytes long, and then it is a 64-byte key ending in zeros.
    #[test]
    fn each_length_accepts_only_its_values() {
        for (offset, accepted) in [(36, &[64][..]), (102, &[32, 64]), (168, &[64])] {
            for value in 0..=u8::MAX {
                let mut bytes = full();
                bytes[offset] = value;
                assert_eq!(
                    parse(&bytes).is_ok(),
                    accepted.contains(&value),
                    "byte {offset}, value {value}"
                );
            }
        }
    }

    #[test]
    fn the_tail_of_a_short_key_accepts_only_zero() {
        for (bytes, tail) in [(full(), 135..167), (gap(), 69..101), (gap(), 201..233)] {
            for offset in tail {
                for value in 0..=u8::MAX {
                    let mut changed = bytes;
                    changed[offset] = value;
                    assert_eq!(
                        parse(&changed).is_ok(),
                        value == 0,
                        "byte {offset}, value {value}"
                    );
                }
            }
        }
    }

    #[test]
    fn an_empty_position_accepts_only_zero() {
        for (bytes, empty) in [(gap(), 101..167), (one(), 101..167), (one(), 167..233)] {
            for offset in empty {
                for value in 0..=u8::MAX {
                    let mut changed = bytes;
                    changed[offset] = value;
                    assert_eq!(
                        parse(&changed).is_ok(),
                        value == 0,
                        "byte {offset}, value {value}"
                    );
                }
            }
        }
    }

    /// Bytes that would cancel out if an empty position were checked by anything but whether every
    /// byte is zero.
    #[test]
    fn an_empty_position_with_bytes_that_cancel_out_is_refused() {
        let mut bytes = gap();
        bytes[102] = 0x5a;
        bytes[140] = 0x5a;
        assert_eq!(parse(&bytes).err(), Some(Malformed));
        let mut bytes = gap();
        bytes[103..167].fill(0xff);
        assert_eq!(parse(&bytes).err(), Some(Malformed));
        // The length and the first key byte, and the first bytes of neighbouring 16-byte pieces.
        for (first, second) in [(102, 103), (103, 119), (119, 135), (135, 151)] {
            let mut bytes = gap();
            bytes[first] = 0x5a;
            bytes[second] = 0x5a;
            assert_eq!(
                parse(&bytes).err(),
                Some(Malformed),
                "bytes {first} and {second}"
            );
        }
    }

    /// Bytes past a short key that would cancel out if the tail were checked by anything but whether
    /// every byte is zero.
    #[test]
    fn a_short_key_with_a_tail_that_cancels_out_is_refused() {
        let mut bytes = full();
        bytes[135] = 0x5a;
        bytes[151] = 0x5a;
        assert_eq!(parse(&bytes).err(), Some(Malformed));
    }

    #[test]
    fn every_byte_lands_in_its_field() {
        let expected = &cases()[1];
        for offset in 0..PLAINTEXT_LEN {
            let mut bytes = full();
            bytes[offset] ^= 0xff;
            let mut header = expected.header;
            let mut epoch = header.epoch.to_le_bytes();
            let mut revision = expected.stages.revision.to_le_bytes();
            let mut keys = expected.keys.clone();
            let mut flip = |at: usize, index: usize| {
                if let Some((_, key)) = &mut keys[at] {
                    key[index] ^= 0xff;
                }
            };
            match offset {
                // The control bytes, the stages, the lengths and the zero tail of the short key.
                0..3 | 35 | 36 | 101 | 102 | 135..167 | 167 | 168 => {
                    assert_eq!(read(&bytes).err(), Some(Malformed), "byte {offset}");
                    continue;
                }
                3..19 => header.parent[offset.wrapping_sub(3)] ^= 0xff,
                19..27 => epoch[offset.wrapping_sub(19)] ^= 0xff,
                27..35 => revision[offset.wrapping_sub(27)] ^= 0xff,
                37..101 => flip(0, offset.wrapping_sub(37)),
                103..135 => flip(1, offset.wrapping_sub(103)),
                _ => flip(2, offset.wrapping_sub(169)),
            }
            header.epoch = u64::from_le_bytes(epoch);
            let stages = expected.stages.with_revision(u64::from_le_bytes(revision));
            assert_eq!(
                read(&bytes).unwrap(),
                (header, stages, keys),
                "byte {offset}"
            );
        }
    }

    fn stages(members: [Option<Status>; MEMBERS], primary: usize) -> Stages {
        Stages {
            members,
            primary,
            revision: 7,
        }
    }

    type Transition = fn(&mut Stages) -> Result<(), Refused>;

    const E: Option<Status> = Some(Status::Enabled);
    const D: Option<Status> = Some(Status::Disabled);

    #[test]
    fn a_set_of_one_is_whole() {
        let one = Stages::one();
        assert!(one.is_whole());
        assert_eq!(one.members, [E, None, None]);
        assert_eq!(one.revision, 0);
    }

    #[test]
    fn keys_go_through_their_stages_in_order() {
        let mut set = Stages::one();
        assert_eq!(set.add(), Ok(1));
        assert_eq!(set.promote(1), Ok(()));
        assert_eq!(set.disable(0), Ok(()));
        assert_eq!(set.enable(0), Ok(()));
        assert_eq!(set.disable(0), Ok(()));
        assert_eq!(set.destroy(0), Ok(()));
        assert_eq!(set, stages([None, E, None], 1).with_revision(6));
        assert_eq!(set.add(), Ok(0));
        assert_eq!(set.add(), Ok(2));
        assert_eq!(set.add(), Err(Refused::Full));
        assert_eq!(set.revision, 8);
    }

    impl Stages {
        fn with_revision(mut self, revision: u64) -> Self {
            self.revision = revision;
            self
        }
    }

    #[test]
    fn a_transition_out_of_order_is_refused_and_changes_nothing() {
        let set = stages([D, E, None], 1);
        let refusals: [(Transition, Refused); 12] = [
            (|s| s.promote(1), Refused::Primary),
            (|s| s.disable(1), Refused::Primary),
            (|s| s.enable(1), Refused::Primary),
            (|s| s.destroy(1), Refused::Primary),
            (|s| s.promote(0), Refused::Stage),
            (|s| s.disable(0), Refused::Stage),
            (|s| s.promote(2), Refused::Stage),
            (|s| s.disable(2), Refused::Stage),
            (|s| s.enable(2), Refused::Stage),
            (|s| s.destroy(2), Refused::Stage),
            (|s| s.enable(3), Refused::Stage),
            (|s| s.destroy(3), Refused::Stage),
        ];
        for (transition, refused) in refusals {
            let mut changed = set;
            assert_eq!(transition(&mut changed), Err(refused));
            assert_eq!(changed, set);
        }
    }

    #[test]
    fn an_exhausted_set_refuses_every_transition_and_changes_nothing() {
        let set = stages([D, E, None], 1).with_revision(u64::MAX);
        let transitions: [Transition; 3] =
            [|s| s.add().map(|_| ()), |s| s.enable(0), |s| s.destroy(0)];
        for transition in transitions {
            let mut changed = set;
            assert_eq!(transition(&mut changed), Err(Refused::Exhausted));
            assert_eq!(changed, set);
        }
        let mut promoted = stages([E, E, None], 1).with_revision(u64::MAX);
        assert_eq!(promoted.promote(0), Err(Refused::Exhausted));
        assert_eq!(promoted.disable(0), Err(Refused::Exhausted));
        assert_eq!(promoted, stages([E, E, None], 1).with_revision(u64::MAX));
    }
}

#[cfg(kani)]
#[coverage(on)]
pub(crate) mod proofs {
    use super::{
        Header, MEMBER_LEN, MEMBERS, PLAINTEXT_LEN, Refused, Stages, Status, build, parent_of,
        parse,
    };
    use crate::key::{Key, KeyLength};
    use crate::record::Purpose;

    /// Offsets of the positions, written from the layout.
    const POSITIONS: [usize; MEMBERS] = [35, 101, 167];

    /// Whether every byte of `bytes` from `start` to `end` is zero.
    fn zero(bytes: &[u8; PLAINTEXT_LEN], start: usize, end: usize) -> bool {
        let mut seen = 0;
        let mut at = start;
        while at < end {
            seen |= bytes[at];
            at += 1;
        }
        seen == 0
    }

    /// Whether the position starting at `at` is one `build` can write for the purpose `purpose`:
    /// keys of 32 or 64 bytes for 1, of 32 for 2 and 3.
    fn writable_position(bytes: &[u8; PLAINTEXT_LEN], at: usize, purpose: u8) -> bool {
        let stage = bytes[at];
        let length = bytes[at + 1];
        if stage == 0 {
            return zero(bytes, at, at + MEMBER_LEN);
        }
        (stage == 1 || stage == 2)
            && ((length == 64 && purpose == 1)
                || (length == 32 && zero(bytes, at + 34, at + MEMBER_LEN)))
    }

    /// Whether `build` can write `bytes` for stages that are whole, decided from the layout alone,
    /// not from `parse`.
    fn writable(bytes: &[u8; PLAINTEXT_LEN]) -> bool {
        let primary = bytes[2];
        let purpose = bytes[1];
        bytes[0] == 1
            && (purpose == 1 || purpose == 2 || purpose == 3)
            && writable_position(bytes, POSITIONS[0], purpose)
            && writable_position(bytes, POSITIONS[1], purpose)
            && writable_position(bytes, POSITIONS[2], purpose)
            && ((primary == 0 && bytes[POSITIONS[0]] == 1)
                || (primary == 1 && bytes[POSITIONS[1]] == 1)
                || (primary == 2 && bytes[POSITIONS[2]] == 1))
    }

    /// Whether `bytes` would be writable with the byte at `offset` set to `value`.
    fn with(bytes: &[u8; PLAINTEXT_LEN], offset: usize, value: u8) -> bool {
        let mut changed = *bytes;
        changed[offset] = value;
        writable(&changed)
    }

    /// For any 233 bytes, parsing succeeds exactly when the layout allows them, and never panics.
    #[kani::proof]
    #[kani::unwind(67)]
    fn parsing_a_set_accepts_exactly_what_building_can_write() {
        let bytes: [u8; PLAINTEXT_LEN] = kani::any();
        let accepted = parse(&bytes).is_ok();
        kani::assert(
            accepted == writable(&bytes),
            "parsing accepts exactly what the layout allows",
        );

        let [first, second, third] = POSITIONS.map(|at| bytes[at]);
        kani::cover!(accepted && second == 0 && third == 0, "a set of one");
        kani::cover!(
            accepted && first != 0 && second == 0 && third != 0,
            "an empty position between two keys"
        );
        kani::cover!(
            accepted && first == 2 && second == 1 && third == 1 && bytes[2] == 2,
            "a full set with the primary last"
        );
        kani::cover!(
            !accepted && with(&bytes, 0, 1),
            "only the version is refused"
        );
        kani::cover!(
            !accepted && bytes[1] > 3 && with(&bytes, 1, 1),
            "only the purpose is refused"
        );
        kani::cover!(accepted && bytes[1] == 2, "a set of external data");
        kani::cover!(accepted && bytes[1] == 3, "a set of a key for transfers");
        kani::cover!(
            !accepted && bytes[1] == 2 && with(&bytes, 1, 1),
            "only a key too long for external data is refused"
        );
        kani::cover!(
            !accepted && bytes[2] == 0 && first == 2 && with(&bytes, POSITIONS[0], 1),
            "only a disabled primary is refused"
        );
        kani::cover!(
            !accepted && bytes[2] == 3 && with(&bytes, 2, 0),
            "only a primary past the last position is refused"
        );
        kani::cover!(
            !accepted && first > 2 && with(&bytes, POSITIONS[0], 1),
            "only a stage is refused"
        );
        kani::cover!(
            !accepted && first == 1 && with(&bytes, POSITIONS[0] + 1, 64),
            "only a length is refused"
        );
        kani::cover!(
            !accepted && second == 0 && with(&bytes, POSITIONS[1] + 2, 0),
            "only a byte of an empty position is refused"
        );
        kani::cover!(
            !accepted && bytes[POSITIONS[0] + 1] == 32 && with(&bytes, POSITIONS[0] + 40, 0),
            "only the tail of a short key is refused"
        );
    }

    fn any_stage() -> Option<Status> {
        match kani::any::<u8>() {
            0 => None,
            1 => Some(Status::Enabled),
            _ => Some(Status::Disabled),
        }
    }

    pub(crate) fn any_whole_stages() -> Stages {
        let stages = Stages {
            members: [any_stage(), any_stage(), any_stage()],
            primary: kani::any(),
            revision: kani::any(),
        };
        // The primary's stage named by position, not read through an index chosen at run time.
        let [first, second, third] = stages.members;
        let primary = match stages.primary {
            0 => first,
            1 => second,
            2 => third,
            _ => None,
        };
        kani::assume(primary == Some(Status::Enabled));
        stages
    }

    /// Any purpose.
    pub(crate) fn any_purpose() -> Purpose {
        match kani::any::<u8>() % 3 {
            0 => Purpose::Wrap,
            1 => Purpose::ExternalData,
            _ => Purpose::Transfer,
        }
    }

    fn any_key() -> Key {
        let mut key = Key::empty();
        if kani::any() {
            key.load32(&mut kani::any());
        } else {
            key.load64(&mut kani::any());
        }
        key
    }

    /// Whether `purpose` takes a key of `length`, as the documentation of `Purpose` states it: any
    /// length for wrapping, 32 bytes for external data and for transfers. Written apart from the
    /// code.
    pub(crate) fn allowed(purpose: Purpose, length: KeyLength) -> bool {
        purpose == Purpose::Wrap || length == KeyLength::Bytes32
    }

    /// Any key of a length `purpose` takes.
    fn any_key_for(purpose: Purpose) -> Key {
        let key = any_key();
        kani::assume(allowed(purpose, key.length()));
        key
    }

    /// For any header of any purpose, any whole stages and any keys of a length the purpose
    /// takes, building puts every field where the layout says, empty positions zero, and parsing
    /// gives back the same header, stages and keys. The offsets and values are written from the
    /// layout, independently of the builder and the parser.
    #[kani::proof]
    #[kani::unwind(67)]
    fn building_then_parsing_gives_back_the_set() {
        let header = Header {
            purpose: any_purpose(),
            parent: kani::any(),
            epoch: kani::any(),
        };
        let stages = any_whole_stages();
        let keys = [
            any_key_for(header.purpose),
            any_key_for(header.purpose),
            any_key_for(header.purpose),
        ];
        let mut out: [u8; PLAINTEXT_LEN] = kani::any();
        build(&header, &stages, [&keys[0], &keys[1], &keys[2]], &mut out);

        let purpose = match header.purpose {
            Purpose::Wrap => 1,
            Purpose::ExternalData => 2,
            Purpose::Transfer => 3,
        };
        kani::assert(
            out[0] == 1 && out[1] == purpose && usize::from(out[2]) == stages.primary,
            "the control bytes are written as the layout says",
        );
        kani::assert(out[3..19] == header.parent, "the parent is at its offset");
        kani::assert(
            parent_of(&out) == &header.parent,
            "the parent is read from its offset",
        );
        kani::assert(
            out[19..27] == header.epoch.to_le_bytes(),
            "the epoch is at its offset, least significant byte first",
        );
        kani::assert(
            out[27..35] == stages.revision.to_le_bytes(),
            "the revision is at its offset, least significant byte first",
        );
        for at in 0..MEMBERS {
            let start = POSITIONS[at];
            let written = &out[start..start + MEMBER_LEN];
            match stages.members[at] {
                None => kani::assert(
                    written.iter().all(|&byte| byte == 0),
                    "an empty position is zero",
                ),
                Some(status) => {
                    let length = if keys[at].length() == KeyLength::Bytes32 {
                        32
                    } else {
                        64
                    };
                    let stage = if status == Status::Enabled { 1 } else { 2 };
                    kani::assert(
                        written[0] == stage && written[1] == length,
                        "the stage and the length of a key are at their offsets",
                    );
                    kani::assert(
                        written[2..] == keys[at].bytes()[..],
                        "a key is at its offset, zero past its length",
                    );
                }
            }
        }

        let parsed = parse(&out);
        kani::assert(parsed.is_ok(), "what building writes parses");
        // Not an `if let`: its failing path, ruled out above, would be proof code no proof reaches.
        let _ = parsed.map(|(read_header, read_stages, read_keys)| {
            kani::assert(read_header == header, "parsing gives back the header");
            kani::assert(read_stages == stages, "parsing gives back the stages");
            let [first, second, third] = read_keys;
            for (at, key_bytes) in [(0, first), (1, second), (2, third)] {
                kani::assert(
                    key_bytes.is_some() == stages.members[at].is_some(),
                    "a key is read exactly where the stages hold one",
                );
                if let Some(key_bytes) = key_bytes {
                    let mut read = Key::empty();
                    key_bytes.load_into(&mut read);
                    kani::assert(
                        read.bytes() == keys[at].bytes() && read.length() == keys[at].length(),
                        "parsing gives back each key and its length",
                    );
                }
            }
        });

        kani::cover!(stages.members[1].is_none(), "an empty position");
        kani::cover!(
            stages.members
                == [
                    Some(Status::Disabled),
                    Some(Status::Enabled),
                    Some(Status::Enabled)
                ]
                && stages.primary == 2,
            "a full set"
        );
        kani::cover!(stages.revision == u64::MAX, "the last revision");
        kani::cover!(
            header.purpose == Purpose::ExternalData && stages.members[0].is_some(),
            "a set of external data"
        );
        kani::cover!(
            header.purpose == Purpose::Transfer,
            "a set of a key for transfers"
        );
    }

    /// For any 233 bytes that parse, loading the keys and building again gives the same bytes: a
    /// set has exactly one way to be written.
    #[kani::proof]
    #[kani::unwind(234)]
    fn a_parsed_set_builds_back_to_the_same_bytes() {
        let bytes: [u8; PLAINTEXT_LEN] = kani::any();
        let Ok((header, stages, read_keys)) = parse(&bytes) else {
            return;
        };
        let mut keys = [any_key(), any_key(), any_key()];
        let [first, second, third] = read_keys;
        for (key, key_bytes) in keys.iter_mut().zip([first, second, third]) {
            if let Some(key_bytes) = key_bytes {
                key_bytes.load_into(key);
            }
        }
        let mut out: [u8; PLAINTEXT_LEN] = kani::any();
        build(&header, &stages, [&keys[0], &keys[1], &keys[2]], &mut out);
        kani::assert(out == bytes, "a parsed set builds back to the same bytes");

        kani::cover!(stages.members[2].is_none(), "an empty position");
        kani::cover!(
            stages.members[0] == Some(Status::Disabled),
            "a disabled key"
        );
    }

    /// From any whole stages, every transition at any position succeeds exactly when its starting
    /// stage holds and the revision has room, and then leaves exactly the stages written out below,
    /// one revision later; otherwise it is refused for the reason written out below and changes
    /// nothing. Either way the stages stay whole; a set of one is whole, so by induction every
    /// sequence of transitions from it keeps the set whole.
    #[kani::proof]
    #[kani::unwind(4)]
    fn a_transition_keeps_the_set_whole() {
        kani::assert(Stages::one().is_whole(), "a set of one is whole");
        let before = any_whole_stages();
        let at: usize = kani::any();
        let kind: u8 = kani::any();
        let room = before.revision < u64::MAX;
        let stage_at = before.members.get(at).copied().flatten();
        let first_empty = before.members.iter().position(Option::is_none);

        // What the transition should do, decided from the rules alone.
        let mut expected = before;
        let allowed = match kind {
            0 => match first_empty {
                None => Err(Refused::Full),
                Some(empty) => {
                    expected.members[empty] = Some(Status::Enabled);
                    Ok(())
                }
            },
            _ if at == before.primary => Err(Refused::Primary),
            1 if stage_at == Some(Status::Enabled) => {
                expected.primary = at;
                Ok(())
            }
            2 if stage_at == Some(Status::Enabled) => {
                expected.members[at] = Some(Status::Disabled);
                Ok(())
            }
            3 if stage_at == Some(Status::Disabled) => {
                expected.members[at] = Some(Status::Enabled);
                Ok(())
            }
            4.. if stage_at == Some(Status::Disabled) => {
                expected.members[at] = None;
                Ok(())
            }
            _ => Err(Refused::Stage),
        };
        let allowed = allowed.and_then(|()| {
            if room {
                Ok(())
            } else {
                Err(Refused::Exhausted)
            }
        });

        let mut after = before;
        let result = match kind {
            0 => {
                let added = after.add();
                if let Ok(position) = added {
                    kani::assert(
                        Some(position) == first_empty,
                        "adding returns the position it filled",
                    );
                }
                added.map(|_| ())
            }
            1 => after.promote(at),
            2 => after.disable(at),
            3 => after.enable(at),
            _ => after.destroy(at),
        };

        kani::assert(
            result == allowed,
            "a transition succeeds exactly when the rules allow it, and is refused for the first reason they give",
        );
        if result.is_ok() {
            expected.revision = before.revision + 1;
            kani::assert(
                after == expected,
                "a transition changes exactly what it names",
            );
        } else {
            kani::assert(after == before, "a refused transition changes nothing");
        }
        kani::assert(after.is_whole(), "the stages stay whole");

        kani::cover!(kind == 0 && result.is_ok(), "a key is added");
        kani::cover!(kind == 1 && result.is_ok(), "a key is promoted");
        kani::cover!(kind == 2 && result.is_ok(), "a key is disabled");
        kani::cover!(kind == 3 && result.is_ok(), "a key is enabled");
        kani::cover!(kind == 4 && result.is_ok(), "a key is destroyed");
        kani::cover!(result == Err(Refused::Full), "a full set refuses a key");
        kani::cover!(result == Err(Refused::Primary), "the primary refuses");
        kani::cover!(
            result == Err(Refused::Stage),
            "a key in another stage refuses"
        );
        kani::cover!(
            result == Err(Refused::Stage) && at >= MEMBERS,
            "a position past the last refuses"
        );
        kani::cover!(
            result == Err(Refused::Exhausted),
            "an exhausted set refuses"
        );
    }
}

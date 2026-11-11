// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The results of the Java layer: a level of storage is positive, a failure negative, as the
//! constants of `Keystore.java` define them.

use lethewis_android::{Failure, Level, Watchable, Watched};

const OK: i32 = 0;

pub(crate) fn level(code: i32) -> Result<Level, Failure> {
    match code {
        1 => Ok(Level::StrongBox),
        2 => Ok(Level::TrustedEnvironment),
        3 => Ok(Level::UnknownSecure),
        4 => Ok(Level::Software),
        5 => Ok(Level::Unknown),
        other => Err(failure(other)),
    }
}

pub(crate) fn status(code: i32) -> Result<(), Failure> {
    if code == OK {
        Ok(())
    } else {
        Err(failure(code))
    }
}

pub(crate) fn watched(code: i32) -> Result<Watched, Failure> {
    match code {
        6 => Ok(Watched::Kept),
        7 => Ok(Watched::Gone),
        other => Err(failure(other)),
    }
}

pub(crate) fn watchable(code: i32) -> Result<Watchable, Failure> {
    match code {
        8 => Ok(Watchable::Ready),
        9 => Ok(Watchable::NoLockScreen),
        10 => Ok(Watchable::NothingEnrolled),
        11 => Ok(Watchable::NotNow),
        12 => Ok(Watchable::Never),
        other => Err(failure(other)),
    }
}

pub(crate) fn presence(code: i32) -> Result<bool, Failure> {
    match code {
        1 => Ok(true),
        0 => Ok(false),
        other => Err(failure(other)),
    }
}

/// A code the layer does not define is a failure of unknown reason: never taken for a missing key.
const fn failure(code: i32) -> Failure {
    match code {
        -1 => Failure::Transient,
        -2 => Failure::Locked,
        -3 => Failure::Absent,
        -4 => Failure::Corrupted,
        -5 => Failure::StrongBoxUnavailable,
        -7 => Failure::Refused,
        _ => Failure::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use lethewis_android::{Failure, Level, Watchable};

    use super::{level, presence, status, watchable, watched};

    /// The constants as the Java layer declares them.
    fn declared() -> Vec<(String, i32)> {
        let source =
            include_str!("../../../android/src/main/java/com/alanwisper/lethewis/Keystore.java");
        source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("static final int "))
            .map(|declaration| {
                let (name, value) = declaration.trim_end_matches(';').split_once(" = ").unwrap();
                (name.to_owned(), value.parse().unwrap())
            })
            .collect()
    }

    #[test]
    fn the_codes_are_those_the_java_layer_declares() {
        let expected = [
            ("OK", 0),
            ("STRONG_BOX", 1),
            ("TRUSTED_ENVIRONMENT", 2),
            ("UNKNOWN_SECURE", 3),
            ("SOFTWARE", 4),
            ("UNKNOWN", 5),
            ("KEPT", 6),
            ("GONE", 7),
            ("READY", 8),
            ("NO_LOCK_SCREEN", 9),
            ("NOTHING_ENROLLED", 10),
            ("NOT_NOW", 11),
            ("NEVER", 12),
            ("TRANSIENT", -1),
            ("LOCKED", -2),
            ("ABSENT", -3),
            ("CORRUPTED", -4),
            ("STRONG_BOX_UNAVAILABLE", -5),
            ("UNKNOWN_FAILURE", -6),
            ("REFUSED", -7),
        ];
        let declared = declared();
        assert_eq!(declared.len(), expected.len(), "{declared:?}");
        for (name, value) in expected {
            assert!(
                declared.contains(&(name.to_owned(), value)),
                "{name} = {value}"
            );
        }
    }

    #[test]
    fn each_level_and_failure_reads_as_its_code() {
        assert_eq!(level(1), Ok(Level::StrongBox));
        assert_eq!(level(2), Ok(Level::TrustedEnvironment));
        assert_eq!(level(3), Ok(Level::UnknownSecure));
        assert_eq!(level(4), Ok(Level::Software));
        assert_eq!(level(5), Ok(Level::Unknown));
        for (code, failure) in [
            (-1, Failure::Transient),
            (-2, Failure::Locked),
            (-3, Failure::Absent),
            (-4, Failure::Corrupted),
            (-5, Failure::StrongBoxUnavailable),
            (-6, Failure::Unknown),
            (-7, Failure::Refused),
        ] {
            assert_eq!(level(code), Err(failure));
            assert_eq!(status(code), Err(failure));
            assert_eq!(presence(code), Err(failure));
            assert_eq!(watchable(code), Err(failure));
        }
        for (code, answer) in [
            (8, Watchable::Ready),
            (9, Watchable::NoLockScreen),
            (10, Watchable::NothingEnrolled),
            (11, Watchable::NotNow),
            (12, Watchable::Never),
        ] {
            assert_eq!(watchable(code), Ok(answer));
        }
        assert_eq!(watched(6), Ok(lethewis_android::Watched::Kept));
        assert_eq!(watched(7), Ok(lethewis_android::Watched::Gone));
        assert_eq!(status(0), Ok(()));
        assert_eq!(presence(0), Ok(false));
        assert_eq!(presence(1), Ok(true));
    }

    #[test]
    fn a_code_not_defined_is_never_a_missing_key() {
        for code in [i32::MIN, -8, 6, 7, 8, 12, 100, i32::MAX] {
            assert_eq!(level(code), Err(Failure::Unknown));
            assert_eq!(status(code), Err(Failure::Unknown));
            assert_eq!(presence(code), Err(Failure::Unknown));
        }
        for code in [i32::MIN, -8, 0, 1, 5, 8, 100, i32::MAX] {
            assert_eq!(watched(code), Err(Failure::Unknown));
        }
        for code in [i32::MIN, -8, 0, 1, 7, 13, 100, i32::MAX] {
            assert_eq!(watchable(code), Err(Failure::Unknown));
        }
        assert_eq!(level(0), Err(Failure::Unknown));
        assert_eq!(status(1), Err(Failure::Unknown));
        assert_eq!(presence(2), Err(Failure::Unknown));
    }
}

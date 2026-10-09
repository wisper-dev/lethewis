// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! The guard where data-independent timing cannot be reported: it does nothing.

pub(super) fn supported() -> bool {
    false
}

pub(super) fn active() -> bool {
    false
}

pub(super) fn switch_on() -> bool {
    false
}

pub(super) fn switch_off() {}

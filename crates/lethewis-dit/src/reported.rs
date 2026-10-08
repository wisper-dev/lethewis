// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! What an answer of `sysctlbyname` about a feature says.

/// Present only when the call succeeded and wrote a four-byte value that is not zero.
pub(crate) fn present(status: i32, size: usize, value: u32) -> bool {
    status == 0 && size == size_of::<u32>() && value != 0
}

#[cfg(test)]
mod tests {
    use super::present;

    #[test]
    fn only_a_successful_four_byte_answer_that_is_not_zero_counts() {
        assert!(present(0, 4, 1));
        assert!(!present(0, 4, 0));
        assert!(!present(-1, 4, 1));
        assert!(!present(0, 8, 1));
        assert!(!present(0, 0, 1));
    }
}

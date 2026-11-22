// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Measures the time of a key derivation from a password on the target device. Ignored by default;
//! run on a phone with `--ignored --nocapture --test-threads=1`.

use std::time::Instant;

use lethewis_core::{
    Entropy, EntropyError, Epoch, Error, MemoryBlock, PasswordParams, Slot, Slots,
};

struct Fixed(u64);

impl Entropy for Fixed {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for byte in dest {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *byte = (self.0 >> 56) as u8;
        }
        Ok(())
    }
}

fn once(memory_kib: u32, passes: u32) -> Result<u128, Error> {
    let mut source = Fixed(1);
    let params = PasswordParams::new(memory_kib, passes, &mut source)?;
    let mut memory = vec![MemoryBlock::new(); params.memory_blocks()];
    let (mut slot_memory, mut epoch) = ([const { Slot::empty() }; 2], Epoch::empty());
    let mut epoch_key = [0u8; 32];
    let mut slots = Slots::new(&mut slot_memory, &mut epoch, 0, &mut epoch_key);
    let mut password = b"correct horse battery staple".to_vec();
    let started = Instant::now();
    let handle = slots.derive_from_password(&mut password, &params, &mut memory)?;
    let millis = started.elapsed().as_millis();
    let _ = slots.release(handle);
    Ok(millis)
}

#[test]
#[ignore = "slow; a measurement on the target device"]
fn password_timing() -> Result<(), Error> {
    // One warm-up, then the median of three, to shed the first-run cost.
    for &(memory_kib, passes) in &[
        (65_536u32, 3u32),
        (131_072, 3),
        (262_144, 3),
        (524_288, 3),
        (1_048_576, 3),
        (262_144, 4),
        (262_144, 6),
    ] {
        let _ = once(memory_kib, passes)?;
        let mut runs = [
            once(memory_kib, passes)?,
            once(memory_kib, passes)?,
            once(memory_kib, passes)?,
        ];
        runs.sort_unstable();
        println!(
            "TIMING memory={}MiB passes={} -> {} ms",
            memory_kib >> 10,
            passes,
            runs[1]
        );
    }
    Ok(())
}

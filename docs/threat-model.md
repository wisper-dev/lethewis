# Threat model

This covers the library, not an application built on it: a screen, a network and a user each carry
threats this document does not reach.

**Lines marked "Intended" are design intentions, not working defences.** A line becomes "In place"
when the defence works and is checked on every change; what is proven, rather than tested, is
recorded in [proofs.md](proofs.md). Lines marked "Not defended" are true now and will stay true.

## What is protected

Key material on a device: the keys, the relationships between them, and the accuracy of what the
library reports about them. Not the data the keys encrypt.

## Adversaries, in order of priority

### 1. Someone holding the locked device

**Capability.** Physical possession, commercial forensic tooling, the ability to copy storage and to
attempt passwords. No knowledge of the password.

**In place, in the library.** A key is derived from a password with Argon2id over 64 MiB to 2 GiB
of memory and at least 3 passes. Parameters out of these bounds are neither made nor read, and other
parameters derive another key, under which no record wrapped under the first key opens.

A key is also derived from twelve words of the English list of BIP 39. The words a generation
writes stand for 128 bits of the platform's random source, hedged with the key of the epoch, and
cannot be guessed. Other words derive another key, under which no record wrapped under the first
key opens.

A key for wrapping from a password, from words or imported is never wrapped. It wraps only a stored
key for wrapping, in a lock record of two layers: the inner one opens only under that key, the outer
only under the key of the epoch. A guess at a password against a lock record needs that epoch's key too.

A key from a password can be combined with the chip's answer to a challenge derived from it: the key
the two make needs both, so each guess at the password needs the chip of the device.

**Intended.** Parameters tuned to seconds on the target device by the platform layer, and the
platform layer that puts the challenge to the chip. After destruction, no call returns the key.

**Not defended.** A device unlocked once since boot holds keys in memory, lock screen or not. Many
Android devices lack a dedicated secure element, so the password can be attacked off the device on
fast hardware, where a short secret falls quickly; their share is our estimate. The library is
intended to record the level actually reached.

A challenge read on its way to the chip lets guesses at the password run without the chip.

### 2. Someone who compels the password

**Capability.** Can demand that the owner unlock, lawfully or otherwise.

**In place, in the library.** A profile's stored key is destroyed by a change of epoch that carries
none of its lock records and locks it under no key again. Once the change is committed, the old root
erased and no slot holds the key, the password still derives its key, and that key opens nothing.

**Intended.** Give each profile its own entry key, so that a second password derives a different
profile's key rather than part of the same one.

**This is not deniable storage.** Whether a second profile exists at all is a question about the
storage layer, which is outside this library.

**Not defended.** An adversary who knows a second profile exists and keeps demanding. The library
cannot demonstrate that a hidden profile is absent. Destruction is a setting the owner enables, and in
some jurisdictions using it is itself an offence.

### 3. A laboratory reading the flash chip

**Capability.** Desoldering, reading raw flash, recovering superseded writes.

**In place, in the library.** A record is wrapped under a key derived from its epoch's key, and a
key set's change is saved only in a new epoch. Once the platform erases the old root, a record left
on flash from an earlier epoch no longer opens, even with the password; the commit reports how
surely it was erased.

A lock record is carried into a new epoch without the key from a secret that opens it, and one not
carried opens no more once the old root is erased: so a way in is revoked.

**Intended.** A platform layer whose root the hardware erases.

**Not defended.** Whoever held the key of an epoch while a lock record lived, and knows the secret it
was locked under, keeps the stored key it holds after that way in is revoked. Only a new stored key,
with every way in locked again, stands against that.

Whether a chip really erases a key, and whether the keys it uses to wrap its own
keys stay inside it, cannot be checked from outside. On a device without an erasable root, or where
a platform gives two epochs the same key, old records stay readable to whoever holds the password
and the flash.

### 4. An attacker on the same device

**Capability.** Another application, possibly with elevated privileges.

**In place.** Keys are held only in fixed-size slots whose memory the caller provides, each slot a
set of up to three keys. A key is held in one place only, whatever purpose it serves: a load of a key
the slots already hold, or of a set that holds one key twice, is refused.

Each key wraps only at its level: a key from a secret only stored keys for wrapping, in lock
records, and a stored key only keys for external data, in plain records. No call wraps a key from a
secret.

A new key is the hedge of the platform's random bytes under the key of the epoch, written straight
into its slot; the bytes drawn are wiped, and if the source fails or panics, so is the slot. The
keys of a set are wiped when it is released, and every key is wiped when its slots are dropped.

Only a key for external data is returned, to a call that names its purpose, into the caller's
buffer. The stack below the call is wiped after it, 8 KiB, or 64 KiB without optimisation, and a
test reads it back for the key.

Apart from a reveal, a set leaves its slot only as one record of all its keys, encrypted with
AES-256-GCM-SIV under a key derived from the key of the set that wraps it, bound to a context the
caller names. Only a key for wrapping wraps and unwraps; its set holds that one key and never
changes.

Before every wrap the cipher encrypts a known input of the shape of a record and must give the answer
an independent implementation gives, or nothing is written.

A record is unwrapped into a slot only after its tag, its layout and the identifier of the key that
wraps it are checked. A record that fails any of these checks is refused with one error.

After each key derivation, whether it succeeded or not, the stack below the caller is wiped: 8 KiB,
or 64 KiB in a build without optimisation. Tests read the memory of their own process back, with and
without optimisation and with the hardware and the software SHA-256, and check that the wipe reaches
that depth.

They also check that the derivation uses less than half of it and more than a sixteenth. They find
no 16-byte piece of the key, the extracted key, the HMAC key blocks, the SHA-256 states, inner hashes
and message schedules, or the output beyond the identifier, in the byte orders and arrangements the
two SHA-256 paths use.

After a wrap and an unwrap the stack below the caller is wiped as well: 24 KiB, or 64 KiB without
optimisation, at least twice what the cipher uses at every level of optimisation by the same
measurement.

Tests read the stack back after a wrap, an unwrap and an unwrap whose record fails its tag, with a set
of three keys under a 64-byte parent. They look for pieces of every key, of the derived cipher key
and of the message keys.

They also look for the AES round keys of the derived key and of the message encryption key as laid
out by the instructions, the keystream and what the record decrypts to.

The wipe on release and on creating the slots, and the refusal of a released or foreign handle, are
proven for two slots; the statements and their limits are in [proofs.md](proofs.md).

After a derivation from a password the stack below the caller is wiped: 32 KiB, or 192 KiB without
optimisation, twice what it uses or more. Tests read it back and find no 16-byte piece of the
password, of the hash Argon2id starts from, of the last block of its working memory or of the key.

The working memory a derivation from a password used is wiped whether it succeeded or not, and the
password only when it succeeded.

After each call on words that returns, the stack below the caller is wiped: 8 KiB, or 64 KiB without
optimisation. Tests read it back and find no 16-byte piece of the bytes in either
byte order, of the numbers or of the words laid out together, of the checksum's hash, of the
derivation or of the key.

The words are wiped when their key is derived, and left as they were when it is not. A generation
of words is the one call that gives out what a key derives from: its twelve words, once.

A key for external data is added enabled, and only a disabled key other than the primary is
destroyed, wiped with its identifier. A record of its set wrapped afterwards does not hold it; one
wrapped before still does, and opens until the next epoch is committed, then only while the
platform keeps the old root.

**Intended.** Drop keys from memory when the device locks.

**Not defended.** Copies left by a value move, a buffer reallocation, a CPU register, swap, or a
crash dump. A set of slots leaked instead of dropped keeps its keys in memory. A system component
with elevated privileges is outside what process isolation provides.

The stack wipe is best effort. It does not reach registers, and it relies on the compiler keeping
the derivation, the hedge, the reveal, the wrap and the unwrap out of their caller's frame. Its depth
follows the optimisation of this crate: a build that optimises it but not the hash and cipher code
sets `--cfg lethewis_unoptimised`.

The wipe is measured only where the tests run, so far x86-64 and aarch64 Linux, not on a
microcontroller such as Cortex-M. A call needs at least the stack its documentation states, as
deep as the wipe after it.

Without a guard on the stack, an MPU region or a layout that puts the stack below all other data, an
overflow corrupts memory silently.

The hedge does not cover a key of the epoch made by the same broken source, or a process or machine
copied with its state. Nor does it cover a source that repeats itself in another `Slots` under the
same key of the epoch, such as after a restart: the count of draws starts again with each `Slots`.

The salt of password parameters is not hedged: a broken source makes it predictable, and work done
in advance against a password then serves every device with that source.

The AES round keys of the software AES are bitsliced and are not looked for in that form. A record
is not bound to one key in the strict sense: whoever chooses two keys can cheaply build bytes the
cipher accepts under both.

For such bytes to unwrap under both keys they must also name each key's identifier, which raises the
work to no less than about 2^64 by estimate; this is not proven. A set cannot wrap itself, and since
no key is held in two places, no set is wrapped under one of its own keys.

Longer cycles, such as one set wrapped under another that is wrapped under the first, and a key whose
bytes begin with the bytes of the key it is wrapped under, are not detected. Two sets of slots alive
at once may hold the same key; the one-place rule holds within each.

The copy a reveal writes, and what the engine it goes to keeps, are the caller's to wipe; a key
revealed before a record of its set is stored is lost with the slots. The wipe after a reveal relies
on the reveal staying out of its caller's frame, and the call needs at least the stack it wipes.

A derivation from a password does not reach copies of the password made before the call, such as an
immutable string, or working memory the system swaps out. Its wipe reaches 32 KiB, or 192 KiB
without optimisation, and it needs 64 MiB of working memory, more than a microcontroller usually
has.

The words a generation writes are the caller's to show once and to wipe, and copies of words made
before a derivation are not reached. Whoever reads the words holds the key. A call on words needs at
least the 8 KiB, or 64 KiB, its wipe reaches.

### 5. The supply chain

**Capability.** A compromised dependency, a stolen maintainer credential, a rewritten tag.

**In place.** Licence and advisory gates, a committed lockfile, an exact compiler pin, tag rules that
forbid moving or deleting a tag, publication only from the build with a thirty-minute credential,
and a recorded review of every version of every dependency, including any build script or macro
it brings, read in full where the crate handles key material; the continuous integration check fails
without one, and nothing from a dependency is built before that check passes. The repository holds no
Cargo configuration file, no manifest patches or replaces a dependency, no toolchain file names a
compiler by path, and every dependency comes from crates.io; the same check enforces it.

**Not defended.** An undiscovered vulnerability in a dependency. An advisory published outside the
RustSec database, which is the only one the advisory gate reads. A compromise of the hosting
platform or of a maintainer's account. A dependent that resolves a newer version of a dependency
than the one reviewed here receives code this project has not read. A hostile change that also edits
these checks: they run from the change under review, so they catch a mistake, not an attack, and
what stands against an attack is the reading of every changed file before it is merged.

### 6. Timing and other side channels

**Not measured.** The cipher compares its tag, and the library compares the identifier of the
wrapping key a record names, through a comparison written for constant time: inline assembly on
x86-64 and aarch64, best effort on other targets.

A build step compiles that comparison for x86-64, aarch64, Cortex-M4 and WebAssembly and fails
unless its machine code runs straight through: no branch, no call and no write of the program
counter but the final return. This shows how the pinned compiler laid the code out, before
link-time optimisation, not how long each instruction takes.

AES and POLYVAL run on the processor's instructions where present and on bitsliced portable code
elsewhere. Whether those instructions take the same time for all data is up to the processor. On
recent Intel processors that holds only in a mode the operating system sets.

On aarch64 it holds only in the data-independent timing mode. `lethewis-dit` switches it on around
loading a key and wrapping and unwrapping a set where Linux, Android or an Apple system reports the
feature; elsewhere, and where the system or a virtual machine hides it, the mode stays off.

On Apple M1 and M2 the mode does not stop the data prefetcher from reading memory by its contents;
on M3 it does. On Cortex-M3 the portable multiplication varies with its operands, and WebAssembly
makes no promise.

When timing is measured, the tool, its version, the compiler version and the coverage will be stated
in [proofs.md](proofs.md). The available tools are statistical and detect only pronounced leaks, and
compiler optimisation can reintroduce a leak after a check has passed.

From the middle of its first pass on, Argon2id reads its memory at addresses that depend on the
password and divides values that depend on it, so whoever watches the cache of the same device, or
times the derivation, learns something about the password.

A word is looked up by comparing it with every word of the list, and written by reading every word,
in steps whose machine code the same build step checks on the same four targets. `lethewis-dit`
switches the mode on around reading and writing words as well.

## Assumptions

1. The device's hardware element behaves as documented by its manufacturer. An application cannot
   verify this.
2. The operating system is not already compromised when the library runs.
3. The owner's password is not known to the adversary and is not trivially guessable. Password
   strength is the application's responsibility; the library only makes guessing slow. Bringing a
   password typed as text into one Unicode form, NFC, before it reaches the library is the
   application's as well.
4. The third-party cryptographic primitives are sound. They are not proven here.
5. The platform's random source is unpredictable to the adversary, or the key of the epoch that
   keys, words and nonces drawn from it are hedged with is, provided the source does not repeat its
   bytes in another `Slots` under that key. The library does not test the source's output.
6. The twelve words are kept where only the owner reads them. Bringing typed words into twelve
   fields of 8 bytes, lowercase ASCII followed by zeros, is the application's.

## Known gaps

- No external audit has been performed.
- Deniable storage is outside this library, which supplies keys to it and makes no claim about it.
- Reproducible builds for native code inside an Android application: no published recipe was found.
  A CI job measures reproducibility of the Rust build.

# Threat model

This covers the library, not an application built on it: a screen, a network and a user each carry
threats this document does not reach.

**Lines marked "Intended" are design intentions, not working defences.** A line leaves that state
when [proofs.md](proofs.md) records what was checked. Lines marked "Not defended" are true now and
will stay true.

## What is protected

Key material on a device: the keys, the relationships between them, and the accuracy of what the
library reports about them. Not the data the keys encrypt.

## Adversaries, in order of priority

### 1. Someone holding the locked device

**Capability.** Physical possession, commercial forensic tooling, the ability to copy storage and to
attempt passwords. No knowledge of the password.

**Intended.** Derive the key from the password through a slow transformation tuned to seconds on the
target device, and have the hardware element wrap the master key, confining attempts to that one
device. After destruction, no call returns the key.

**Not defended.** A device unlocked at least once since boot holds keys in memory, and a lock screen
does not change that. On a large share of Android devices there is no dedicated secure element, and
the password can then be attacked off the device on fast hardware, where a short secret falls quickly.
Our figure for that share is an estimate rather than a measurement. The library is intended to record
which level was actually reached rather than assume the better one.

### 2. Someone who compels the password

**Capability.** Can demand that the owner unlock, lawfully or otherwise.

**Intended.** Give each profile its own entry key, so that a second password derives a different
profile's key rather than part of the same one, and allow destroying a profile's key on command.

**This is not deniable storage.** Whether a second profile exists at all is a question about the
storage layer, which is outside this library.

**Not defended.** An adversary who knows a second profile exists and keeps demanding. The library
cannot demonstrate that a hidden profile is absent. Destruction is a setting the owner enables, and in
some jurisdictions using it is itself an offence.

### 3. A laboratory reading the flash chip

**Capability.** Desoldering, reading raw flash, recovering superseded writes.

**Not defended, at all.** Deleting a key file is "most likely gone", never "certainly gone": flash is
not overwritten in place, and traces of earlier writes remain below the level any application can
reach.

### 4. An attacker on the same device

**Capability.** Another application, possibly with elevated privileges.

**Intended.** Wipe keys after use, size buffers in advance so that growth leaves no stale copies, and
drop keys from memory when the device locks.

**Not defended.** Copies left by a value move, a buffer reallocation, a CPU register, swap, or a crash
dump. A system component with elevated privileges is outside what process isolation provides.

### 5. The supply chain

**Capability.** A compromised dependency, a stolen maintainer credential, a rewritten tag.

**In place.** Licence and advisory gates, a committed lockfile, an exact compiler pin, tag rules that
forbid moving or deleting a tag, and publication only from the build with a thirty-minute credential.

**Intended** once there are dependencies: review of every build script and macro on each appearance.

**Not defended.** An undiscovered vulnerability in a dependency. A compromise of the hosting
platform or of a maintainer's account.

### 6. Timing and other side channels

**Not claimed either way.** Constant-time behaviour is not measured. When it is, the tool, its
version, the compiler version and the coverage will be stated in [proofs.md](proofs.md). The
available tools are statistical and detect only pronounced leaks, and compiler optimisation can
reintroduce a leak after a check has passed.

## Assumptions

1. The device's hardware element behaves as documented by its manufacturer. An application cannot
   verify this.
2. The operating system is not already compromised when the library runs.
3. The owner's password is not known to the adversary and is not trivially guessable. Password
   strength is the application's responsibility; the library only makes guessing slow.
4. The third-party cryptographic primitives are sound. They are not proven here.

## Known gaps

- No external audit has been performed.
- Deniable storage is outside this library, which supplies keys to it and makes no claim about it.
- Reproducible builds for native code inside an Android application: no published recipe was found.
  A CI job measures reproducibility of the Rust build.

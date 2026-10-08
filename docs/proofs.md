# Proofs

The register of what this library claims and what has been proven. A claim appears in the second
table only when the build runs its proof.

## Conditions for a row

All six must hold. A row missing any one of them is not written.

1. The tool and its exact version are named.
2. The statement is exact, and about this version of the crate.
3. The assumptions are listed, each with a written reason why the remaining inputs do not matter.
4. What is not covered is listed.
5. The proof runs in the build on every change. A proof too slow to run is marked unverified in
   that run, never skipped silently.
6. The proof has been checked with a deliberately introduced error (a flipped sign, a shifted
   bound, a changed constant) and it failed. A compile error does not count as a failure.

## Claimed

| Property | Statement | Crate |
|---|---|---|
| Key destruction | after destruction no reachable state holds the real key, and no later call returns it | `lethewis-core` |
| No key leak | a key leaves the library only wrapped: no call returns it in the clear, and it is never written to a sink the library controls | `lethewis-core` |
| Two-tier access | the key for history past a caller-supplied cut-off is not derivable from one password | `lethewis-core` |
| No silent substitution | when a key is lost the data either opens or is honestly marked unavailable; a replacement is never created silently | `lethewis-core` |
| Handle isolation | a handle reaches only the key it was issued for: never a key loaded later into the same slot, never a key in another set of slots | `lethewis-core` |
| No panic | no call panics or overflows, whatever the state of the slots and whatever handle is passed, unless the caller's random source panics | `lethewis-core` |
| Record layout | a record's plaintext is read back exactly as it was written, and bytes the library does not write are refused | `lethewis-core` |
| Key separation | the labels of two key derivations that differ in key length, branch or output length are different | `lethewis-core` |
| Record integrity | a key is loaded from a record only when the record is intact, opens with the parent named in it and the context it was wrapped for; a refused record loads nothing | `lethewis-core` |

Key shares and the time lock will each add a row when the crate exists. A call into the operating
system is covered by tests and by measurements on real devices, not by proof, so the crate that makes
such calls will not appear in either table.

## Proven

| Property | Statement | Crate | Tool and version | Runs on every change | Assumptions | Not covered |
|---|---|---|---|---|---|---|
| Key destruction, in slots | for any sequence of imports and releases, of any length, with any keys of 32 or 64 bytes over two slots: once a key is released its slot holds only zero bytes, in the key and in its identifier, and its handle is refused by every later call, including while the slot holds a new key; until then the handle reaches exactly its own key | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the wipe is modelled as stores of zero, because the real one ends in inline assembly the tool cannot model, and the real wipe is checked by a unit test; the proof checks one step by induction: from any state of two slots and for any handle that reaches exactly its own key or can never be live again because its slot is retired or past its generation, one import or one release keeps that so, a live handle stays live unless it is the one released, and a handle an import issues is a live handle of this set that reaches exactly its own key; any sequence follows step by step from the moment a handle is issued, and cover properties show a released handle refused while its slot holds a new key; the row on handle isolation within a set proves from any generation that every way of loading keeps the generation and a release advances it, so a slot never issues an old generation again however often it is reused; the starting states include every state the code can produce; the derivation of the identifier is modelled as in the row on handle isolation within a set | more slots; generations, unwraps and wraps within the sequence, whose rows prove what each does to the slots; copies the compiler makes in registers or on the stack; whether an optimised build keeps the wipe; the wipe when a set of slots is dropped |
| Key destruction, on creating a set | from any state of two slots, with any bytes left in any buffer, creating the set wipes every key and identifier and leaves no slot loaded | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the wipe is modelled as stores of zero, as above; the starting states include every state the code can produce | more than two slots; copies the compiler makes; whether an optimised build keeps the wipe |
| Handle isolation, between sets | from any state of two slots, a handle whose set number differs from this set's is refused, whatever slot and generation it names, and no slot changes | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | two sets alive at once have different numbers: the number is the address of their memory, the memory of two live sets does not overlap, and a handle keeps its memory borrowed | more than two slots |
| Handle isolation, within a set; no panic | from any state of two slots and any generation: a load by importing 32 or 64 bytes or by generating a key of either length from the platform's random source takes the first free slot, issues that slot's generation, keeps that generation in the slot and leaves exactly the imported or generated bytes there, zero past the key's length, with the purpose given, the enabled status and the identifier derived from those bytes, their length and that purpose; a load fails with `EntropyFailed` exactly when the source fails and with `DerivationFailed` exactly when the derivation fails; an import wipes its source exactly when it succeeds; a generation asks the source exactly once, for exactly the key's length, and has it write straight into the slot's buffer; a failed load changes no slot, and a full set asks the source for nothing; a handle of this set naming any slot and generation releases a key only if that slot is loaded with that generation, and otherwise is refused and changes nothing; a release wipes the key and its identifier and advances the generation by one, or retires the slot when the generation runs out; no call panics or overflows | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the starting states are a superset of those the code can produce; a key appears only in a loaded slot, because every path out of the loaded state wipes the key first, and bytes a generation writes into a free slot are wiped when it fails, which this proof checks, or when the source panics, which a unit test checks; the platform's source is modelled as one that writes any bytes and then succeeds or fails, and its panics are not modelled; HKDF-SHA-256 is modelled as a function that may fail, after writing into its output, and records whether it did, and otherwise gives the first 16 bytes of the key with the key's length and the label folded in, so the identifier depends on those bytes, that length and the label, while the label itself is built by the real code; one purpose exists, so the purpose kept cannot differ from the one given; the wipe is modelled as stores of zero, as above | more than two slots; the quality of the platform's random bytes; the values HKDF-SHA-256 gives, and that the rest of the key and the output length reach it, which the unit tests check against RFC 5869 and an independent implementation; panics inside HKDF-SHA-256, which the model stands in for; copies the compiler makes; whether an optimised build keeps the wipe |
| Record layout | a record's plaintext is 92 bytes: version (1 byte), purpose (1), key length (1), status (1), parent identifier (16), epoch (8, least significant byte first), key (64, zero past a 32-byte key). For any 92 bytes, parsing never panics or overflows, and accepts them exactly when the version is 1, the purpose is 1 (wraps keys), the length is 32 or 64, the status is 1 (enabled) or 2 (disabled), and the bytes past a 32-byte key are zero; for any attributes and any key of either length, building writes every field at the offset above, and parsing gives back the same attributes and the same key; for any bytes that parse, building again from what was read gives the same bytes, so a record has one way to be written | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the accepted values and the offsets are written from the layout, independently of the parser and the builder; a key is built only by the functions that load it, so its bytes past its length are zero, as the proofs on slots and the round trip in this row show | the encryption of the record, which the rows on wrapping and on record integrity cover with a model of the cipher; whether the check of the bytes past a 32-byte key takes the same time for every key |
| Key separation | for any key length, any branch and any output length that fits in two bytes, a derivation label is built, and the labels built for two derivations that differ in key length, branch or output length are different | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | one purpose exists, so the purpose is fixed; the layout of the label (library prefix, format version, purpose, key length, output length in two bytes least significant first, length of the branch name, branch name) and the fixed salt are checked by unit tests against labels written out by hand and against outputs of an independent HKDF-SHA-256; HKDF and SHA-256 are taken as correct, checked against the test vectors of RFC 5869 | that a derivation passes its purpose, branch, key length and output length to the label and the whole key to HKDF: for the identifier the proofs on slots check the key length, the branch and the first 16 bytes of the key with a model of HKDF, and the unit tests check the whole key and the output length for both branches and both key lengths; the strength of HKDF-SHA-256; copies of the key and of derived values in registers; the stack is wiped after each derivation, which tests check by reading the memory of the process, not a proof |
| No key leak, at the cipher | for any 32-byte key, 12-byte nonce, associated data, 92-byte record and 16-byte tag, and any behaviour of the cipher its interface allows: a seal that fails leaves the record buffer zero; opening fails exactly when the cipher rejects the record, and then leaves the buffer zero; neither panics | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | AES-256-GCM-SIV is modelled at one point: encryption writes any bytes into the buffer and then gives any tag or fails; decryption writes any bytes and then accepts or rejects at will, and records which; the wipe is modelled as stores of zero, as above; the associated data are four bytes, because the code around the cipher passes them on without reading them | the values the cipher gives, which unit tests check against the vectors of RFC 8452, appendices C.2 and C.3, on the portable code and on the hardware code of the x86-64 and aarch64 machines the tests run on, Linux and macOS; that a seal refuses to encrypt when the cipher gives a known input of the shape of a record a wrong answer, checked by unit tests against that answer computed by an independent implementation; panics inside AES-256-GCM-SIV, which the model stands in for; copies the cipher leaves in registers, and on the stack, which the wipe after a wrap or an unwrap covers and tests check |
| No key leak, wrapping | for two slots in any state, handles of this set naming any slots and generations, any context of up to two bytes, any record buffer, and any behaviour of the platform's random source and of the cipher its interface allows: wrapping changes no slot and writes the record only when it succeeds, beginning with the nonce the source gave; it fails with `InvalidContext` for an empty context, with `StaleHandle` unless both handles name loaded slots with their generations, with `SameKey` when both name keys with one identifier, with `KeyDisabled` when the parent is disabled, with `EntropyFailed` when the source fails, and otherwise succeeds or fails with `DerivationFailed` or `CipherFailed`; it never panics | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the cipher is modelled as in the row on the cipher; the derivation and the random source are modelled as in the rows on slots; the code reads a context only for its length, which unit tests check from 1 to 255 bytes, and passes its bytes on to the cipher, so contexts of up to two bytes stand for all; the comparison of key identifiers, which ends in inline assembly, is modelled as plain equality, and unit tests check the real one | that the record holds the key, its attributes and its parent's identifier under the key derived from the parent, with the nonce and the associated data the format states, which unit tests check against records computed by an independent implementation; more than two slots; copies the cipher and the derivation leave in registers; the stack they leave, local buffers included, is wiped after the call, which tests check by reading the memory of the process, not a proof; cycles longer than one key, such as one key wrapped under another wrapped under the first, and a key whose bytes begin with the bytes of the key it is wrapped under |
| Record integrity | for two slots in any state, a handle of this set naming any slot and generation, any 120-byte record, any context of up to two bytes and any behaviour of the cipher its interface allows: unwrapping fails with `InvalidContext` for an empty context, with `StaleHandle` unless the handle names a loaded slot with its generation, with `KeyDisabled` when the parent is disabled and with `NoFreeSlot` when no slot is free, all before it decrypts, and with `RecordRejected` when the cipher rejects the record; a failed unwrap changes no slot and one that succeeds changes only the first free slot. For two slots in any state, the parent loaded in either and any 92 bytes of decrypted plaintext: the key goes into a slot exactly when the bytes parse, the parent identifier they state is the parent's, a slot is free and the key's identifier is derived, and then the first free slot holds exactly the key the bytes hold at offset 28, zero past its length, with the purpose and status they state and that identifier; otherwise no slot changes and the failure is `RecordRejected`, `NoFreeSlot` or `DerivationFailed` in that order | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the cipher is modelled as in the row on the cipher; the comparison of the parent identifier, which ends in inline assembly, is modelled as plain equality, and unit tests check the real one; the offsets, values and lengths are written from the layout, independently of the parser; one purpose exists; contexts as in the row on wrapping | that a record opens only with its parent and context and that any changed bit is refused, which unit tests check for every bit of a record; whether the comparison takes the same time for every identifier, of which a build step checks only that its machine code on four targets runs straight through, with no branch, no call and no write of the program counter but the final return; the epoch, which is written as zero and not checked; more than two slots; copies the cipher and the derivation leave in registers; the stack they leave, local buffers included, is wiped after the call, which tests check by reading the memory of the process, not a proof |

A proof covers one named statement under named assumptions. Keeping the claims and the proofs in one
file is what keeps the distance between them visible.

The build accepts a proof run only if the pinned Kani ran, every declared proof ran by itself and
succeeded within 20 minutes, every proof lives in a module `proofs`, has a cover property and
reached all of them, every proof checks this repository's code, every `kani::assert(` and
`kani::cover!(` written out in the source is in the run, some proof reaches every region that Kani
compiled of the code in the modules `proofs`, and Kani reported no check in this repository's code
as unreachable. Each check is judged by itself, and an unknown status is a failure. The build keeps
the results and a manifest of the run with the tool versions.

## Checked against deliberate errors

Each error was introduced on purpose and was caught by the proof run or, where the table says so, by
unit tests: on an assertion, an unreached cover property, an unreachable check, an assertion missing
from the run, proof code that no proof reaches or a proof outside a module `proofs`, not on a
compile error.

| Error introduced | Caught by |
|---|---|
| a release that does not wipe the key | `a_step_keeps_every_handle_to_its_own_key` |
| a release that does not advance the generation | `a_step_keeps_every_handle_to_its_own_key` |
| a generation that repeats after four releases | `a_handle_releases_only_a_matching_loaded_slot` |
| a generation that wraps to zero instead of retiring the slot | `a_handle_releases_only_a_matching_loaded_slot` |
| a release that ignores whether the slot is loaded | `a_handle_releases_only_a_matching_loaded_slot` |
| a load that takes a retired slot | `a_load_takes_the_first_free_slot` |
| a load that issues generation zero | `a_load_takes_the_first_free_slot` |
| a load that changes the generation kept in the slot | `a_load_takes_the_first_free_slot` |
| a 64-byte import that records the length as 32 | `a_load_takes_the_first_free_slot` |
| a generated short key that takes the whole buffer | `a_load_takes_the_first_free_slot` |
| a generated long key that takes only 32 bytes from the source | `a_load_takes_the_first_free_slot` |
| a generation that never succeeds | `a_load_takes_the_first_free_slot` |
| a generation that asks the source again after a failure | `a_load_takes_the_first_free_slot` |
| a generation that writes the key into a local buffer and copies it into the slot | `a_load_takes_the_first_free_slot` |
| a generation that rejects an all-zero output the source reported as good | `a_load_takes_the_first_free_slot` |
| a guard that does not wipe the slot after a failed generation | `a_load_takes_the_first_free_slot` |
| a failed generation that marks the slot loaded | `a_load_takes_the_first_free_slot` |
| a generation that asks the source when no slot is free | `a_load_takes_the_first_free_slot` |
| a release that does not check which set of slots issued the handle | `a_handle_from_other_slots_is_refused` |
| a set check that compares with `<` or `>` instead of `!=` | `a_handle_from_other_slots_is_refused` |
| a new set of slots that does not wipe keys left in its memory | `creating_slots_wipes_every_key` |
| a wipe that keeps the length of the key | `creating_slots_wipes_every_key` |
| a new set of slots that wipes only the loaded ones | `creating_slots_wipes_every_key` |
| a new set of slots that keeps the identifier of a free slot | `creating_slots_wipes_every_key` |
| a load that derives the identifier through another branch | `a_load_takes_the_first_free_slot` |
| a load that does not store the identifier | `a_load_takes_the_first_free_slot` |
| a failed derivation that leaves the key in the slot | `a_load_takes_the_first_free_slot` |
| a failed derivation that marks the slot loaded | `a_load_takes_the_first_free_slot` |
| an import that fails with `EntropyFailed` | `a_load_takes_the_first_free_slot` |
| a load that fails for some keys the derivation accepts | `a_load_takes_the_first_free_slot` |
| a load that stores the identifier before it checks the derivation | `a_load_takes_the_first_free_slot` |
| a failed import that wipes its source | `a_step_keeps_every_handle_to_its_own_key` |
| a release that does not wipe the identifier | `a_step_keeps_every_handle_to_its_own_key`, `a_handle_releases_only_a_matching_loaded_slot` |
| a record that swaps the parent identifier and the epoch, in building and in parsing alike | `building_then_parsing_gives_back_the_record` |
| a record that writes and reads the epoch most significant byte first | `building_then_parsing_gives_back_the_record` |
| a parser that reads the epoch most significant byte first | `building_then_parsing_gives_back_the_record`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that accepts version 2 | `parsing_accepts_exactly_what_building_can_write`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that does not check the version | `parsing_accepts_exactly_what_building_can_write`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that accepts purpose 0 | `parsing_accepts_exactly_what_building_can_write`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a builder that writes the purpose as 2 | `building_then_parsing_gives_back_the_record`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that accepts status 0 | `parsing_accepts_exactly_what_building_can_write`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that reads status 2 as enabled | `building_then_parsing_gives_back_the_record`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that accepts a length of 48 | `parsing_accepts_exactly_what_building_can_write`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that reads a length of 64 as 32 | all three record proofs |
| a parser that does not check the bytes past a 32-byte key | `parsing_accepts_exactly_what_building_can_write`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that checks only the first byte past a 32-byte key | `parsing_accepts_exactly_what_building_can_write`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a parser that starts that check one byte early | `parsing_accepts_exactly_what_building_can_write`, `building_then_parsing_gives_back_the_record` |
| a builder that writes only the first 32 bytes of a key | `building_then_parsing_gives_back_the_record`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a builder that writes the key one byte late | `building_then_parsing_gives_back_the_record`, `a_parsed_record_builds_back_to_the_same_bytes` |
| loading parsed key bytes without wiping the key first | `building_then_parsing_gives_back_the_record`, `a_parsed_record_builds_back_to_the_same_bytes` |
| a derivation label without the output length | `different_derivations_have_different_labels` |
| a derivation label without the key length | `different_derivations_have_different_labels` |
| a derivation that passes only the first 32 bytes of a 64-byte key | `a_load_takes_the_first_free_slot`, and the unit tests that compare with HKDF called directly and with outputs of an independent implementation |
| a derivation that passes a 64-byte key with its second half zeroed | no proof: the same unit tests |
| a derivation that gives the label 32 as the length of every key | `a_load_takes_the_first_free_slot`, and the same unit tests |
| a derivation that expands from the key without the extract step | no proof: the unit tests that compare with HKDF called directly and with outputs of an independent implementation |
| a derivation with another salt | no proof: the same unit tests |
| a derivation not followed by the stack wipe | no proof: the tests that read the stack back from the memory of the process, with and without optimisation and with both SHA-256 back ends |
| the stack wipe run before the derivation instead of after it | no proof: the same tests |
| a stack wipe constant smaller than twice what the derivation uses | no proof: the test that measures the stack the derivation uses, with or without optimisation, as the constant is for |
| a build script that marks every build as built without optimisation | no proof: the test that measures the stack the derivation uses, which refuses a wipe more than sixteen times that, in an optimised build |
| a build script that never marks a build as built without optimisation | no proof: the same test, in a build without optimisation |
| a wipe call of a fixed size well short of the constant | no proof: the test that checks how deep the wipe reaches |
| a derivation that returns before the wipe when it fails | no proof: the test that reads the stack back after a failed derivation |
| the derivation and the hash code inlined into the caller | no proof: the tests that read the stack back, in the optimised build |
| a derivation label without the branch name, or without its length | no proof: the labels still differ while the two branch names differ in length; the unit tests that write the label out by hand catch it |
| a seal that does not wipe the buffer when it fails | `a_failed_seal_leaves_the_buffer_wiped` |
| a seal that skips the check of the cipher on a known input | no proof: the unit test that gives the check a wrong answer |
| that check comparing only the ciphertext, or only the tag | no proof: the same unit test |
| an open that does not wipe a refused record | `a_rejected_record_leaves_the_buffer_wiped` |
| an open that succeeds whatever the cipher says | `a_rejected_record_leaves_the_buffer_wiped` |
| an open that wipes a record that opens | no proof: the unit test that seals and opens a record |
| a seal or an open under the key, nonce or associated data of the check instead of those it is given | no proof: the unit test that seals and opens records under other keys, nonces and associated data |
| an unwrap that does not check the parent identifier a record names | `admitting_a_plaintext_loads_exactly_the_key_it_holds` |
| an unwrap that loads every key as enabled | `admitting_a_plaintext_loads_exactly_the_key_it_holds` |
| an unwrap that reports a malformed record as another error | `admitting_a_plaintext_loads_exactly_the_key_it_holds` |
| an unwrap with a disabled parent | `a_refused_unwrap_changes_no_slot` |
| an unwrap that looks for a free slot only after it decrypts | `a_refused_unwrap_changes_no_slot` |
| associated data that accept an empty context | `a_refused_unwrap_changes_no_slot`, `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap of a key under itself | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap with a disabled parent | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that writes the record before the seal succeeds | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that writes a zero nonce | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that compares slots instead of key identifiers, so a key loaded twice wraps itself | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds`, and the unit test that loads a key twice |
| a generation that marks the new key disabled | `a_load_takes_the_first_free_slot` |
| a load that does not record the status it is given | `a_load_takes_the_first_free_slot`, `admitting_a_plaintext_loads_exactly_the_key_it_holds` |
| a wrap that writes every key as enabled | no proof: the unit test that unwraps a disabled key and wraps it again |
| a wrap under the key of the identifier branch, or associated data without the length of the context | no proof: the unit test against records computed by an independent implementation |
| a parent identifier compared by its first byte only, or by its last byte only | no proof: the unit test with records that name another parent, one per changed byte; the proof models the comparison as plain equality |
| a wrap not followed by the stack wipe | no proof: the tests that read the stack back after a wrap, with and without optimisation and with both back ends |
| a wrap that wipes the stack only when it succeeds | no proof: the test that checks how deep the wipe after a failed wrap reaches |
| an unwrap that wipes the stack only when it succeeds | no proof: the test that reads the stack back after an unwrap whose record fails its tag, and, in an optimised build, the test that checks how deep the wipe after it reaches |
| the work of a wrap and an unwrap inlined into the calls that wipe after it | no proof: the tests that read the stack back, without optimisation |
| an unwrap not followed by the stack wipe | no proof: the test that reads the stack back after an unwrap whose record fails its tag, and, in an optimised build, the test that checks how deep the wipe after an unwrap reaches |
| a wipe after the cipher only as deep as the one after a derivation | no proof: the test that checks how deep the wipes after a wrap and an unwrap reach, in an optimised build |
| a cipher stack wipe constant smaller than twice what sealing or opening uses | no proof: the test that measures the stack the cipher uses, with or without optimisation, as the constant is for |
| a cipher stack wipe constant more than sixteen times what the cipher uses | no proof: the same test, in an optimised build |
| a cipher stack wipe of less than twice what the cipher uses when it is optimised for size | no proof: the same test, run at every level of optimisation |
| a wrap, an unwrap or a load held to less stack than it reaches, or documented with a stack or a wipe other than its own | no proof: the test that checks the documentation of each of those calls against the stack the tests allow and the wipes the library makes, and the test that measures how deep the calls reach |
| round keys looked for that a wrong S-box made | no proof: the test that checks the S-box and the key expansion against FIPS 197 |
| a parent identifier compared with an early exit, an early return on its first byte, a hand-off to a helper that exits early, or that comparison inlined into its callers | no proof: the build step that checks the comparison's machine code on four targets |
| rules of that build step that let a branch, a write of the program counter or a pop that does not return through, or that skip a directive that emits code, a second statement on a line or an instruction in upper case | no proof: the same step, which runs its rules on listings of known instructions of each target first |
| an induction step that assumes the tracked handle is live | the run: a cover property in `a_step_keeps_every_handle_to_its_own_key` is not reached |
| a release that wipes every slot | `a_step_keeps_every_handle_to_its_own_key` |
| a load that issues a handle of another set | `a_step_keeps_every_handle_to_its_own_key` |
| a cover property that cannot be reached | the run, although the tool itself reports success |
| a `kani::assert` in a proof branch that is never reached | the run: Kani reports it unreachable, and no proof reaches the branch |
| a `kani::assert` in a closure that never runs | the run: the assertion is not in it |
| a proof outside a module `proofs` | the run, before Kani starts |
| an `assert!` or an `unwrap` in a proof branch that is never reached | the run: no proof reaches the branch |
| an `assert!` in a method of a type in a module `proofs`, in a branch that is never reached | the run: no proof reaches the branch |

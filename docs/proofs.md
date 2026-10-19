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
| Key destruction | once destroyed and the next epoch committed, the key is in no slot of that set of slots and no record it wraps in that epoch; an older record opens only while the old root, or other slots, keep the old key; the commit reports how surely the root was erased; the same bytes, password or words bring it back | `lethewis-core` |
| No key leak | A key for wrapping leaves the library only wrapped: no call returns it in the clear, and it is never written to a sink the library controls. A key for external data is returned only to a call that names its purpose. A generation of words writes, once, the words its key derives from. | `lethewis-core` |
| Two-tier access | the key for history past a caller-supplied cut-off is not derivable from one password | `lethewis-core` |
| No silent substitution | when a key is lost the data either opens or is honestly marked unavailable; a replacement is never created silently | `lethewis-core` |
| Handle isolation | a handle reaches only the keys of its own set: never keys loaded later into the same slot, never keys in another set of slots | `lethewis-core` |
| One key, one place | a set of slots holds a key in one place only, whatever purpose it serves: a load or an addition that would hold it a second time is refused | `lethewis-core` |
| Hedged randomness | a key, words or a nonce the library draws is the hedge of the platform's bytes under the key of the epoch and a count of draws: within one set of slots, a broken source alone does not make them predictable, and two draws differ even when the source repeats itself | `lethewis-core` |
| Purpose separation | a key serves the purpose it was loaded with and no other: only a key for wrapping wraps and unwraps, only a key for external data is revealed, and no key of a length its purpose does not take is loaded or read; a set for wrapping holds one key and never changes | `lethewis-core` |
| No panic | no call panics or overflows, whatever the state of the slots and whatever handle is passed, unless the caller's random source panics | `lethewis-core` |
| Record layout | a record's plaintext is read back exactly as it was written, and bytes the library does not write are refused | `lethewis-core` |
| Key separation | the labels of two key derivations that differ in purpose, input length, branch or output length are different | `lethewis-core` |
| Record integrity | A set is loaded from a record only when the record is intact and opens with the parent's key for wrapping, named in it, the context it was wrapped for and the key of the epoch it names. A set for wrapping comes back only as a set of one that has never changed; a refused record loads nothing. | `lethewis-core` |
| Key set stages | a set of keys always has exactly one primary key, and it is enabled; only an enabled key becomes the primary or is disabled, only a disabled key is enabled again or destroyed, and a transition out of this order is refused and changes nothing | `lethewis-core` |
| Password parameters | the parameters of a derivation from a password are read back exactly as written, and none out of the bounds is made or read: memory from 64 MiB to 2 GiB, at least 3 passes, memory times passes up to 8 GiB | `lethewis-core` |
| Words | twelve words are read exactly when each is a word of the English list of BIP 39 and their checksum holds, and the words read are the words of the bytes they stand for: a set of bytes has one set of words | `lethewis-core` |
| Key levels | a key from a secret is never wrapped and wraps only stored keys for wrapping, in lock records; a stored key wraps only keys for external data; a lock record not carried into an epoch opens no more once that epoch is committed and the old root erased | `lethewis-core` |
| Saved changes | a set changes once in an epoch and is saved only by the next: until then it is neither released nor wrapped in its epoch; no set changes while the next epoch is prepared, which ends only when every changed set is wrapped for it and the platform switches the root | `lethewis-core` |

Key shares and the time lock will each add a row when the crate exists. A call into the operating
system is covered by tests and by measurements on real devices, not by proof, so the crates that
make such calls, `lethewis-dit` among them, appear in neither table. Under Kani, `lethewis-dit` only
runs the work it is given.

## Proven

| Property | Statement | Crate | Tool and version | Runs on every change | Assumptions | Not covered |
|---|---|---|---|---|---|---|
| Key destruction, in slots | for any sequence of imports and releases, of any length, with any keys of 32 or 64 bytes over two slots, each holding a set of up to three keys: once a set is released its slot holds only zero bytes, in every key and every identifier, and its handle is refused by every later call, including while the slot holds a new set; until then the handle reaches exactly its own keys | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the wipe is modelled as stores of zero, because the real one ends in inline assembly the tool cannot model, and the real wipe is checked by a unit test; the proofs check one step by induction: from any state of two slots and for any handle and any position whose key the handle reaches exactly or that can never be live again because its slot is retired or past its generation, one import or one release keeps that so, a live handle stays live unless it is the one released, and a handle an import issues is a live handle of this set that reaches exactly its own key; the step is checked by four proofs, an import with the first slot free, loaded or retired, the second free, loaded or retired, and a release from any state, which together are every state; any sequence follows step by step from the moment a handle is issued, and cover properties show a released handle refused while its slot holds a new set; the row on handle isolation within a set of slots proves from any generation that every way of loading keeps the generation and a release advances it, so a slot never issues an old generation again however often it is reused; the starting states include every state the code can produce; the derivation of an identifier is modelled as in that row | more slots; generations, unwraps, wraps, additions and changes of stage within the sequence, whose rows prove what each does to the slots; copies the compiler makes in registers or on the stack; whether an optimised build keeps the wipe; the wipe when a set of slots is dropped |
| Key destruction, on creating a set of slots | from any state of two slots, with any bytes left in any buffer, creating the set of slots wipes every key and identifier at every position, leaves no slot loaded or changed, and takes the epoch and its key, wiping the source | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the wipe is modelled as stores of zero, as above; the starting states include every state the code can produce | more than two slots; copies the compiler makes; whether an optimised build keeps the wipe |
| Handle isolation, between sets of slots | from any state of two slots, a release with a handle whose set number differs from this set's is refused, whatever slot and generation the handle names, and no slot changes | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | two sets of slots alive at once have different numbers: the number is the address of their memory, the memory of two live sets does not overlap, and a handle keeps its memory borrowed | more than two slots; calls other than a release, which reach a slot through the same check |
| Handle isolation, within a set of slots, for a load | From any state of two slots and any generation, a load that succeeds, for either purpose and a length it takes, takes the first free slot and keeps its generation. It leaves a set of one: the bytes imported, or the hedge of those generated, zero past their length; imported keys for wrapping are from a secret, generated ones stored. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | Starting states cover all reachable ones, as loads, additions, changes and unwraps keep: keys at filled positions only, of lengths their purpose takes; one key in a set for wrapping; any purpose in a free slot. HKDF-SHA-256 fails at will or folds in the first bytes of key and salt, key length and label. The source may fail after writing. | more than two slots; two sets of slots alive at once may hold the same key; the quality of the platform's random bytes; the values HKDF-SHA-256 gives, and that the rest of the key and the output length reach it, which the unit tests check against RFC 5869 and an independent implementation; panics inside HKDF-SHA-256, which the model stands in for; copies the compiler makes; whether an optimised build keeps the wipe |
| One key, one place, for a load | From the same states, the identifier of a loaded key is derived from its bytes and length alone. A load fails with `DuplicateKey` exactly when a loaded slot of any purpose holds a key with that identifier at a position its set fills, also a key held for another purpose. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the row above | as in the row above |
| No panic, for a load | From the same states, a load fails first with `WrongLength` for a length the purpose refuses, then with `NoFreeSlot` with no slot free, and with `EntropyFailed` or `DerivationFailed` exactly when the source or the derivation fails, changing no slot. An import wipes its source exactly on success. A generation asks the source once, for the key's length. Nothing panics. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the row above | as in the row above |
| Handle isolation, within a set of slots, for a release | From any state of two slots, a handle of this set naming any slot and generation releases a set only if that slot is loaded with that generation, else it changes nothing. A release wipes every key and identifier of the set and advances the generation by one, or retires the slot when it runs out, and never panics. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the row above | as in the row above |
| Hedged randomness, in slots | From any state of two slots and the epoch, the slot of a generated key, the nonce of a wrap and, with the first slot free, generated words are exactly the hedge of the bytes drawn and the count of draws: under the key of the epoch, or the next key for a nonce during a change. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | HKDF-SHA-256 is modelled as in the rows on slots; that model does not take in the count | that the count and every byte drawn reach HKDF, and its values, checked against an independent implementation; a key of the epoch from the same source; a copied process or machine; more than two slots |
| Hedged randomness, the count of draws | From the same states, a generation of a key or of words and a wrap add one to the count of draws exactly when the source answers. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the row above | that calls which do not draw keep the count, which a unit test checks; other sets of slots under the same key of the epoch, whose counts start again; more than two slots |
| Key set changes, in slots | From any state of two slots, promoting, disabling, enabling and destroying through a live handle refuse a set for wrapping with `WrongPurpose`, and otherwise change its stages exactly as the stage transition does, or fail as it does and change nothing. A destroy wipes the key and identifier at its position. Nothing else changes; a stale handle is refused. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | outside a change of epoch and for a set unchanged in this epoch, whose refusals the row on unsaved changes proves; the stage transitions are proven in the row on key set stages; the wipe is modelled as stores of zero | more than two slots; a record wrapped before a destroy, which still holds the key; copies the compiler makes |
| Epoch changes, in slots | From any state of two slots: a change begins only outside one and before the last epoch, wiping the source of the next key. Abandoning wipes that key and erases its root. A commit needs every changed set wrapped since and the root switched, then makes the next epoch current. Both return the platform's answer; a refusal changes nothing. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the platform switches the root or fails, and answers any level of erasure; it gives a key never used before for each epoch; the wipe is modelled as stores of zero | whether the platform erases the root as it answers; other sets of slots alive at once, each with its own copy of the epoch key; more than two slots; copies the compiler makes |
| Unsaved changes, in slots | In two slots in any state, no set changes during a change of epoch (`EpochChanging`, after `WrongPurpose` for one for wrapping); after a change or an addition, a set refuses another, a release and a wrap in its epoch with `Unsaved`, changing nothing. During a change a wrap marks the set wrapped for the next epoch. A record naming another epoch is refused. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the rows on changes, additions, releases, wrapping and record integrity prove the rest of each call | that a wrap during a change uses the key and number of the next epoch, which unit tests check by opening the record after the commit; more than two slots |
| Key additions, in slots | Importing a 32-byte key into a live set for external data, from any state of two slots, puts it enabled into the first empty position with its identifier and wipes the source. It fails as `WrongPurpose` for a set for wrapping, as the stages refuse, with `DerivationFailed`, or with `DuplicateKey` exactly when a loaded slot of any purpose holds the key, changing nothing. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | outside a change of epoch and for a set unchanged in this epoch, as for changes; the derivation is modelled as in the rows on slots; generation is not in these proofs: its fill is the one the load rows prove, and unit tests check where it writes, when the source is asked, its failure and its panic | more than two slots; the platform's random bytes; copies the compiler makes |
| Purpose separation, in slots | From any state of two slots, a wrap and an unwrap refuse a parent not for wrapping with `WrongPurpose` before they decrypt or write. Loads refuse a length the purpose does not take with `WrongLength` before the source is asked; additions through the first slot, and parsing, refuse it too. A set for wrapping takes no change or addition. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | starting states as in the rows on slots; the rows on loads, additions, wrapping, unwrapping and the record layout prove the rest of each call; keys from a password or words are loaded for wrapping, as their rows prove | an addition from the platform's source, which unit tests check; the same bytes for another purpose in another set of slots alive at once, or after their set is released; more than two slots |
| Password parameters, read | for any 25 bytes: they are read exactly when the first byte is 1 and the memory and the passes, 4 bytes each at offsets 1 and 5, least significant byte first, lie within the bounds: memory from 65,536 to 2,097,152 KiB, at least 3 passes, memory times passes at most 8,388,608 KiB; parameters read write back the same bytes | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the bounds and the offsets are written in the proofs from the documentation, independently of the code | whether the bounds suit a device, which the caller's choice of parameters decides; the strength of Argon2id |
| Password parameters, made | for any memory and passes: parameters are made only within the bounds above, asking the source once and only then; they hold the memory and passes asked for and the source's 16 bytes as the salt, and are read back as they are | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the bounds and the offsets are written in the proofs from the documentation, independently of the code; the random source writes any bytes and may fail | the quality of the platform's random bytes; whether the bounds suit a device; the strength of Argon2id |
| Password length | for any length: a password is refused exactly when it is empty or longer than 2^32 - 1 bytes | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | none: the check reads the length alone | that the derivation asks this check, which the proofs of the derivation reach only for passwords of up to two bytes |
| No panic, for a derivation from a password | from any state of two slots, with any parameters within the bounds, any password of up to two bytes and any working memory: an empty password and too little memory are refused first; a failure of Argon2id is `DerivationFailed`; the password is wiped exactly on success; a failure changes no slot; no derivation panics or overflows | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | Argon2id writes any 32 bytes, then succeeds or fails, and the proofs see which; a block of memory holds nothing, as the model never reads it; passwords of two bytes or fewer stand for all up to 2^32 - 1, as the code reads only their length; the identifier and the rest of the load are as on slots | that the password, the salt, the memory and the passes reach Argon2id, and the values it gives, which unit tests check against the reference implementation and an independent one; the wipe of the working memory and of the stack, which tests check; panics inside Argon2id; more than two slots; copies the compiler makes |
| Handle isolation, within a set of slots, for a derivation from a password | from the same states: a derivation that succeeds loads the first free slot with a set of one 32-byte key from a secret, for wrapping, zero past it, with the identifier derived from it, and changes no other slot | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | Argon2id writes any 32 bytes, then succeeds or fails, and the proofs see which; a block of memory holds nothing, as the model never reads it; passwords of two bytes or fewer stand for all up to 2^32 - 1, as the code reads only their length; the identifier and the rest of the load are as on slots | that the password, the salt, the memory and the passes reach Argon2id, and the values it gives, which unit tests check against the reference implementation and an independent one; the wipe of the working memory and of the stack, which tests check; panics inside Argon2id; more than two slots; copies the compiler makes |
| Words, lookup | for any list of three different words of 8 bytes and any 8 bytes: they are found exactly when an entry of the list is those bytes, and then with that entry's number; for any number, the entry of that number is read, and nothing past the list | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | a list of three stands for the list of 2048, because the code reads every list alike; the comparison and the choice, which end in inline assembly, are modelled as plain equality and selection, and unit tests check the real ones | the list itself, which unit tests check word by word against the published list and its SHA-256; the timing, beyond straight-line machine code of each step on four targets |
| Words, numbers | for any 16 bytes: twelve numbers below 2048 stand for them and carry their checksum; for any twelve numbers below 2048: they are the numbers of the bytes they stand for exactly when they carry the checksum of those bytes | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | SHA-256 is modelled as 4 bits that equal bytes give alike | the order BIP 39 fixes, 11 bits to a number from the most significant and the checksum last, and that the checksum is the first 4 bits of SHA-256: both functions read the same shifts, and unit tests check them against the vectors of the reference implementation |
| Words, read | for any list of three different words and any twelve words of 8 bytes: they are read exactly when each is of the list and their checksum holds; else `UnknownWord` comes before `InvalidChecksum`, and the bytes are wiped; words read are the words of the bytes read; no read panics or overflows | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the two rows above | the list of 2048, which unit tests check with the vectors and with random words through the real code, a million on every change; the stack the reading leaves, which tests check |
| No panic, for a derivation from words | from any state of two slots and any 16 bytes the words stand for: a failure of a derivation is `DerivationFailed`, and nothing else is, and changes no slot; with the first slot free and a list of three, refused words derive nothing, and the words are wiped exactly on success; no call panics or overflows | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | HKDF-SHA-256 as on slots, given the 16 bytes twice so that a 32-byte key takes every byte; the list as above; the calls on words are checked with the first slot free, where they differ from a load, whose rest is proven past a loaded and a retired slot as well | the values of HKDF from the bytes, which unit tests check against an independent implementation; the stack wipe, which tests check; panics inside HKDF-SHA-256 and SHA-256; more than two slots; copies the compiler makes |
| Handle isolation, within a set of slots, for a derivation from words | from the same states: a derivation that succeeds loads the first free slot with a set of one 32-byte key from a secret, for wrapping, derived from the bytes, zero past it, with the identifier derived from it, and changes no other slot | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the row above | as in the row above |
| Generation of words | with the first slot free and a list of three, a generation asks the platform source once for 16 bytes, fails with `EntropyFailed` exactly when it fails, and on success writes the words of their hedge and loads their key, else changes nothing; without a free slot, in all four ways two slots are taken, it asks nothing and changes nothing | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the rows above; the source writes any bytes and may fail | the quality of the platform's random bytes; the stack wipe, which tests check; more than two slots; copies the compiler makes |
| Record layout, the format | A record's plaintext has 233 bytes: version, purpose and primary position (1 byte each), parent identifier (16), epoch and revision (8 each, least significant byte first). Three positions of 66 bytes follow, each a stage (1 enabled, 2 disabled), a key length (1) and a key (64, zero past a 32-byte key), or zeros when empty. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the accepted values and the offsets are written from the layout, independently of the parser and the builder; a key is built only by the functions that load it, so its bytes past its length are zero, as the proofs on slots and the round trip in this row show | the encryption of the record, which the rows on wrapping and on record integrity cover with a model of the cipher; whether the checks of a 32-byte key's tail and of an empty position take the same time for every key |
| Record layout, parsing | For any 233 bytes, parsing never panics or overflows and accepts them exactly when the version is 1 and the purpose 1 (wrapping) or 2 (external data). Every position is zero or holds stage 1 or 2, length 32, or 64 for purpose 1, and zeros past a 32-byte key. The primary position, 0 to 2, holds an enabled key. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the row above | as in the row above |
| Record layout, building | For any header of either purpose, any stages whose primary position holds an enabled key and keys of lengths the purpose takes, building writes every field at its offset and an empty position as zeros. The parent identifier is read back from its offset, and parsing gives back the same set. Bytes that parse build back to the same bytes. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the row above | as in the row above |
| Key set stages | from any stages of three positions whose primary position holds an enabled key, and for any position: adding succeeds exactly when a position is empty, promoting and disabling exactly when the position holds an enabled key other than the primary, enabling and destroying exactly when it holds a disabled key other than the primary, each only while the revision is below its largest value, and a refusal gives the first reason in the order: a full set, the primary, another stage, an exhausted revision; a success leaves the primary position holding an enabled key, adds one to the revision and changes only what it names: adding fills the first empty position with an enabled key and returns that position, promoting changes only which position is the primary, disabling, enabling and destroying change only the stage at that position; a refusal changes nothing. By induction the same holds for every sequence of transitions from a set of one | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the stages are proven apart from the keys the positions hold; the cover properties show a success of each transition and each reason for a refusal | the keys in memory and in records, which the rows on slots cover; more than three positions |
| Key separation | for any purpose or none, any input length that fits in a byte, any branch and any output length that fits in two bytes, a derivation label is built, and the labels of two derivations that differ in any of these are different | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | Unit tests check the label's layout against hand-written labels: prefix, format version, purpose or zero for an identifier, input length, output length least significant byte first, branch name and its length. They check the salts, fixed for an identifier and the epoch's key for a wrap key, against an independent HKDF-SHA-256. The HKDF-SHA-256 the library calls passes RFC 5869. | that each derivation passes its purpose, branch, lengths and whole input on: the proofs on slots check part of it with a model of HKDF, unit tests the rest for every branch and length; the strength of HKDF-SHA-256; copies in registers; the stack wipe after each derivation, which tests check by reading the memory of the process |
| No key leak, at the cipher | for any 32-byte key, 12-byte nonce, associated data, 233-byte record and 16-byte tag, and any behaviour of the cipher its interface allows: a seal that fails leaves the record buffer zero; opening fails exactly when the cipher rejects the record, and then leaves the buffer zero; neither panics | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | AES-256-GCM-SIV is modelled at one point: encryption writes any bytes into the buffer and then gives any tag or fails; decryption writes any bytes and then accepts or rejects at will, and records which; the wipe is modelled as stores of zero, as above; the associated data are four bytes, because the code around the cipher passes them on without reading them | the values the cipher gives, which unit tests check against the vectors of RFC 8452, appendices C.2 and C.3, on the portable code and on the hardware code of the x86-64 and aarch64 machines the tests run on, Linux and macOS; that a seal refuses to encrypt when the cipher gives a known input of the shape of a record a wrong answer, checked by unit tests against that answer computed by an independent implementation; panics inside AES-256-GCM-SIV, which the model stands in for; copies the cipher leaves in registers, and on the stack, which the wipe after a wrap or an unwrap covers and tests check |
| No key leak, wrapping | For any slots, epoch, handles, context of up to two bytes, source and cipher: a wrap or a lock changes no key, stage or epoch and writes only on success, last nonce first. It refuses, in order, bad contexts, stale handles, a set under itself, parents not for wrapping, wrong levels, unsaved sets, failed sources. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the cipher is modelled as in the row on the cipher; the derivation and the random source are modelled as in the rows on slots; the code reads a context only for its length, which unit tests check from 1 to 255 bytes, and passes its bytes on to the cipher, so contexts of up to two bytes stand for all; a set cannot be wrapped under one of its own keys, because a key is held in one place only | what the record holds, under which key, nonce and associated data, which unit tests check against records an independent implementation computes; more than two slots; copies in registers; the stack wiped after the call, which tests read back; cycles longer than one set; a key whose bytes begin with those of its parent |
| No key leak, revealing | For two slots in any state and a handle of this set naming any slot and generation: a reveal writes exactly the 32-byte key at the position named when the handle is live, set and call name external data, and the key is enabled. Else it fails with `StaleHandle`, `WrongPurpose` or `WrongStage`, in order, writing nothing. No slot changes; nothing panics. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | starting states as in the rows on slots: a key for external data has 32 bytes, as loads, additions and records keep it | what the caller does with the copy; the stack the call leaves, which a test reads back; copies in registers; more than two slots |
| Record integrity, the trial | For any parent for wrapping, associated data of up to two bytes and cipher behaviour, the parent's key is tried once, under the key derived from it and the epoch's, or from it alone in a lock record. A failed derivation is `DerivationFailed`. The plaintext is kept exactly when the cipher accepts it and it names that key, else `RecordRejected`, writing nothing. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | The cipher is modelled as in the row on the cipher, and in the trial and the unwrap by a stand-in that writes any bytes, accepts or rejects at will and records the key it was given. Identifiers are compared as plain equality, and unit tests check the real comparison. | unit tests check instead that the handle's key is tried, that nonce, associated data and tag reach the cipher with every changed bit refused, the real path on a million random records, and the stack wipe; the comparison's timing, beyond straight-line machine code on four targets; the revision; more than two slots; register copies |
| Record integrity, unwrapping | For any two slots, handle, record or lock record and context of up to two bytes: an empty context, a stale handle, a parent not for wrapping, one of the other level and no free slot are refused in order, before decryption. A failed call changes no slot; a success only the first free slot, after accepted trials. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the cipher as above; contexts as in the row on wrapping; unwrapping is checked in three proofs, as a load is | as in the row above |
| Record integrity, admission | For any 233-byte plaintext, the set takes the first free slot exactly when one is free, the bytes parse, a plain record's are of external data and this epoch, a lock record's one unchanged key for wrapping of epoch zero, identifiers derive and none is held twice. The slot holds what they state, stored. Failures change no slot: `NoFreeSlot`, `RecordRejected`, `DerivationFailed`, `DuplicateKey`, in order. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | The offsets, values and lengths are written from the layout, independently of the parser. Whether bytes parse, and the stages they state, are taken from the parser, whose rows prove what it accepts and reads. Admitting is checked in three proofs, as a load is. | as in the row above |
| Lock records, unlocking | From the same states as unwrapping, an unlock opens the outer layer once, under the key derived from the key of this epoch, and refuses it as `StaleRecord`, decrypting nothing more, unless the cipher accepts it and it names this epoch. The inner record it then opens is the one the outer layer holds. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the cipher as above, at both layers; contexts as in the row on wrapping | which key seals each layer, which unit tests check against lock records computed by an independent implementation; more than two slots; register copies |
| Lock records, carrying | For any slots, epoch, lock record, output, context of up to two bytes, source and cipher: a carry changes nothing but the count of draws and its output. It refuses an empty context, no change, and as `StaleRecord` a record not opening in this epoch. It writes only on success, nonce first, hedged with the next epoch's key. | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | as in the row above | the key that seals the new layer and the number it names, which unit tests check against a carried record computed by an independent implementation; more than two slots; register copies |

A proof covers one named statement under named assumptions. Keeping the claims and the proofs in one
file is what keeps the distance between them visible.

The build accepts a proof run only if the pinned Kani ran, every declared proof ran by itself and
succeeded within 10 minutes, every proof lives in a module `proofs`, has a cover property and
reached all of them, every proof checks this repository's code, every `kani::assert(` and
`kani::cover!(` written out in the source is in the run, some proof reaches every region that Kani
compiled of the code in the modules `proofs`, and Kani reported no check in this repository's code
as unreachable. Each check is judged by itself, and an unknown status is a failure. The results are
read from CBMC's own output as Kani reads it; on every run, the reading is compared with Kani's own
results on a proof with every outcome, failures among them, and on two of these proofs. The build
keeps the results and a manifest of the run with the tool versions.

## Checked against deliberate errors

Each error was introduced on purpose and was caught by the proof run or, where the table says so, by
unit tests: on an assertion, an unreached cover property, an unreachable check, an assertion missing
from the run, proof code that no proof reaches or a proof outside a module `proofs`, not on a
compile error.

| Error introduced | Caught by |
|---|---|
| a release that does not wipe the keys | `a_step_by_a_release`, `a_handle_releases_only_a_matching_loaded_slot` |
| a wipe of a set that keeps its keys, or its identifiers | `a_step_by_a_release`, `a_handle_releases_only_a_matching_loaded_slot`, `creating_slots_wipes_every_key` |
| a wipe of a set that reaches only its first key | `a_step_by_a_release`, `a_handle_releases_only_a_matching_loaded_slot`, `creating_slots_wipes_every_key` |
| a release that does not advance the generation | `a_step_by_a_release` |
| a generation that repeats after four releases | `a_handle_releases_only_a_matching_loaded_slot` |
| a generation that wraps to zero instead of retiring the slot | `a_handle_releases_only_a_matching_loaded_slot` |
| a release that ignores whether the slot is loaded | `a_handle_releases_only_a_matching_loaded_slot` |
| a load that takes a retired slot | `a_load_past_a_retired_slot` |
| a load that issues generation zero | `a_load_into_the_first_slot` |
| a load that changes the generation kept in the slot | `a_load_into_the_first_slot` |
| a 64-byte import that records the length as 32 | `a_load_into_the_first_slot` |
| a generated short key that takes the whole buffer | `a_load_into_the_first_slot` |
| a generated long key that takes only 32 bytes from the source | `a_load_into_the_first_slot` |
| a generation that never succeeds | `a_load_into_the_first_slot` |
| a generation that asks the source again after a failure | `a_load_into_the_first_slot` |
| a generation that rejects an all-zero output the source reported as good | `a_load_into_the_first_slot` |
| a guard that does not wipe the slot after a failed generation | no proof: the unit tests of a failed and a panicking source; a load wipes its slot after any failure, so only a panic needs the guard, and panics are not modelled |
| a failed load that leaves the slot loaded | `a_load_into_the_first_slot` |
| a generation that asks the source when no slot is free | `a_load_past_a_loaded_slot` |
| a release that does not check which set of slots issued the handle | `a_handle_from_other_slots_is_refused` |
| a set check that compares with `<` or `>` instead of `!=` | `a_handle_from_other_slots_is_refused` |
| a new set of slots that does not wipe keys left in its memory | `creating_slots_wipes_every_key` |
| a wipe that keeps the length of the key | `creating_slots_wipes_every_key` |
| a new set of slots that wipes only the loaded ones | `creating_slots_wipes_every_key` |
| a load that derives the identifier through another branch | `a_load_into_the_first_slot` |
| a load that does not store the identifiers | `a_load_into_the_first_slot`, `admitting_into_the_first_slot` |
| a load that stores only the first identifier | `admitting_into_the_first_slot` |
| a failed load that leaves the keys in the slot | `a_load_into_the_first_slot`, `admitting_into_the_first_slot` |
| a failed load that marks the slot loaded | `a_load_into_the_first_slot` |
| an import that fails with `EntropyFailed` | `a_load_into_the_first_slot` |
| a load that fails for some keys the derivation accepts | `a_load_into_the_first_slot` |
| a load that ignores a failed derivation | `a_load_into_the_first_slot`, `admitting_into_the_first_slot` |
| a load that derives an identifier for every position, filled or not | `a_load_into_the_first_slot`, `admitting_into_the_first_slot` |
| a load that does not look for its key among the sets held | `a_load_into_the_first_slot`, `admitting_into_the_first_slot` |
| a held key looked for only at the first position of each set | `a_load_into_the_first_slot`, `admitting_into_the_first_slot` |
| a held key looked for in slots that are not loaded too | `a_load_into_the_first_slot` |
| a set that may hold one key twice, or its first or second key again in its third position | `admitting_into_the_first_slot`, and the unit tests on slots |
| a load that does not record the stages | `a_load_into_the_first_slot`, `admitting_into_the_first_slot` |
| a failed import that wipes its source | `a_step_by_an_import_into_the_first_slot`, `a_load_into_the_first_slot` |
| an import that does not wipe its source | `a_load_into_the_first_slot` |
| a load into the last free slot rather than the first | no proof: the unit test of imports past a retired slot |
| a set that swaps the parent identifier and the epoch, in building and in parsing alike | `building_then_parsing_gives_back_the_set` |
| a set that writes and reads the epoch most significant byte first | `building_then_parsing_gives_back_the_set` |
| a set parser that reads the epoch most significant byte first | `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a set parser that accepts purpose 0 | `parsing_a_set_accepts_exactly_what_building_can_write`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a set builder that writes each purpose one higher | `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a set parser that reads stage 2 as enabled | `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a set parser that accepts a length of 48 | `parsing_a_set_accepts_exactly_what_building_can_write`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a set parser that reads a length of 64 as 32 | all three proofs of the set layout |
| a tail check that reads nothing past a 32-byte key | `parsing_a_set_accepts_exactly_what_building_can_write`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a tail check that reads only the first byte past a 32-byte key | `parsing_a_set_accepts_exactly_what_building_can_write`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a tail check that starts one byte early | `parsing_a_set_accepts_exactly_what_building_can_write`, `building_then_parsing_gives_back_the_set` |
| a set builder that writes only the first 32 bytes of a key | `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a set builder that writes a key one byte late | `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| loading parsed key bytes without wiping the key first | `a_parsed_set_builds_back_to_the_same_bytes` |
| a parent field read one byte late | `building_then_parsing_gives_back_the_set`, `opening_uses_the_key_of_the_parent` |
| a set parser that accepts any version | `parsing_a_set_accepts_exactly_what_building_can_write` |
| a set parser that accepts a disabled primary | `parsing_a_set_accepts_exactly_what_building_can_write` |
| a set parser that reads every primary as the first position | `admitting_into_the_first_slot`, `building_then_parsing_gives_back_the_set` |
| a set parser that takes a primary past the last position as the last | `parsing_a_set_accepts_exactly_what_building_can_write` |
| an empty position whose length byte is not read | `parsing_a_set_accepts_exactly_what_building_can_write` |
| an empty position read only in its first byte | `parsing_a_set_accepts_exactly_what_building_can_write` |
| a set parser that does not check the tail of a short key | `parsing_a_set_accepts_exactly_what_building_can_write` |
| a set parser that reads the revision as the epoch | `building_then_parsing_gives_back_the_set` |
| a set parser that reads the second and third positions swapped | `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a set parser that reads the first and second positions swapped | `parsing_a_set_accepts_exactly_what_building_can_write`, `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| a set builder that writes the first and third positions swapped | `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| the second and third positions swapped in both the builder and the parser | no proof: the unit tests against sets written out from the layout by hand |
| the revision written most significant byte first by both the builder and the parser | no proof: the same unit tests |
| a set builder that always names the first position the primary | `building_then_parsing_gives_back_the_set` |
| a set builder that leaves the key of an empty position | `building_then_parsing_gives_back_the_set` |
| a set builder that writes every key as enabled | `building_then_parsing_gives_back_the_set` |
| disabling the primary | `a_transition_keeps_the_set_whole` |
| destroying an enabled key | `a_transition_keeps_the_set_whole` |
| enabling an enabled key | `a_transition_keeps_the_set_whole` |
| a promotion that counts a revision before it is allowed | `a_transition_keeps_the_set_whole` |
| a promotion that disables the former primary | `a_transition_keeps_the_set_whole` |
| a key added in the last empty position | `a_transition_keeps_the_set_whole` |
| a revision counter that wraps | `a_transition_keeps_the_set_whole` |
| a key added as disabled | `a_transition_keeps_the_set_whole` |
| a key added in the last empty position while the first is returned | `a_transition_keeps_the_set_whole` |
| a position read through its lowest byte | `a_transition_keeps_the_set_whole` |
| a full set that is refused as exhausted first | `a_transition_keeps_the_set_whole` |
| a derivation label without the output length | `different_derivations_have_different_labels` |
| a derivation label without the input length | `different_derivations_have_different_labels` |
| a derivation that passes only the first 32 bytes of a 64-byte key | `a_load_into_the_first_slot`, and the unit tests that compare with HKDF called directly and with outputs of an independent implementation |
| a derivation that passes a 64-byte key with its second half zeroed | no proof: the same unit tests |
| a derivation that gives the label 32 as the length of every key | `a_load_into_the_first_slot`, and the same unit tests |
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
| an unwrap that does not check the parent identifier a record names | `opening_uses_the_key_of_the_parent` |
| an unwrap that keeps a plaintext the cipher refused | `opening_uses_the_key_of_the_parent` |
| an unwrap that ignores a failed derivation of a cipher key | `opening_uses_the_key_of_the_parent` |
| an unwrap that does not keep the plaintext of the key that opens the record | `opening_uses_the_key_of_the_parent` |
| the key of a set for wrapping taken from its second position | `opening_uses_the_key_of_the_parent`, unit tests |
| a wrap of a set for wrapping | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds`, unit tests |
| a wrap under a key from a secret, or a lock under a stored key | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds`, `a_lock_changes_no_slot_and_writes_only_when_it_succeeds` |
| a lock of a key from a secret | `a_lock_changes_no_slot_and_writes_only_when_it_succeeds`, unit tests |
| a lock during a change that names this epoch, or seals under its key | no proof: the unit test that opens a lock record made during a change only after the commit |
| an unwrap under a key from a secret, or an unlock under a stored key | `an_unwrap_into_the_first_slot` |
| an admission of a set for wrapping from a plain record | `admitting_into_the_first_slot`, unit tests |
| an admission from a lock record that names an epoch | `admitting_into_the_first_slot`, unit tests |
| an unlocked key loaded as a key from a secret | `admitting_into_the_first_slot` |
| an imported key for wrapping loaded as a stored key, or a generated one as a key from a secret | `a_load_into_the_first_slot`, unit tests |
| a key from a password or from words loaded as a stored key | `a_derivation_from_a_password_into_the_first_slot`, `a_derivation_from_words_into_the_first_slot`, `words_are_written_exactly_when_their_key_is_generated` |
| an inner layer locked under a key derived with the key of the epoch, or naming the epoch | no proof: the unit tests against lock records computed by an independent implementation |
| an inner layer opened under a key derived with the key of the epoch | `opening_uses_the_key_of_the_parent`, unit tests |
| an outer layer read whatever epoch it names | `an_unwrap_into_the_first_slot`, `a_carry_changes_no_slot_and_writes_only_when_it_succeeds` |
| an outer layer kept when the cipher refuses it | `an_unwrap_into_the_first_slot`, `a_carry_changes_no_slot_and_writes_only_when_it_succeeds` |
| an inner record taken from the start of the outer layer | `an_unwrap_into_the_first_slot`, unit tests |
| an outer layer that does not open reported as a rejected record | `an_unwrap_into_the_first_slot`, `a_carry_changes_no_slot_and_writes_only_when_it_succeeds`, unit tests |
| an unlock that opens the outer layer under the key of the next epoch | `an_unwrap_into_the_first_slot` |
| a carry outside a change of epoch | `a_carry_changes_no_slot_and_writes_only_when_it_succeeds`, unit tests |
| a carry that opens under the key of the next epoch | `a_carry_changes_no_slot_and_writes_only_when_it_succeeds` |
| a carry that seals under the key of this epoch, or keeps the number of this epoch | no proof: the unit test against a carried record computed by an independent implementation, and the test that opens a carried record after the commit |
| an outer layer derived under the label of the inner | no proof: the unit tests against lock records computed by an independent implementation |
| a lock key under the name of a wrap key | `different_derivations_have_different_labels` |
| an unwrap that reports a malformed record as another error | `admitting_into_the_first_slot` |
| an unwrap that looks for a free slot only after it decrypts | `an_unwrap_past_a_loaded_slot` |
| an unwrap that admits the plaintext whatever the trial gives | `an_unwrap_into_the_first_slot` |
| an unwrap that does not check its parent handle | `an_unwrap_into_the_first_slot` |
| an admission that issues a handle with the next generation | `admitting_into_the_first_slot` |
| an unwrap that issues a handle of other slots | `an_unwrap_into_the_first_slot` |
| an admission that loads the second and third keys swapped | `admitting_into_the_first_slot` |
| an admission that loads its keys as a set of one | `admitting_into_the_first_slot` |
| an unwrap that tries the keys of the first slot rather than its parent's | no proof: the unit tests that unwrap under a parent in another slot |
| an admission that parses before it looks for a free slot | `admitting_past_a_loaded_slot` |
| associated data cut to their first 64 bytes | no proof: the unit test of the associated data, and the test of random records through the real cipher |
| associated data that accept an empty context | `an_unwrap_into_the_first_slot`, `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap of a set under itself | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that writes the record before the seal succeeds | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that writes a zero nonce | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that unloads every slot after it writes the record | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that does not check the parent handle | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that ignores a failed source | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap that writes the stages of a set of one | no proof: the unit tests against records computed by an independent implementation |
| a wrap under the key of the identifier branch, or associated data without the length of the context | no proof: the unit test against records computed by an independent implementation |
| a parent identifier compared by its first byte only, or by its last byte only | no proof: the unit test with records that name another parent, one per changed byte; the proof models the comparison as plain equality |
| a wrap not followed by the stack wipe | no proof: the tests that read the stack back after a wrap, with and without optimisation and with both back ends |
| a wrap that wipes the stack only when it succeeds | no proof: the test that checks how deep the wipe after a failed wrap reaches |
| an unwrap that wipes the stack only when it succeeds | no proof: the test that reads the stack back after an unwrap whose record fails its tag, and, in an optimised build, the test that checks how deep the wipe after it reaches |
| the work of a wrap and an unwrap inlined into the calls that wipe after it | no proof: the test that reads the stack back after a wrap and the test that checks how deep a wrap reaches, in an optimised build |
| an unwrap not followed by the stack wipe | no proof: the test that reads the stack back after an unwrap whose record fails its tag, and, in an optimised build, the test that checks how deep the wipe after an unwrap reaches |
| a wipe after the cipher only as deep as the one after a derivation | no proof: the test that checks how deep the wipes after a wrap and an unwrap reach, in an optimised build |
| a cipher stack wipe constant smaller than twice what sealing or opening uses | no proof: the test that measures the stack the cipher uses, with or without optimisation, as the constant is for |
| a cipher stack wipe constant more than sixteen times what the cipher uses | no proof: the same test, in an optimised build |
| a cipher stack wipe of less than twice what the cipher uses when it is optimised for size | no proof: the same test, run at every level of optimisation |
| a wrap, an unwrap, a load or a reveal held to less stack than it reaches, or documented with a stack or a wipe other than its own | no proof: the test that checks the documentation of each of those calls against the stack the tests allow and the wipes the library makes, and the test that measures how deep the calls reach |
| round keys looked for that a wrong S-box made | no proof: the test that checks the S-box and the key expansion against FIPS 197 |
| a parent identifier compared with an early exit, an early return on its first byte, a hand-off to a helper that exits early, or that comparison inlined into its callers | no proof: the build step that checks the comparison's machine code on four targets |
| rules of that build step that let a branch, a write of the program counter or a pop that does not return through, or that skip a directive that emits code, a second statement on a line or an instruction in upper case | no proof: the same step, which runs its rules on listings of known instructions of each target first |
| an induction step that assumes the tracked handle is live | the run: a cover property in `a_step_by_an_import_into_the_first_slot` and in `a_step_by_a_release` is not reached |
| a release that wipes every slot | `a_step_by_a_release` |
| a load that issues a handle of another set | `a_step_by_an_import_into_the_first_slot` |
| a cover property that cannot be reached | the run, although the tool itself reports success |
| a `kani::assert` in a proof branch that is never reached | the run: Kani reports it unreachable, and no proof reaches the branch |
| a `kani::assert` in a closure that never runs | the run: the assertion is not in it |
| an addition that puts the key at the first position whatever the stages say | `an_addition_in_the_first_slot` |
| an addition that keeps the new stages when it fails | `an_addition_in_the_first_slot` |
| an addition that looks for the key only in other slots | `an_addition_in_the_first_slot`, unit tests |
| an addition that leaves a refused key in its position | `an_addition_in_the_first_slot` |
| an addition that does not keep the identifier of its key | `an_addition_in_the_first_slot` |
| an addition that wipes its source also when it fails | `an_addition_in_the_first_slot` |
| a destroy that keeps the key, or its identifier | `a_change_of_stage_in_the_first_slot` |
| a destroy that wipes the first position | `a_change_of_stage_in_the_first_slot` |
| a disable that promotes | `a_change_of_stage_in_the_first_slot` |
| a change of stage that does not check its handle | `a_change_of_stage_with_a_stale_handle_changes_nothing` |
| a refused change that names the primary for a wrong stage | no proof: unit tests |
| an exhausted set refused as a full one | no proof: unit tests |
| an addition that does not check its handle | `a_change_of_stage_with_a_stale_handle_changes_nothing` |
| a proof outside a module `proofs` | the run, before Kani starts |
| a reading of the results that takes a failed check for one that holds | the comparison with Kani's results |
| a reading that takes a reached cover property for one never reached | the comparison with Kani's results |
| a reading that takes covered code for uncovered | the comparison with Kani's results |
| a reading that ignores which checks are unreachable | the comparison with Kani's results |
| a reading that leaves out checks Kani reports | the comparison with Kani's results |
| a reading that places a check in the file of its function rather than its own | the comparison with Kani's results |
| a reading that does not count the properties, so a lost line of the results goes unnoticed | the comparison with Kani's results |
| a proof with every outcome that no longer reaches a branch it never runs, or no longer has a check placed in a file other than its function's | the comparison with Kani's results: it requires every outcome |
| a proof that must panic, which the reading of the results does not support | the run, before Kani starts |
| an `assert!` or an `unwrap` in a proof branch that is never reached | the run: no proof reaches the branch |
| an `assert!` in a method of a type in a module `proofs`, in a branch that is never reached | the run: no proof reaches the branch |
| a wrap key derived without the key of the epoch | `opening_uses_the_key_of_the_parent`, unit tests |
| an unwrap that admits a record of another epoch | `admitting_into_the_first_slot` |
| an admission that takes a set for wrapping of more than one key | `admitting_into_the_first_slot` |
| a set of one that may have changed | `admitting_into_the_first_slot` |
| a wrap that writes the number of no epoch | no proof: unit tests |
| a wrap during a change under the key of this epoch | no proof: unit tests |
| a wrap of a changed set outside a change | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a wrap during a change that does not mark the set wrapped | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a change that does not refuse a set changed already | `a_change_of_stage_in_the_first_slot` |
| a change that does not mark the set changed | `a_change_of_stage_in_the_first_slot` |
| a change that keeps the mark of a set wrapped for the next epoch | `a_change_of_stage_in_the_first_slot` |
| an addition that does not refuse a set changed already | `an_addition_in_the_first_slot` |
| an addition that does not mark the set changed | `an_addition_in_the_first_slot` |
| an addition that keeps the mark of a set wrapped for the next epoch | `an_addition_in_the_first_slot` |
| a release of a changed set | `a_handle_releases_only_a_matching_loaded_slot`, `a_step_by_a_release` |
| an unload that keeps the mark of a change | `creating_slots_wipes_every_key` |
| new slots that do not wipe the source of the epoch key | `creating_slots_wipes_every_key` |
| a change begun while another is under way | `an_epoch_changes_only_in_order` |
| a change begun in the last epoch | `an_epoch_changes_only_in_order` |
| a change that keeps the source of the next key | `an_epoch_changes_only_in_order` |
| an abandoned change that keeps the next key | `an_epoch_changes_only_in_order` |
| an abandoned change that keeps the marks of sets wrapped for it | `an_epoch_changes_only_in_order` |
| a commit without a change | `an_epoch_changes_only_in_order` |
| a commit with a set unsaved | `an_epoch_changes_only_in_order` |
| a commit that goes on when the root is not switched | `an_epoch_changes_only_in_order` |
| a commit that keeps the old key of the epoch | `an_epoch_changes_only_in_order` |
| a commit that keeps the next key | `an_epoch_changes_only_in_order` |
| a commit that saves no set | `an_epoch_changes_only_in_order` |
| a commit that erases the new root | `an_epoch_changes_only_in_order` |
| a commit that reports a guarantee the platform did not give | `an_epoch_changes_only_in_order` |
| a change of stage during a change of epoch | `a_change_of_stage_in_the_first_slot`, `no_set_changes_during_a_change_of_epoch`, unit tests |
| an addition during a change of epoch | `no_set_changes_during_a_change_of_epoch`, unit tests |
| a change of stage of a set for wrapping | `a_change_of_stage_in_the_first_slot`, unit tests |
| an addition to a set for wrapping | `an_addition_in_the_first_slot`, unit tests |
| a change that refuses a set for wrapping only outside a change of epoch | `no_set_changes_during_a_change_of_epoch` |
| an abandon without a change under way | `an_epoch_changes_only_in_order` |
| an abandon that leaves the root made for the change | `an_epoch_changes_only_in_order` |
| new slots that keep what the memory of the epoch held | `creating_slots_wipes_every_key` |
| dropped slots that keep the keys of the epoch | no proof: unit tests |
| password parameters read in any version but zero | `parameters_are_read_exactly_as_written` |
| password parameters with less memory, two passes or twice the work allowed, or a most memory one KiB too high | `parameters_are_read_exactly_as_written`, `parameters_are_made_only_within_the_bounds` |
| password parameters whose work is counted in 32 bits | `parameters_are_read_exactly_as_written`, `parameters_are_made_only_within_the_bounds` |
| password parameters read with the memory and the passes swapped | `parameters_are_read_exactly_as_written`, `parameters_are_made_only_within_the_bounds` |
| password parameters written and read most significant byte first | `parameters_are_read_exactly_as_written`, `parameters_are_made_only_within_the_bounds` |
| password parameters written with a zero salt | `parameters_are_read_exactly_as_written`, `parameters_are_made_only_within_the_bounds` |
| new password parameters that ask the source when out of bounds, or ignore a failed source | `parameters_are_made_only_within_the_bounds` |
| a derivation from an empty password | `a_derivation_from_a_password_into_the_first_slot`, `passwords_are_taken_by_their_length` |
| a password of 2^32 bytes taken | `passwords_are_taken_by_their_length` |
| a derivation that takes one block less than its parameters | `a_derivation_from_a_password_into_the_first_slot` |
| a derivation that reports a failed Argon2id as a failed platform source, or as an invalid password | `a_derivation_from_a_password_into_the_first_slot` |
| a derivation that wipes the password before it checks the memory, or does not wipe it | `a_derivation_from_a_password_into_the_first_slot` |
| a derivation of a 64-byte key | `a_derivation_from_a_password_into_the_first_slot` |
| a derivation with Argon2i, Argon2d, version 0x10 or two lanes | no proof: the unit tests against vectors of the reference implementation and an independent implementation |
| a derivation with the memory and the passes swapped, or with a zero salt | no proof: the unit tests against vectors of the reference implementation and an independent implementation |
| a derivation that leaves its working memory, or wipes it only when the key is loaded | no proof: the unit test of the working memory after a derivation that succeeds and one that fails |
| a derivation from a password not followed by the stack wipe, or that returns before it when it fails | no proof: the tests that read the stack back and check how deep the wipe reaches, after a derivation that succeeds and one that fails, with and without optimisation |
| a stack wipe after a derivation from a password smaller than twice what it uses | no proof: the test that measures the stack the derivation uses, with and without optimisation |
| a derivation from a password documented with another stack | no proof: the test that checks the documentation against the stack the tests allow and the wipe the library makes |
| a lookup that skips the first entry or numbers the entries from one | `a_word_is_found_exactly_where_it_is_listed`, `words_are_read_exactly_when_listed_with_their_checksum` |
| a choice of a word that reads the entry after its number | `the_entry_of_a_number_is_read`, `words_are_read_exactly_when_listed_with_their_checksum` |
| a choice of a word that starts from a word that is not zero | `the_entry_of_a_number_is_read` |
| a lookup step that never marks a word, or a choice step that takes every entry | no proof: the unit tests of every word of the list |
| a lookup step that returns early or is inlined into the lookup, or a choice step that branches on the number | no proof: the check of the machine code on four targets |
| numbers one bit off from the first, a last number one bit off, or numbers read back without the last word's bits | `bytes_are_read_back_from_their_numbers`, `numbers_stand_for_one_set_of_bytes` |
| a checksum of 3 bits | `numbers_stand_for_one_set_of_bytes` |
| two shifts of the numbers swapped | no proof: the unit tests against the vectors of the reference implementation |
| words read with a bad checksum before an unknown word, refused words that keep their bytes, words read whatever their checksum when it is zero, or read without the first word looked up | `words_are_read_exactly_when_listed_with_their_checksum` |
| words written in the wrong order | `words_are_read_exactly_when_listed_with_their_checksum` and the unit tests against the vectors |
| a derivation from words that reports a failed derivation as a failed source, of a 64-byte key, or of the key of zero bytes | `a_derivation_from_words_into_the_first_slot` |
| a derivation from words under the label of a wrap key, or whose label states 32 bytes | `a_derivation_from_words_into_the_first_slot` and the unit tests against an independent HKDF-SHA-256 |
| a derivation from words that leaves the words, wipes them when the key is held already, or loads the key of zero bytes once the words are read | `words_are_wiped_exactly_when_their_key_is_derived` |
| a generation of words that writes them when the key is held already, reports a failed source as a failed derivation, asks the source for 32 bytes, or loads the key of zero bytes | `words_are_written_exactly_when_their_key_is_generated` |
| a generation of words that asks the source without a free slot | `no_words_are_generated_without_a_free_slot` |
| a word list with one word changed, or a checksum from the low 4 bits of the first byte of SHA-256 | no proof: the unit tests against the published list and the vectors of the reference implementation |
| a derivation from words or a generation of words not followed by the stack wipe, or a derivation from words inlined into its caller with the hash code | no proof: the tests that read the stack back, with and without optimisation |
| calls on words documented with another stack | no proof: the test that checks the documentation against the stack the tests allow |
| a wrap that does not check the purpose of its parent, checks the purpose of the set it wraps instead, or checks it only after it asks the source | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| an unwrap that does not check the purpose of its parent, or checks it only after it decrypts | `an_unwrap_into_the_first_slot` |
| a load that does not check the length its purpose takes, or checks it only after it asks the source | `a_load_into_the_first_slot` |
| a purpose for external data that takes 64-byte keys | `a_load_into_the_first_slot`, `a_long_addition_in_the_first_slot`, `parsing_a_set_accepts_exactly_what_building_can_write` |
| an addition that does not check the length its purpose takes | `a_long_addition_in_the_first_slot` |
| a set parser that does not check the length its purpose takes | `parsing_a_set_accepts_exactly_what_building_can_write`, and the unit tests on slots and on random records |
| a set parser that reads purpose 2 as wrapping | `building_then_parsing_gives_back_the_set`, `admitting_into_the_first_slot` |
| a set builder that writes every purpose as 1 | `building_then_parsing_gives_back_the_set`, `a_parsed_set_builds_back_to_the_same_bytes` |
| the purpose and the version swapped in both the builder and the parser | `building_then_parsing_gives_back_the_set`, and the unit tests against records computed by an independent implementation |
| an admission that loads a set for wrapping whatever its record says | `admitting_into_the_first_slot` |
| a held key looked for only among keys for wrapping, or an identifier derived for the purpose of wrapping | `a_load_into_the_first_slot` |
| an addition that looks for its key only among sets for wrapping | `an_addition_in_the_first_slot` |
| a derivation label without the purpose, or one that writes no purpose as the first | `different_derivations_have_different_labels`, and for the second the unit test of the label's layout |
| a key from words or from a password for external data | `a_derivation_from_words_into_the_first_slot`, `a_derivation_from_a_password_into_the_first_slot` |
| a reveal that does not check the purpose named or its handle, reveals a key for wrapping named so, a disabled key or the first position whatever is named, or writes before it refuses | `only_an_enabled_key_for_external_data_is_revealed` |
| a reveal not followed by the stack wipe | no proof: the test that reads the stack back after a reveal, without optimisation, and the test of how deep the wipe after it reaches |
| a reveal inlined into the call that wipes after it | no proof: the test that reads the stack back after a reveal, without optimisation |
| a reveal that returns before the wipe when it is refused | no proof: the test of how deep the wipe after a refused reveal reaches, in an optimised build |
| a load that keeps the purpose a free slot had, for a key for wrapping | `a_load_into_the_first_slot` |
| a purpose for wrapping that takes only 32-byte keys | `a_load_into_the_first_slot`, `parsing_a_set_accepts_exactly_what_building_can_write` |
| an addition from the platform's source that checks the length its purpose takes only after it asks the source | no proof: the unit test of the lengths each purpose takes |
| a wrap that writes the purpose of its parent, or always that of external data, into the record | no proof: the unit tests against records computed by an independent implementation, and the round trip of a set for external data |
| a generation that does not hedge, hedges under the salt of identifiers or the label of nonces, leaves the bytes drawn out of the material of the hedge, or reports a failed hedge as a failed source | `a_load_into_the_first_slot` |
| words drawn without the hedge or under the label of keys | `words_are_written_exactly_when_their_key_is_generated` |
| a nonce drawn without the hedge or under the label of keys, or a failed hedge of a nonce reported as a failed source | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds` |
| a nonce hedged with the key of this epoch during a change | `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds`, and the unit test of a nonce during a change |
| a generated key or words hedged with the next key during a change | `a_load_into_the_first_slot`, `words_are_written_exactly_when_their_key_is_generated` |
| a count of draws that does not grow | `a_load_into_the_first_slot`, `a_wrap_changes_no_slot_and_writes_only_when_it_succeeds`, `words_are_written_exactly_when_their_key_is_generated` |
| a count of draws that grows when the source fails | `a_load_into_the_first_slot` |
| a key from words through the hedge | `a_derivation_from_words_into_the_first_slot` |
| a key from a password through the hedge | no proof: the unit tests of the derivation from a password against an independent implementation |
| a hedge without the count | no proof: the unit tests against known answers, against HKDF called directly, and of a source that repeats itself |
| a commit that starts the count of draws again | no proof: the unit test of the count across calls that do not draw |
| a hedge that asks the source for a length it does not take | no proof: the unit test of lengths no hedge takes |
| a hedge that leaves the bytes drawn when the source panics | no proof: the test that reads the stack back after the panic, without optimisation, since with it the unwinding overwrites the bytes |
| a hedge not followed by the stack wipe | no proof: the test that reads the stack back after a hedge, with and without optimisation |
| a generation of a key with no stack wipe after the hedge, the identifier or the load, or of words with none after the hedge, the load or the generation | no proof: the tests that read the stack back after a generation of a key and of words, with and without optimisation |

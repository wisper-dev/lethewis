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
| No panic | no call panics or overflows, whatever the state of the slots and whatever handle is passed | `lethewis-core` |

Key shares and the time lock will each add a row when the crate exists. A call into the operating
system is covered by tests and by measurements on real devices, not by proof, so the crate that makes
such calls will not appear in either table.

## Proven

| Property | Statement | Crate | Tool and version | Runs on every change | Assumptions | Not covered |
|---|---|---|---|---|---|---|
| Key destruction, in slots | starting from empty memory with generation 0, for two slots and any sequence of four imports and releases with any keys: once a key is released its slot holds only zero bytes, and its handle is refused by every later call, including while the slot holds a new key | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the wipe is modelled as stores of zero, because the real one ends in inline assembly the tool cannot model, and the real wipe is checked by a unit test; four calls is the shortest sequence that reaches a released handle refused while its slot holds a new key, and a cover property shows that case is reached; the last row proves from any generation that an import keeps the generation and a release advances it, so a slot never issues an old generation again however often it is reused | longer sequences and more slots; copies the compiler makes in registers or on the stack; whether an optimised build keeps the wipe; the wipe when a set of slots is dropped |
| Key destruction, on creating a set | from any state of two slots, creating the set wipes every loaded key and leaves no slot loaded | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the wipe is modelled as stores of zero, as above; the starting states include every state the code can produce | more than two slots; copies the compiler makes; whether an optimised build keeps the wipe |
| Handle isolation, between sets | from any state of two slots, a handle whose set number differs from this set's is refused, whatever slot and generation it names, and no slot changes | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | two sets alive at once have different numbers: the number is the address of their memory, the memory of two live sets does not overlap, and a handle keeps its memory borrowed | more than two slots |
| Handle isolation, within a set; no panic | from any state of two slots and any generation: an import takes the first free slot, issues that slot's generation, keeps that generation in the slot and wipes its source; a handle of this set naming any slot and generation releases a key only if that slot is loaded with that generation, and otherwise is refused and changes nothing; a release wipes the key and advances the generation by one, or retires the slot when the generation runs out; no call panics or overflows | `lethewis-core` | Kani 0.68.0, CBMC 6.11.0, compiler nightly-2026-08-21 | yes | the starting states are a superset of those the code can produce; a key appears only in a loaded slot, because every path out of the loaded state wipes the key first; the wipe is modelled as stores of zero, as above | more than two slots; copies the compiler makes; whether an optimised build keeps the wipe |

A proof covers one named statement under named assumptions. Keeping the claims and the proofs in one
file is what keeps the distance between them visible.

The build accepts a proof run only if the pinned Kani ran, every declared proof ran and succeeded,
every proof has a cover property and reached all of them, every proof checks this repository's code,
and no check in that code was unreachable. Each check is judged by itself, and an unknown status is a
failure. The build keeps the results and a manifest of the run with the tool versions.

## Checked against deliberate errors

Each error was introduced on purpose, and the proof run failed on an assertion or an unreached cover
property, not on a compile error.

| Error introduced | Caught by |
|---|---|
| a release that does not wipe the key | `a_handle_reaches_only_its_own_key` |
| a release that does not advance the generation | `a_handle_reaches_only_its_own_key` |
| a generation that repeats after four releases | `a_handle_releases_only_a_matching_loaded_slot` |
| a generation that wraps to zero instead of retiring the slot | `a_handle_releases_only_a_matching_loaded_slot` |
| a release that ignores whether the slot is loaded | `a_handle_releases_only_a_matching_loaded_slot` |
| an import that takes a retired slot | `a_handle_releases_only_a_matching_loaded_slot` |
| an import that issues generation zero | `a_handle_releases_only_a_matching_loaded_slot` |
| an import that changes the generation kept in the slot | `a_handle_releases_only_a_matching_loaded_slot` |
| a release that does not check which set of slots issued the handle | `a_handle_from_other_slots_is_refused` |
| a set check that compares with `<` or `>` instead of `!=` | `a_handle_from_other_slots_is_refused` |
| a new set of slots that does not wipe keys left in its memory | `creating_slots_wipes_every_key` |
| a bound of three calls instead of four | the run: a cover property in `a_handle_reaches_only_its_own_key` is not reached |
| a cover property that cannot be reached | the run, although the tool itself reports success |

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
| No key leak | a key is never written to a sink the library controls, and leaves only through the one call meant to hand it over | `lethewis-core` |
| Two-tier access | the key for history past a caller-supplied cut-off is not derivable from one password | `lethewis-core` |
| No silent substitution | when a key is lost the data either opens or is honestly marked unavailable; a replacement is never created silently | `lethewis-core` |

Key shares and the time lock will each add a row when the crate exists. A call into the operating
system is covered by tests and by measurements on real devices, not by proof, so the crate that makes
such calls will not appear in either table.

## Proven

| Property | Statement | Crate | Tool and version | Runs on every change | Assumptions | Not covered |
|---|---|---|---|---|---|---|

A proof covers one named statement under named assumptions. Keeping the claims and the proofs in one
file is what keeps the distance between them visible.

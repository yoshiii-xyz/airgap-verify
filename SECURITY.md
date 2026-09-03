# Security policy

## Scope

Report issues that could make airgap-verify accept a changed artifact, trust
unverified evidence, escape the evidence directory, access the network, or
leak artifact or trust-root contents.

Do not include secrets, private artifacts, private trusted roots, or
unredacted evidence in an issue. Use the smallest reproducible fixture.

## Supported version

Only the latest main branch and the latest published release receive fixes.

## Design boundary

airgap-verify is a verifier, not a security boundary. The caller chooses the
trusted root and is responsible for deciding whether that root is authoritative.
Run it with least filesystem access to the named artifact and evidence
directory. The program does not fetch or refresh trust material.

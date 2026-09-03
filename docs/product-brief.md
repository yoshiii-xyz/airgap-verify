# Product brief

## Mission

Verify a local artifact and its local provenance evidence without network
dependency, while making incomplete claims visible in the verdict.

## MVP commands

~~~
airgap-verify verify artifact.tar.gz evidence/
airgap-verify inspect evidence/
airgap-verify version
~~~

## Supported format

The first release supports one regular local file whose basename ends in
.tar.gz. Its evidence directory contains:

1. bundle.sigstore.json, a Sigstore Bundle v0.3.
2. trusted-root.json, a serialized local Sigstore trusted root.

The bundle must contain one detached SHA-256 MessageSignature, one signing
certificate, one transparency-log entry with an inclusion proof, and one
signed entry timestamp. The artifact itself is hashed as bytes. Archive member
contents are not inspected.

## Required behavior

- Report the artifact SHA-256 digest and size.
- Report signature, certificate chain, timestamp, and transparency status.
- List the local trusted root file used.
- State that network access was not attempted.
- List every missing or unverifiable claim.
- Return a fail verdict when any required claim is incomplete.
- Reject duplicate JSON object keys before parsing.
- Reject evidence symlinks, nonregular entries, path-shaped names, and
  oversized bundles.
- Keep machine-readable output deterministic for the same inputs.

## Automated validation boundary

The test suite covers valid and invalid signatures, wrong artifacts and trust
roots, missing and malformed evidence, duplicate claims, symlink path
traversal, an expired integrated time, a Linux network syscall deny filter,
deterministic JSON, and large evidence limits.

The release gate also runs a bounded parser fuzz target and the independent
artifact smoke checks described in docs/release.md.

## Non-goals

The MVP does not parse archive members, support DSSE or public-key bundles,
fetch trust material, contact Rekor or a timestamp service, provide a hosted
service, add a frontend, or make broad compatibility claims. Human usability
and physical-device validation are excluded.

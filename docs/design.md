# Design

## Input boundary

The artifact must be a regular local file with a .tar.gz basename. Symlink
artifacts and directories are rejected. The artifact is read in 64 KiB chunks,
so hashing does not load the artifact into memory.

The evidence path must be a regular directory, not a symlink. Only direct
regular files are accepted. Entry names are converted to UTF-8, sorted, and
checked for path separators. The loader enforces 128 entries, 16 MiB per
file, and 32 MiB total.

## Duplicate claim handling

JSON object keys are scanned recursively with a serde visitor before either
the bundle or trusted root parser is called. A duplicate key is an
unverifiable claim, even if the later value would have produced a valid
structure under last-value-wins parsing.

## Bundle and root verification

The supported bundle is the exact v0.3 media type with detached
MessageSignature content and a SHA-256 message digest. Exactly one
transparency-log entry is required. Its inclusion proof and signed entry
timestamp are required before cryptographic verification begins.

The serialized trusted root is loaded directly with
sigstore-trust-root::TrustedRoot::from_json. TUF and network features are
disabled in the dependency configuration. The default sigstore-verify policy
checks the certificate chain, SCT, transparency inclusion, signed artifact
signature, and artifact digest.

The program passes only when all preflight claims are complete, the supplied
artifact digest matches, the local root parses and has the required key
material, and the verifier returns success with a verified integrated time.

## Reports

Reports contain stable schema fields and basenames rather than absolute
paths. Evidence files are sorted by name. Missing claims are sorted and
deduplicated. No current time, random identifier, or network response is
placed in output.

inspect performs the bounded file and structural checks only. It does not
make a cryptographic pass claim.

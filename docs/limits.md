# Limits

## Supported format

Only a regular .tar.gz file paired with one Sigstore Bundle v0.3 detached
SHA-256 MessageSignature is supported. The program does not inspect the tar
or gzip structure. DSSE envelopes, public-key bundles, certificate-chain
bundles, other bundle versions, and other artifact names are rejected.

## Evidence and trust

The verifier trusts only the serialized root supplied as trusted-root.json.
It does not decide whether a caller-selected root is appropriate. It does not
fetch updated roots, query a log, or ask a timestamp authority for missing
evidence.

Evidence is bounded to 128 direct entries, 16 MiB per file, and 32 MiB total.
Symlinks, directories, non-UTF-8 names, path-shaped names, and files that
exceed those limits are rejected.

## Time and filesystem behavior

The supplied bundle's signed time must verify against the local trusted root
and certificate validity. A changed artifact or changed signed time fails.
There is no snapshot transaction across concurrent artifact replacement, so a
caller that needs stronger file isolation must provide it.

The MVP is Linux-first. Windows and macOS builds may compile, but the release
evidence does not promise physical-device behavior or broad platform support.
Human usability validation is outside the task boundary.

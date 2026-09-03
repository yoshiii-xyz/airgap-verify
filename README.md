# airgap-verify

Offline artifact and provenance verifier.

Status: released v0.1.0.

## Install

From crates.io:

~~~
cargo install airgap-verify --locked
~~~

From a checkout:

~~~
cargo install --path . --locked
~~~

## Quick start

The evidence directory must contain the two direct files shown below:

~~~
airgap-verify verify artifact.tar.gz evidence/
airgap-verify inspect evidence/
airgap-verify version
~~~

~~~
evidence/
|-- bundle.sigstore.json
+-- trusted-root.json
~~~

## What it solves

airgap-verify checks one local release artifact against a complete local
Sigstore evidence bundle. The v0.1.0 MVP supports one regular .tar.gz file,
one Sigstore Bundle v0.3 detached MessageSignature, and one serialized
trusted root.

The verifier reports the SHA-256 digest, signature, certificate chain, signed
time, transparency inclusion, trust root file, network access state, and each
missing or unverifiable claim. It returns a failure verdict when any required
claim is incomplete.

## How it works

The artifact is read as a stream and hashed with SHA-256. Evidence entries are
bounded, sorted, hashed, and rejected when they are symlinks, directories,
oversized, or outside the direct evidence directory. JSON objects are checked
for duplicate keys before the Sigstore parser receives them.

The bundle is restricted to the documented v0.3 detached message-signature
shape. The local trusted root is passed to sigstore-verify with all network
update features disabled. No remote root, log, timestamp, identity, or
inclusion lookup is attempted.

## Commands and output

verify and inspect print deterministic, pretty JSON. The verify report has
schema version airgap-verify/v1 and uses pass only after the artifact digest,
detached signature, certificate chain and SCT, signed time, and transparency
inclusion evidence all verify. inspect checks the evidence shape but does not
perform cryptographic verification.

Exit code 0 means the requested report has a pass verdict. Exit code 1 means
the report has a fail verdict. Command-line parsing errors use clap's normal
error behavior.

## Safety, privacy, and data handling

The program reads the named artifact and direct evidence files. It does not
write to them, send telemetry, contact a service, or update a trust root.
Reports contain only the artifact basename, byte count, digest, evidence
basenames, and verification details. The trusted root contents and artifact
contents are not printed.

## Limits and non-goals

See docs/limits.md. The MVP does not parse archive members, support DSSE,
support public-key bundles, fetch trust roots, access hosted services, or
promise support for every artifact and evidence format. Human usability and
physical-device validation are outside this release.

## Testing and development

The local validation commands and release evidence are documented in
docs/release.md. Contribution rules are in CONTRIBUTING.md.

## Release and support status

The v0.1.0 release is a narrow Linux-first MVP. Its pass verdict means the
required local claims verified under the supplied root. It does not mean that
the artifact is safe for a particular deployment or that an untrusted trusted
root has been approved.

## Contributing

See CONTRIBUTING.md.

## License

See LICENSE.

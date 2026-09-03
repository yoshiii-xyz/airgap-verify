# Research

## Format decision

The MVP uses the Sigstore Bundle v0.3 detached message-signature shape. This
is a narrow choice because the bundle already carries the signature,
certificate, transparency-log entry, inclusion proof, signed entry timestamp,
and the artifact digest needed by this verifier. It lets the first release
exercise the complete local trust decision without adding archive parsing,
DSSE statement policy, or remote service discovery.

The official Sigstore documentation describes bundle verification material,
inclusion evidence, signed timestamps, and offline verification:

- Sigstore bundle format: https://docs.sigstore.dev/about/bundle/
- Sigstore verification: https://docs.sigstore.dev/cosign/verifying/verify/
- Sigstore bundle protobuf schema: https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto

The Rust implementation is built on the local parsing and verification APIs
from these crates:

- sigstore-verify 0.11.0: https://docs.rs/sigstore-verify/0.11.0/sigstore_verify/
- sigstore-trust-root 0.11.0: https://docs.rs/sigstore-trust-root/0.11.0/sigstore_trust_root/
- sigstore-types 0.11.0: https://docs.rs/sigstore-types/0.11.0/sigstore_types/

## Product decisions

The bundle must include inclusion and signed-time evidence. The verifier
does not call a result a pass when either claim is absent. A local serialized
trusted root is mandatory, so the program can state exactly which trust-root
file was used and can make its no-network behavior testable.

Duplicate object keys are rejected before deserialization because accepting
last-value-wins JSON would make the signed claim representation ambiguous.
Evidence entries are bounded and symlinks are rejected because this tool is
intended for disconnected staging directories, not an unrestricted filesystem
scanner.

## Validation boundary

The positive fixture is a real Sigstore v0.3 bundle produced for a small
detached artifact. The negative tests mutate only local fixture copies. A
Linux seccomp filter kills the verifier if it attempts selected network
syscalls. No test claims access to a remote log, a remote root repository, a
physical device, or a human operator.

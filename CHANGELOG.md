# Changelog

## 0.1.0

Initial release.

- Verify a regular .tar.gz file with a Sigstore Bundle v0.3 detached
  SHA-256 MessageSignature.
- Require a local serialized trusted root, one Rekor inclusion proof, and one
  signed entry timestamp.
- Reject duplicate JSON keys, symlink evidence entries, path-shaped names,
  oversized evidence, and incomplete claims.
- Provide deterministic JSON for verification and evidence inspection.

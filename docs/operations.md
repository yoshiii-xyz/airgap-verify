# Operations

## Prepare evidence

Place exactly the named bundle and trusted root files directly in an evidence
directory:

~~~
mkdir evidence
cp bundle.sigstore.json evidence/bundle.sigstore.json
cp trusted-root.json evidence/trusted-root.json
~~~

The verifier does not create, refresh, or infer either file.

## Verify

~~~
airgap-verify verify artifact.tar.gz evidence/
~~~

The command prints JSON to stdout. Inspect verdict and
missingOrUnverifiableClaims, not only the process exit code. A pass requires
all four claim statuses to be verified.

## Inspect

~~~
airgap-verify inspect evidence/
~~~

Inspect lists direct evidence file names, sizes, and SHA-256 values, then
reports whether the supported bundle and trusted root structures are
parseable. It does not verify a signature or make an artifact pass claim.

## Failure handling

Missing files, malformed JSON, duplicate keys, incomplete transparency
material, wrong artifact digests, invalid roots, expired signed times, and
cryptographic failures return a fail JSON report and exit code 1. The report
keeps each missing or unverifiable claim visible.

## Privacy

Use an evidence directory with least-privilege access. Reports include
basenames, sizes, and SHA-256 values but do not print artifact contents,
certificate bytes, or trusted root contents. Keep private evidence and QA
records out of version control.

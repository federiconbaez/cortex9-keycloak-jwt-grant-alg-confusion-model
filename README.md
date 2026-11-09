# cortex9-keycloak-jwt-grant-alg-confusion-model

Offline differential model of **CVE-2026-11800** (GHSA-j97h-3f8r-mrjr):
Keycloak JWT validators backed by an IdP public key accepted symmetric
(HMAC) `alg` values, enabling RS256→HS256 algorithm confusion. Fixed in
26.6.4. Educational, offline, deterministic.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## Mechanism

Before the fix, Keycloak accepted HMAC signatures that used the IdP's
configured **public** key as the secret. With a hardcoded public key,
`HardcodedPublicKeyLoader` handled `HS*` algorithms by loading
`KeyUtils.loadSecretKey(Base64Url.decode(encodedKey))` (removed diff line
206). The configured value is normally `PemUtils.encodeKey(publicKey)`, i.e.
base64 of the DER SubjectPublicKeyInfo without PEM headers, so the HMAC
secret was exactly the DER bytes of a key that is public by design. Anyone
who knows the public key can sign an `HS256` assertion that verifies. The
validator did not stop it: before the fix it only checked for a null `alg`
or a mismatch with an explicitly expected algorithm.

The fix (diff lines 64-96) makes `validateSignatureAlgorithm` reject
`none` (case-insensitive) and, unless `isSymmetricAlgorithmAllowed()`,
require an asymmetric `ClientSignatureVerifierProvider` for the header
`alg`. It also removes the HMAC branch from the loader. Only
`JWTClientSecretValidator` (shared client secret) keeps symmetric
algorithms.

## Two semantics, always side by side

| Case | pre (`32cdceb8`) | post (`6d61885f` / `8970032a`) |
|---|---|---|
| `p01` HS256, HMAC over the DER | `ACCEPT` | `REJECT` |
| `p02` HS512, HMAC over the DER | `ACCEPT` | `REJECT` |
| `n06` HS256 keyed with the PEM text | `BAD_SIGNATURE` | `REJECT` |
| `n01` RS256 | `PROCEEDS_TO_SIGNATURE_CHECK` | same |
| `d01` `alg=none` (defense in depth) | `VALIDATOR_PASS_DOWNSTREAM_UNMODELED` | `REJECT` |

The positives are HS256/HS512 only. HS256 is backed by the upstream tests
`testHS256AlgorithmConfusion*` in the fix diff (lines 253, 263-277, 279,
321, 351, 399, 408-421, 424); they sign with
`getPublicKey().getEncoded()` (DER) and expect "Invalid signature
algorithm". HS512 follows from the validator change (lines 85-89); no
upstream test targets it specifically.

`alg=none` is not a positive: before the fix the validator lets it through,
but whether the rest of the grant path rejects it is not modelled. It stays
as a defense-in-depth case. 22 cases: 2 positive, 7 negative, 1 defense in
depth and 12 adversarial.

## Run

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.

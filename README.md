# cortex9-keycloak-jwt-grant-alg-confusion-model

Offline differential model of **CVE-2026-11800** (GHSA-j97h-3f8r-mrjr):
Keycloak's JWT Authorization Grant path with a hardcoded public key
accepted symmetric `alg` values (and `none`), enabling algorithm confusion.
Educational, offline, deterministic.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## Two semantics, always side by side

| | pre (`32cdceb8`) | post (`6d61885f`) |
|---|---|---|
| Hardcoded pubkey IdP + HS256 | loader → OCT secret; validator accepts | validator requires asymmetric; loader drops HMAC |
| Diff | AbstractBaseJWTValidator + HardcodedPublicKeyLoader | diff lines 64–96 and 150–214 |

## Run

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.

# Limitations

- **Validator + hardcoded-key loader only.** JWKS-URL IdPs, the full
  ClientSignatureVerifierProvider wiring and token exchange are not
  modelled. Asymmetric signatures are not verified: those paths end in
  `PROCEEDS_TO_SIGNATURE_CHECK`.
- **`alg=none` before the fix.** The validator passes it; what the rest
  of the grant path does is not modelled, so it is labelled
  `VALIDATOR_PASS_DOWNSTREAM_UNMODELED`, not `ACCEPT`.
- **PEM vs base64 without headers.** The pre HMAC secret is
  `Base64Url.decode(configured value)`. `Base64Url.decode` maps `+`/`/` to
  `-`/`_`, drops everything from the first `=`, and then uses Java's strict
  `Base64.getUrlDecoder()`. So:
  - a value in the `PemUtils.encodeKey` form (base64 DER, no headers, no
    line breaks) decodes to the **DER SPKI bytes**; that is the secret
    (`p01`, `p02`);
  - a full PEM (`-----BEGIN PUBLIC KEY-----`, spaces, newlines) contains
    characters outside the alphabet and the decoder throws
    (`n07`, `LOADER_EXCEPTION`); no HMAC key is built;
  - an HMAC keyed with the PEM text never matches the DER secret (`n06`).
  Whether the admin console or API normalises a pasted PEM before storing
  it is not modelled.
- **Provider lookup is assumed case-sensitive** (`hs256` finds no
  provider). `JavaAlgorithm.getJavaAlgorithm` is a case-sensitive switch
  that throws on unknown names (verified at `32cdceb8`). Whether JOSE
  header parsing ever yields `None`/`NONE`/`hs256` is not modelled.
- **Odd Python types** (int, list, dict, bytes) are labelled
  `UNREPRESENTABLE_*`: a header `alg` or a configured key is a Java String.
- **JWTClientSecretValidator** still allows symmetric algorithms; covered
  by one unit test, not by the fixtures.
- The RSA key is a local lab key; the private half is not in this repo.
- This is not a finding. Nothing is attributed beyond SOURCES.md and the CVE.

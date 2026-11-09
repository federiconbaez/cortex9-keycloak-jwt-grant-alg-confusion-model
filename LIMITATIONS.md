# Limitations

- **Validator + loader only.** Full ClientSignatureVerifierProvider wiring,
  JWKS-URL IdPs and token exchange are not modelled.
- **HMAC demonstration** uses the PEM bytes as the secret to show the
  confusion primitive; Keycloak's pre loader actually Base64Url-decodes the
  encoded key for OCT — the exact byte derivation may differ. The gate
  change (reject HS* on the pubkey path) is what the tests assert.
- **JWTClientSecretValidator** still allows symmetric algorithms; covered
  by one adversarial test, not the grant-path fixtures.
- This is not a finding. Nothing is attributed beyond SOURCES.md and the CVE.

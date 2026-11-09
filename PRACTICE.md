# Guía práctica (10 niveles)

Todo es offline; el HMAC se calcula en local con una clave de laboratorio.

1. ¿Qué es la confusión de algoritmo JWT (RS256 vs HS256)?
2. `p01_hs256_der_secret`: HS256 → `ACCEPT` pre, `REJECT` post. Localiza en
   el diff `testHS256AlgorithmConfusionWithHardcodedPublicKey` (líneas
   263-277 y 408-421): ¿con qué bytes firma? (`getPublicKey().getEncoded()`).
3. El secreto real del pre: `Base64Url.decode(valor configurado)` (línea
   206). Con `PemUtils.encodeKey(pub)` (base64 sin cabeceras) eso es el DER
   SPKI. Compruébalo con `loader_pre("HS256", CONFIGURED_KEY)`.
4. `n06_hs256_pem_text_secret`: firma HMAC con el texto PEM. ¿Por qué da
   `BAD_SIGNATURE` en pre?
5. `n07_hs256_pem_configured`: si se configura el PEM completo, ¿qué hace
   el decoder estricto de Java?
6. Localiza `isSymmetricAlgorithmAllowed` y el check de proveedor
   asimétrico (líneas 68 y 85-89).
7. `d01_alg_none`: ¿por qué no es un positivo? ¿Qué significa
   `VALIDATOR_PASS_DOWNSTREAM_UNMODELED`?
8. `a01`/`a02`: `None` y `NONE` frente a `equalsIgnoreCase` (línea 81).
9. `n01_rs256`: ¿por qué la etiqueta es `PROCEEDS_TO_SIGNATURE_CHECK`?
10. Diferencia el path client-secret (simétricos permitidos) del de clave
    pública.

Más allá: regenera `fixtures/expected.tsv` con
`scripts/derive_expected.py` y comprueba el oráculo.

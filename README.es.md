# cortex9-keycloak-jwt-grant-alg-confusion-model

Modelo diferencial offline de **CVE-2026-11800** (GHSA-j97h-3f8r-mrjr):
los validadores JWT de Keycloak respaldados por la clave pública de un IdP
aceptaban `alg` simétricos (HMAC), permitiendo confusión de algoritmo
RS256→HS256. Corregido en 26.6.4. Educativo, offline y determinista.

English: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Mecanismo

Antes del fix, Keycloak aceptaba firmas HMAC que usaban como secreto la
clave **pública** configurada del IdP. Con clave pública hardcodeada,
`HardcodedPublicKeyLoader` trataba los `HS*` cargando
`KeyUtils.loadSecretKey(Base64Url.decode(encodedKey))` (línea 206 del
diff, eliminada). El valor configurado suele ser
`PemUtils.encodeKey(publicKey)`: base64 del DER SubjectPublicKeyInfo sin
cabeceras PEM. Por tanto el secreto HMAC eran exactamente los bytes DER de
una clave pública por diseño, y cualquiera que la conozca puede firmar una
aserción `HS256` válida. El validador no lo frenaba: antes del fix solo
comprobaba `alg` nulo o distinto del algoritmo esperado explícito.

El fix (líneas 64-96) rechaza `none` (sin distinguir mayúsculas) y, salvo
`isSymmetricAlgorithmAllowed()`, exige un `ClientSignatureVerifierProvider`
asimétrico para el `alg` del header. Además elimina la rama HMAC del
loader. Solo `JWTClientSecretValidator` (secreto compartido) conserva los
simétricos.

## Casos

- Positivos solo HS256/HS512 (`p01`, `p02`): `ACCEPT` pre, `REJECT` post.
  HS256 lo respaldan los tests `testHS256AlgorithmConfusion*` del diff
  (líneas 253, 263-277, 279, 321, 351, 399, 408-421, 424). HS512 se deriva
  del cambio del validador (líneas 85-89); no hay test específico.
- `d01` `alg=none`: defensa en profundidad. Pre
  `VALIDATOR_PASS_DOWNSTREAM_UNMODELED` (el validador lo deja pasar; el
  resto del flujo no se modela), post `REJECT`.
- 22 casos: 2 positivos, 7 negativos, 1 de defensa en profundidad y 12
  adversariales.

## Cómo ejecutarlo

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

Ver [LIMITATIONS.md](LIMITATIONS.md) y [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.

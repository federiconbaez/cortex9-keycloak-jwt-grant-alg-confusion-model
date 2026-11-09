# Guía práctica (8 niveles)

1. ¿Qué es la confusión de algoritmo JWT (RS256 vs HS256)?
2. `p01`: HS256 en IdP de clave pública → ACCEPT pre, REJECT post.
3. Localiza en el diff `isSymmetricAlgorithmAllowed`.
4. ¿Qué rama elimina HardcodedPublicKeyLoader?
5. `n01`: RS256 sigue ACCEPT en ambos.
6. `test_forge_roundtrip`: HMAC con la PEM pública (solo laboratorio local).
7. `n05`: expected=RS256 rechaza HS256 también en pre.
8. Diferencia el path client-secret (symmetric allowed) del grant path.

Más allá: regenera expected.tsv y comprueba el oráculo.

# cortex9-keycloak-jwt-grant-alg-confusion-model

Modelo diferencial offline de **CVE-2026-11800**: el JWT Authorization
Grant de Keycloak con clave pública hardcodeada aceptaba `alg` simétricos
(y `none`), permitiendo confusión de algoritmo. Educativo, offline y
determinista.

English: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Cómo ejecutarlo

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

Ver [LIMITATIONS.md](LIMITATIONS.md) y [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.

# Sources

Local copies under `security-research-45/sources/cve2026/`. Advisory:
GHSA-j97h-3f8r-mrjr. CVE: CVE-2026-11800 (NVD Analyzed; not deprecated).
Affected `keycloak-services` < 26.6.4; fixed in release **26.6.4**.

## Commits

| Commit | Where | Role |
|---|---|---|
| `8970032a8617062da31f63a36c64c1b0b2ca9b7c` | **main** (merge of PR #50374, "Closes #50357") | fix on main |
| `d343c7373dcc7bfeb9dc14de2309836299c81837` | head of PR #50374, **not on main** | PR head only; its diff equals 8970032a's |
| `6d61885f20ac59a2ff8b823fc9ed1f1ef1019951` | 26.6 branch (#740), "Closes CVE-2026-11800"; contained in tag 26.6.4 | backport; diff line numbers in this repo refer to it |

Pre sources are taken at `32cdceb80aeb43dc082bb032a87daa5105ea1fbd`, the
parent of 6d61885f.

## Files

| Source | Used for | SHA-256 of copy |
|---|---|---|
| NVD / GHSA JSON | ID + affected/fixed versions | see SHA256SUMS |
| `6d61885f` diff | the fix; cited line numbers | `24536433440e5adad13bb5329ac883497acddadb57bd96a66ede5fac2bc2c8a1` |
| `8970032a` diff (identical to `d343c737` diff) | the fix on main | `561edf9e75510de9f570b4418d0a09a8b6582d1a1c76ab787eeb649ce0ec3ff9` |
| `AbstractBaseJWTValidator.java` at `32cdceb8` | pre validator | `50202fc314351a92740638e8ded7c0af7c335afacb4e49e79d64f6ec9347f8b4` |
| `AbstractBaseJWTValidator.java` at `6d61885f` | post validator | `511ecbd4895ca36dc17552c74af08cd1f9eca3bd1b37c2419af2f5bb3be5970c` |
| `HardcodedPublicKeyLoader.java` at `32cdceb8` | pre loader (HMAC branch) | `c16da23ef87a1fd107262097b83ca6dc2e0ea6fd53e4a1b497e4f4f72e36cfed` |
| `Base64Url.java` at `32cdceb8` | `decode` = strict URL decoder | `32030fe3a3dfac2d1b3122452cfb0cb0540b9105060f52a1259bbddbd53dde32` |
| `PemUtils.java` at `32cdceb8` | `encodeKey` delegates to provider | `4b224a81db44731fe7eb18d3bb66d59b65a4211bc2774646e59581ab50b2ca8d` |
| `PemUtilsProvider.java` at `32cdceb8` | `removeBeginEnd` | `fc6cf00afa23c37173775906007960bb55258dfa912d25929c49eab9fff7311e` |
| `BCPemUtilsProvider.java` at `32cdceb8` | `encode` = PEM writer + `removeBeginEnd` | `62761f26871e87010cc50929c3ca61769c0502f2969cb75966ab2a4eef65f6ae` |
| `JavaAlgorithm.java` at `32cdceb8` | case-sensitive `getJavaAlgorithm` | `f1a94dfe3946508fefdbaa4617a4e2aa42bdcbff56d3f8545a4f53a22ad30754` |

No source contained instructions addressed to a tool or agent.

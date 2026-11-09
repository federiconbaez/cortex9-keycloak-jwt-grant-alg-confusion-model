# Sources

Local copies under `security-research-45/sources/cve2026/`. Advisory:
GHSA-j97h-3f8r-mrjr. CVE: CVE-2026-11800 (NVD Analyzed; not deprecated).

| Source | Used for | SHA-256 of copy |
|---|---|---|
| NVD / GHSA JSON | ID + keycloak-services < 26.6.4 → 26.6.4 | see SHA256SUMS |
| commit `6d61885f20ac59a2ff8b823fc9ed1f1ef1019951` diff | the fix | `24536433440e5adad13bb5329ac883497acddadb57bd96a66ede5fac2bc2c8a1` |
| `AbstractBaseJWTValidator.java` at parent `32cdceb8` | pre validator | `50202fc314351a92740638e8ded7c0af7c335afacb4e49e79d64f6ec9347f8b4` |
| `AbstractBaseJWTValidator.java` at `6d61885f` | post validator | `511ecbd4895ca36dc17552c74af08cd1f9eca3bd1b37c2419af2f5bb3be5970c` |
| `HardcodedPublicKeyLoader.java` at parent | pre loader (HMAC branch) | `c16da23ef87a1fd107262097b83ca6dc2e0ea6fd53e4a1b497e4f4f72e36cfed` |

No source contained instructions addressed to a tool or agent.

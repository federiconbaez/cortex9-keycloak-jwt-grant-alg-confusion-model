"""Offline model of Keycloak JWT Authorization Grant alg confusion (CVE-2026-11800).

Line numbers refer to diffs/CVE-2026-11800_keycloak_6d61885f20ac.diff
(26.6 backport, "Closes CVE-2026-11800"). The main-branch commit 8970032a
(merge of PR #50374, head d343c737) carries the same change.

1. AbstractBaseJWTValidator.validateSignatureAlgorithm (diff lines 64-96)
   - pre: only a null alg or an expected-alg mismatch fails
   - post: "none".equalsIgnoreCase(alg) fails (line 81); unless
     isSymmetricAlgorithmAllowed(), the ClientSignatureVerifierProvider for
     the alg must exist and be asymmetric (lines 85-89)

2. HardcodedPublicKeyLoader (diff lines 150-214)
   - pre: HMAC algs load KeyUtils.loadSecretKey(Base64Url.decode(encodedKey))
     (removed line 206): the HMAC secret is the base64url-decode of the
     configured value. When the IdP is configured with
     PemUtils.encodeKey(publicKey) (base64 DER, no headers, as the tests at
     diff lines 263-277 and 408-421 do), that secret is the DER
     SubjectPublicKeyInfo of the IdP public key.
   - post: unrecognized/non-asymmetric algs give kw = null

Asymmetric signature cryptography is NOT modelled; HMAC is computed locally.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass

ASYMMETRIC = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA",
              "PS256", "PS384", "PS512"}
HMAC_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
# Providers registered by exact name (assumption: lookup is case-sensitive).
PROVIDERS = {**{a: "asymmetric" for a in ASYMMETRIC}, **{a: "symmetric" for a in HMAC_HASH}}
# JavaAlgorithm.getJavaAlgorithm: case-sensitive switch, default throws.
JAVA_KNOWN = ASYMMETRIC | set(HMAC_HASH)

# Local RSA-2048 public key (offline only; private half never committed).
PUBLIC_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzRzXtwNScOgQvvLZOlrV\n"
    "oIudReXfKIa1KhrkdekaREKP9GhSivGtH0yjbB4q/SA1ZRLR/X0mVLTfAXbQNyxA\n"
    "LBe/3QNxfrOp0Kpn5yTz6XclMbyrA4HBPGXdHH6zYPUu+1RtxkvwiprV3792apaj\n"
    "9EU2MhJ9k2ZbJMfQscuES6uFP8nlEyV2YSF3eIQ0cl6uE6Gjhqt8BG20amNUoy8i\n"
    "8Ls5ez8wVQJE5SCLBJiNBShlkGStuADlfXFLmHwmd3GXioSG/18a5YcxRcel8lmj\n"
    "HxkeQHCayOYk6x1pXRSmkZYYlt56dwDy5OTzlYyzhfZHx/XbQp+7t4zPTdcmrn5u\n"
    "VQIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
)
# PemUtils.encodeKey(pub): JcaPEMWriter output passed through removeBeginEnd
# (strips BEGIN/END lines and newlines, then trim) -> base64 DER, one line.
CONFIGURED_KEY = "".join(PUBLIC_PEM.strip().splitlines()[1:-1])
PUBLIC_DER = base64.b64decode(CONFIGURED_KEY)

SIGNING_INPUT = b"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsYWItdXNlciJ9"

_URL_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class LoaderError(Exception):
    pass


def base64url_decode_keycloak(s: str) -> bytes:
    """Base64Url.decode at 32cdceb8: encodeBase64ToBase64Url then
    java.util.Base64.getUrlDecoder() (strict alphabet, padding optional)."""
    s = s.split("=")[0].replace("+", "-").replace("/", "_")
    if any(ch not in _URL_ALPHABET for ch in s) or len(s) % 4 == 1:
        raise LoaderError("IllegalArgumentException: illegal base64url input")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def loader_pre(algorithm: str, encoded_key):
    """HardcodedPublicKeyLoader constructor before the fix.
    Returns ("NO_KEY", None) | ("ASYMMETRIC_KEY", None) | ("OCT_SECRET", bytes)."""
    if encoded_key is None or str(encoded_key).strip() == "":
        return "NO_KEY", None
    if algorithm not in JAVA_KNOWN:
        raise LoaderError("IllegalArgumentException: Unknown algorithm")
    if algorithm in ASYMMETRIC:
        return "ASYMMETRIC_KEY", None
    return "OCT_SECRET", base64url_decode_keycloak(encoded_key)


def loader_post(algorithm: str, encoded_key):
    if encoded_key is None or str(encoded_key).strip() == "":
        return "NO_KEY", None
    if algorithm in ASYMMETRIC:
        return "ASYMMETRIC_KEY", None
    return "NO_KEY", None  # warn + kw = null (HMAC branch removed)


def validate_pre(algorithm, expected) -> bool:
    if algorithm is None:
        return False
    if expected is not None and expected != algorithm:
        return False
    return True


def validate_post(algorithm, expected, *, symmetric_allowed: bool) -> bool:
    if algorithm is None:
        return False
    if algorithm.lower() == "none":  # "none".equalsIgnoreCase(algorithmName)
        return False
    if not symmetric_allowed and PROVIDERS.get(algorithm) != "asymmetric":
        return False
    if expected is not None and expected != algorithm:
        return False
    return True


def sign(spec: str, algorithm) -> bytes:
    """Signature specs used by the fixtures. Offline HMAC only."""
    if spec == "hmac_der":
        return hmac.new(PUBLIC_DER, SIGNING_INPUT, HMAC_HASH[algorithm]).digest()
    if spec == "hmac_pem_text":
        return hmac.new(PUBLIC_PEM.encode(), SIGNING_INPUT, HMAC_HASH[algorithm]).digest()
    if spec == "opaque":
        return b"\x01" * 32
    if spec == "empty":
        return b""
    raise ValueError(spec)


def grant_path(side: str, algorithm, expected, encoded_key, signature: bytes) -> str:
    if algorithm is not None and not isinstance(algorithm, str):
        return "UNREPRESENTABLE_ALG"  # a JOSE header alg is a String in Java
    if encoded_key is not None and not isinstance(encoded_key, str):
        return "UNREPRESENTABLE_KEY"
    if side == "pre":
        if not validate_pre(algorithm, expected):
            return "REJECT"
        if algorithm.lower() == "none":
            return "VALIDATOR_PASS_DOWNSTREAM_UNMODELED"
        try:
            kind, secret = loader_pre(algorithm, encoded_key)
        except LoaderError:
            return "LOADER_EXCEPTION"
    else:
        if not validate_post(algorithm, expected, symmetric_allowed=False):
            return "REJECT"
        kind, secret = loader_post(algorithm, encoded_key)
    if kind == "NO_KEY":
        return "NO_KEY_LOADED"
    if kind == "ASYMMETRIC_KEY":
        return "PROCEEDS_TO_SIGNATURE_CHECK"
    good = hmac.new(secret, SIGNING_INPUT, HMAC_HASH[algorithm]).digest()
    return "ACCEPT" if hmac.compare_digest(good, signature) else "BAD_SIGNATURE"


@dataclass(frozen=True)
class Case:
    id: str
    kind: str  # pos | neg | did (defense in depth) | adv
    description: str
    algorithm: object
    expected: object
    encoded_key: object
    sig: str
    pre: str
    post: str


K = CONFIGURED_KEY
CASES = [
    Case("p01_hs256_der_secret", "pos",
         "HS256 signed with DER of IdP pubkey (diff tests L263-277, L408-421)",
         "HS256", None, K, "hmac_der", "ACCEPT", "REJECT"),
    Case("p02_hs512_der_secret", "pos",
         "HS512, same secret (validator diff L85-89; no dedicated HS512 test)",
         "HS512", None, K, "hmac_der", "ACCEPT", "REJECT"),
    Case("n01_rs256", "neg", "legitimate RS256 assertion",
         "RS256", "RS256", K, "opaque", "PROCEEDS_TO_SIGNATURE_CHECK", "PROCEEDS_TO_SIGNATURE_CHECK"),
    Case("n02_es256", "neg", "ES256 asymmetric",
         "ES256", None, K, "opaque", "PROCEEDS_TO_SIGNATURE_CHECK", "PROCEEDS_TO_SIGNATURE_CHECK"),
    Case("n03_expected_mismatch", "neg", "expected RS256, token ES256",
         "ES256", "RS256", K, "opaque", "REJECT", "REJECT"),
    Case("n04_null_alg", "neg", "missing alg",
         None, None, K, "opaque", "REJECT", "REJECT"),
    Case("n05_hs256_with_expected_rs", "neg", "HS256 with expected RS256",
         "HS256", "RS256", K, "hmac_der", "REJECT", "REJECT"),
    Case("n06_hs256_pem_text_secret", "neg",
         "HS256 keyed with PEM text (wrong secret): pre BAD_SIGNATURE",
         "HS256", None, K, "hmac_pem_text", "BAD_SIGNATURE", "REJECT"),
    Case("n07_hs256_pem_configured", "neg",
         "IdP configured with full PEM (headers): Base64Url.decode throws pre",
         "HS256", None, PUBLIC_PEM, "hmac_der", "LOADER_EXCEPTION", "REJECT"),
    Case("d01_alg_none", "did",
         "alg=none: pre validator passes, rest of path unmodelled; post rejects (L81)",
         "none", None, K, "empty", "VALIDATOR_PASS_DOWNSTREAM_UNMODELED", "REJECT"),
    # --- adversarial ---
    Case("a01_alg_None", "adv", "alg='None' (equalsIgnoreCase)",
         "None", None, K, "empty", "VALIDATOR_PASS_DOWNSTREAM_UNMODELED", "REJECT"),
    Case("a02_alg_NONE", "adv", "alg='NONE'",
         "NONE", None, K, "empty", "VALIDATOR_PASS_DOWNSTREAM_UNMODELED", "REJECT"),
    Case("a03_alg_hs256_lower", "adv", "alg='hs256': getJavaAlgorithm switch is case-sensitive",
         "hs256", None, K, "opaque", "LOADER_EXCEPTION", "REJECT"),
    Case("a04_alg_int", "adv", "alg=256 (int)",
         256, None, K, "opaque", "UNREPRESENTABLE_ALG", "UNREPRESENTABLE_ALG"),
    Case("a05_alg_list_empty", "adv", "alg=[]",
         [], None, K, "opaque", "UNREPRESENTABLE_ALG", "UNREPRESENTABLE_ALG"),
    Case("a06_alg_dict", "adv", "alg={}",
         {}, None, K, "opaque", "UNREPRESENTABLE_ALG", "UNREPRESENTABLE_ALG"),
    Case("a07_alg_bytes_empty", "adv", "alg=b''",
         b"", None, K, "opaque", "UNREPRESENTABLE_ALG", "UNREPRESENTABLE_ALG"),
    Case("a08_key_none", "adv", "configured key null",
         "HS256", None, None, "hmac_der", "NO_KEY_LOADED", "REJECT"),
    Case("a09_key_blank", "adv", "configured key '   ' (trim().isEmpty())",
         "HS256", None, "   ", "hmac_der", "NO_KEY_LOADED", "REJECT"),
    Case("a10_key_int", "adv", "configured key 42",
         "HS256", None, 42, "hmac_der", "UNREPRESENTABLE_KEY", "UNREPRESENTABLE_KEY"),
    Case("a11_empty_signature", "adv", "HS256 with empty signature",
         "HS256", None, K, "empty", "BAD_SIGNATURE", "REJECT"),
    Case("a12_alg_empty_string", "adv", "alg=''",
         "", None, K, "opaque", "LOADER_EXCEPTION", "REJECT"),
]


def evaluate_case(case: Case) -> dict:
    alg_for_sig = case.algorithm if isinstance(case.algorithm, str) and case.algorithm in HMAC_HASH else "HS256"
    sig = sign(case.sig, alg_for_sig)
    pre = grant_path("pre", case.algorithm, case.expected, case.encoded_key, sig)
    post = grant_path("post", case.algorithm, case.expected, case.encoded_key, sig)
    ok = pre == case.pre and post == case.post
    flips = pre == "ACCEPT" and post == "REJECT"
    return {
        "id": case.id, "kind": case.kind, "description": case.description,
        "pre": pre, "post": post, "expected_pre": case.pre, "expected_post": case.post,
        "ok": ok, "flips": flips,
    }

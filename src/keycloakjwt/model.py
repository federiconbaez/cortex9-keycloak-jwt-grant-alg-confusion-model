"""Offline model of Keycloak JWT Authorization Grant alg confusion (CVE-2026-11800).

Ports two cooperating checks from commit 6d61885f:

1. AbstractBaseJWTValidator.validateSignatureAlgorithm (diff lines 64-96)
   - pre: only compares expected alg (if set); null alg fails
   - post: also rejects "none"; unless isSymmetricAlgorithmAllowed(), requires
     an asymmetric ClientSignatureVerifierProvider for the header alg

2. HardcodedPublicKeyLoader (diff lines 150-214)
   - pre: HMAC algorithms load the encoded key as an OCT secret
   - post: unrecognized/non-asymmetric algorithms are refused (kw = null)

The JWT Authorization Grant path with a hardcoded public key is modelled as
symmetric_allowed=False. A local HMAC-SHA256 over the PEM bytes demonstrates
why accepting HS256 on that path is dangerous; no network is used.
"""
from __future__ import annotations
import hashlib
import hmac
from dataclasses import dataclass


ASYMMETRIC = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512"}
SYMMETRIC = {"HS256", "HS384", "HS512"}


def loader_pre(algorithm: str) -> str:
    """HardcodedPublicKeyLoader before the fix."""
    if algorithm in ASYMMETRIC:
        return "ASYMMETRIC_KEY"
    if algorithm in SYMMETRIC:
        return "OCT_SECRET"  # Base64Url.decode(encodedKey) path
    return "NULL"


def loader_post(algorithm: str) -> str:
    """HardcodedPublicKeyLoader after the fix: HMAC branch removed."""
    if algorithm in ASYMMETRIC:
        return "ASYMMETRIC_KEY"
    return "NULL"  # warn + kw = null


def validate_pre(algorithm: str | None, expected: str | None) -> str:
    """validateSignatureAlgorithm before the fix."""
    if algorithm is None:
        return "REJECT"
    if expected is not None and expected != algorithm:
        return "REJECT"
    return "ACCEPT"


def validate_post(algorithm: str | None, expected: str | None, *, symmetric_allowed: bool) -> str:
    """validateSignatureAlgorithm after the fix."""
    if algorithm is None:
        return "REJECT"
    if algorithm.lower() == "none":
        return "REJECT"
    if not symmetric_allowed:
        # ClientSignatureVerifierProvider must exist and be asymmetric.
        if algorithm not in ASYMMETRIC:
            return "REJECT"
    if expected is not None and expected != algorithm:
        return "REJECT"
    return "ACCEPT"


def grant_path(side: str, algorithm: str | None, expected: str | None = None) -> str:
    """Combined hardcoded-public-key JWT Authorization Grant path.

    For alg=none there is no key load; the validator alone decides.
    For HS* the pre loader still yields an OCT secret from the hardcoded
    material, which is what makes the confusion possible.
    """
    if side == "pre":
        if validate_pre(algorithm, expected) != "ACCEPT":
            return "REJECT"
        if algorithm is not None and algorithm.lower() == "none":
            return "ACCEPT"
        loaded = loader_pre(algorithm or "")
        return "ACCEPT" if loaded != "NULL" else "REJECT"
    if validate_post(algorithm, expected, symmetric_allowed=False) != "ACCEPT":
        return "REJECT"
    if algorithm is not None and algorithm.lower() == "none":
        return "ACCEPT"  # unreachable: validate_post already rejects none
    loaded = loader_post(algorithm or "")
    return "ACCEPT" if loaded != "NULL" else "REJECT"


# Local RSA public key PEM (same as the PyJWT model; offline only).
PUBLIC_PEM = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzRzXtwNScOgQvvLZOlrV\n"
    b"oIudReXfKIa1KhrkdekaREKP9GhSivGtH0yjbB4q/SA1ZRLR/X0mVLTfAXbQNyxA\n"
    b"LBe/3QNxfrOp0Kpn5yTz6XclMbyrA4HBPGXdHH6zYPUu+1RtxkvwiprV3792apaj\n"
    b"9EU2MhJ9k2ZbJMfQscuES6uFP8nlEyV2YSF3eIQ0cl6uE6Gjhqt8BG20amNUoy8i\n"
    b"8Ls5ez8wVQJE5SCLBJiNBShlkGStuADlfXFLmHwmd3GXioSG/18a5YcxRcel8lmj\n"
    b"HxkeQHCayOYk6x1pXRSmkZYYlt56dwDy5OTzlYyzhfZHx/XbQp+7t4zPTdcmrn5u\n"
    b"VQIDAQAB\n"
    b"-----END PUBLIC KEY-----\n"
)


def forge_hs256_with_public_pem(signing_input: bytes) -> bytes:
    """Demonstrate HMAC-SHA256 using the public PEM bytes as the secret.

    This is the classic algorithm-confusion primitive. Offline only.
    """
    return hmac.new(PUBLIC_PEM, signing_input, hashlib.sha256).digest()


def verify_hs256_with_public_pem(signing_input: bytes, signature: bytes) -> bool:
    return hmac.compare_digest(forge_hs256_with_public_pem(signing_input), signature)


@dataclass(frozen=True)
class Case:
    id: str
    kind: str
    description: str
    algorithm: str | None
    expected: str | None
    pre: str
    post: str


CASES = [
    Case("p01_hs256_on_pubkey_idp", "pos",
         "JWT Authorization Grant + hardcoded pubkey IdP + alg=HS256",
         "HS256", None, "ACCEPT", "REJECT"),
    Case("p02_hs512_on_pubkey_idp", "pos",
         "same path with alg=HS512",
         "HS512", None, "ACCEPT", "REJECT"),
    Case("p03_none_alg", "pos",
         "alg=none rejected post; pre accepted if no expected alg set",
         "none", None, "ACCEPT", "REJECT"),
    Case("n01_rs256", "neg",
         "legitimate RS256 assertion on pubkey IdP",
         "RS256", "RS256", "ACCEPT", "ACCEPT"),
    Case("n02_es256", "neg",
         "ES256 asymmetric",
         "ES256", None, "ACCEPT", "ACCEPT"),
    Case("n03_expected_mismatch", "neg",
         "expected RS256 but token says ES256",
         "ES256", "RS256", "REJECT", "REJECT"),
    Case("n04_null_alg", "neg",
         "missing alg",
         None, None, "REJECT", "REJECT"),
    Case("n05_hs256_with_expected_rs", "neg",
         "HS256 when expected is RS256: rejected both sides by expected check",
         "HS256", "RS256", "REJECT", "REJECT"),
]


def evaluate_case(case: Case) -> dict:
    pre = grant_path("pre", case.algorithm, case.expected)
    post = grant_path("post", case.algorithm, case.expected)
    ok = pre == case.pre and post == case.post
    flips = case.kind == "pos" and pre == "ACCEPT" and post == "REJECT"
    return {
        "id": case.id, "kind": case.kind, "description": case.description,
        "pre": pre, "post": post, "expected_pre": case.pre, "expected_post": case.post,
        "ok": ok, "flips": flips,
    }

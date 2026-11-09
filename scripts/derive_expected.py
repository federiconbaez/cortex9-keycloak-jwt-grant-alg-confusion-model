#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv for CVE-2026-11800.

Does NOT import the package. Rebuilds the secret from the PEM with binascii
and re-implements the pre/post rules from the saved Java sources with its
own code (validator diff L64-96, loader diff L150-214, Base64Url.decode,
JavaAlgorithm.getJavaAlgorithm, PemUtilsProvider.removeBeginEnd).
"""
import binascii, hashlib, hmac, re

PEM = ("-----BEGIN PUBLIC KEY-----\n"
       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzRzXtwNScOgQvvLZOlrV\n"
       "oIudReXfKIa1KhrkdekaREKP9GhSivGtH0yjbB4q/SA1ZRLR/X0mVLTfAXbQNyxA\n"
       "LBe/3QNxfrOp0Kpn5yTz6XclMbyrA4HBPGXdHH6zYPUu+1RtxkvwiprV3792apaj\n"
       "9EU2MhJ9k2ZbJMfQscuES6uFP8nlEyV2YSF3eIQ0cl6uE6Gjhqt8BG20amNUoy8i\n"
       "8Ls5ez8wVQJE5SCLBJiNBShlkGStuADlfXFLmHwmd3GXioSG/18a5YcxRcel8lmj\n"
       "HxkeQHCayOYk6x1pXRSmkZYYlt56dwDy5OTzlYyzhfZHx/XbQp+7t4zPTdcmrn5u\n"
       "VQIDAQAB\n"
       "-----END PUBLIC KEY-----\n")
# removeBeginEnd
CFG = re.sub(r"-----END (.*)----", "", re.sub(r"-----BEGIN (.*)-----", "", PEM)).replace("\r\n", "").replace("\n", "").strip()
DER = binascii.a2b_base64(CFG)
MSG = b"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsYWItdXNlciJ9"
HS = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
ASYM = "RS256 RS384 RS512 ES256 ES384 ES512 EdDSA PS256 PS384 PS512".split()

def b64url(s):
    s = s.split("=")[0].replace("+", "-").replace("/", "_")
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s) or len(s) % 4 == 1:
        return None
    return binascii.a2b_base64((s.replace("-", "+").replace("_", "/") + "===")[: len(s) + (-len(s) % 4)])

def sig(spec, alg):
    h = HS.get(alg, "sha256")
    return {"hmac_der": lambda: hmac.new(DER, MSG, h).digest(),
            "hmac_pem_text": lambda: hmac.new(PEM.encode(), MSG, h).digest(),
            "opaque": lambda: b"\x01" * 32, "empty": lambda: b""}[spec]()

def run(side, alg, exp, key, s):
    if alg is not None and type(alg) is not str:
        return "UNREPRESENTABLE_ALG"
    if key is not None and type(key) is not str:
        return "UNREPRESENTABLE_KEY"
    if alg is None or (exp is not None and exp != alg):
        return "REJECT"
    if side == "post":
        if alg.lower() == "none" or alg not in ASYM:
            return "REJECT"
    elif alg.lower() == "none":
        return "VALIDATOR_PASS_DOWNSTREAM_UNMODELED"
    if key is None or key.strip() == "":
        return "NO_KEY_LOADED"
    if side == "pre" and alg not in ASYM and alg not in HS:
        return "LOADER_EXCEPTION"
    if alg in ASYM:
        return "PROCEEDS_TO_SIGNATURE_CHECK"
    secret = b64url(key)
    if secret is None:
        return "LOADER_EXCEPTION"
    return "ACCEPT" if hmac.compare_digest(hmac.new(secret, MSG, HS[alg]).digest(), s) else "BAD_SIGNATURE"

INPUTS = [
    ("p01_hs256_der_secret", "pos", "HS256", None, CFG, "hmac_der"),
    ("p02_hs512_der_secret", "pos", "HS512", None, CFG, "hmac_der"),
    ("n01_rs256", "neg", "RS256", "RS256", CFG, "opaque"),
    ("n02_es256", "neg", "ES256", None, CFG, "opaque"),
    ("n03_expected_mismatch", "neg", "ES256", "RS256", CFG, "opaque"),
    ("n04_null_alg", "neg", None, None, CFG, "opaque"),
    ("n05_hs256_with_expected_rs", "neg", "HS256", "RS256", CFG, "hmac_der"),
    ("n06_hs256_pem_text_secret", "neg", "HS256", None, CFG, "hmac_pem_text"),
    ("n07_hs256_pem_configured", "neg", "HS256", None, PEM, "hmac_der"),
    ("d01_alg_none", "did", "none", None, CFG, "empty"),
    ("a01_alg_None", "adv", "None", None, CFG, "empty"),
    ("a02_alg_NONE", "adv", "NONE", None, CFG, "empty"),
    ("a03_alg_hs256_lower", "adv", "hs256", None, CFG, "opaque"),
    ("a04_alg_int", "adv", 256, None, CFG, "opaque"),
    ("a05_alg_list_empty", "adv", [], None, CFG, "opaque"),
    ("a06_alg_dict", "adv", {}, None, CFG, "opaque"),
    ("a07_alg_bytes_empty", "adv", b"", None, CFG, "opaque"),
    ("a08_key_none", "adv", "HS256", None, None, "hmac_der"),
    ("a09_key_blank", "adv", "HS256", None, "   ", "hmac_der"),
    ("a10_key_int", "adv", "HS256", None, 42, "hmac_der"),
    ("a11_empty_signature", "adv", "HS256", None, CFG, "empty"),
    ("a12_alg_empty_string", "adv", "", None, CFG, "opaque"),
]

print("id\tkind\tpre\tpost")
for cid, kind, alg, exp, key, spec in INPUTS:
    s = sig(spec, alg if type(alg) is str and alg in HS else "HS256")
    print(f"{cid}\t{kind}\t{run('pre', alg, exp, key, s)}\t{run('post', alg, exp, key, s)}")

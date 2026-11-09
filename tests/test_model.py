import base64, hashlib, hmac, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from keycloakjwt.model import (
    CASES, evaluate_case, loader_pre, loader_post, validate_pre, validate_post,
    base64url_decode_keycloak, grant_path, LoaderError,
    PUBLIC_PEM, PUBLIC_DER, CONFIGURED_KEY, SIGNING_INPUT,
)


class TestDifferential(unittest.TestCase):
    def test_all_cases(self):
        for c in CASES:
            with self.subTest(c.id):
                self.assertTrue(evaluate_case(c)["ok"], evaluate_case(c))

    def test_positives_are_hmac_only_and_flip(self):
        pos = [c for c in CASES if c.kind == "pos"]
        self.assertEqual({c.algorithm for c in pos}, {"HS256", "HS512"})
        for c in pos:
            self.assertTrue(evaluate_case(c)["flips"], c.id)

    def test_none_is_never_accept(self):
        for c in CASES:
            if isinstance(c.algorithm, str) and c.algorithm.lower() == "none":
                r = evaluate_case(c)
                self.assertEqual(r["pre"], "VALIDATOR_PASS_DOWNSTREAM_UNMODELED", c.id)
                self.assertEqual(r["post"], "REJECT", c.id)
                self.assertNotEqual(c.kind, "pos")

    def test_accept_only_for_pre_hmac(self):
        for c in CASES:
            r = evaluate_case(c)
            self.assertNotEqual(r["post"], "ACCEPT", c.id)
            if r["pre"] == "ACCEPT":
                self.assertIn(c.algorithm, ("HS256", "HS512"))

    def test_independent_oracle(self):
        out = subprocess.check_output([sys.executable, str(ROOT / "scripts" / "derive_expected.py")], text=True)
        self.assertEqual(out, (ROOT / "fixtures" / "expected.tsv").read_text())
        by = {c.id: c for c in CASES}
        lines = [l for l in out.splitlines()[1:] if l]
        self.assertEqual(len(lines), len(CASES))
        for ln in lines:
            cid, kind, pre, post = ln.split("\t")
            r = evaluate_case(by[cid])
            self.assertEqual((kind, pre, post), (r["kind"], r["pre"], r["post"]))


class TestSecretDerivation(unittest.TestCase):
    def test_configured_value_is_base64_der_without_headers(self):
        self.assertNotIn("-----", CONFIGURED_KEY)
        self.assertNotIn("\n", CONFIGURED_KEY)
        self.assertEqual(PUBLIC_DER[:4], bytes.fromhex("30820122"))  # SPKI SEQUENCE
        self.assertEqual(len(PUBLIC_DER), 294)

    def test_pre_secret_is_der(self):
        kind, secret = loader_pre("HS256", CONFIGURED_KEY)
        self.assertEqual(kind, "OCT_SECRET")
        self.assertEqual(secret, PUBLIC_DER)
        self.assertNotEqual(secret, PUBLIC_PEM.encode())

    def test_demo_hmac_with_der_verifies_pre(self):
        sig = hmac.new(PUBLIC_DER, SIGNING_INPUT, hashlib.sha256).digest()
        self.assertEqual(grant_path("pre", "HS256", None, CONFIGURED_KEY, sig), "ACCEPT")
        flipped = sig[:-1] + bytes([sig[-1] ^ 1])
        self.assertEqual(grant_path("pre", "HS256", None, CONFIGURED_KEY, flipped), "BAD_SIGNATURE")
        self.assertEqual(grant_path("post", "HS256", None, CONFIGURED_KEY, sig), "REJECT")

    def test_pem_with_headers_breaks_strict_decoder(self):
        with self.assertRaises(LoaderError):
            base64url_decode_keycloak(PUBLIC_PEM)

    def test_base64_url_and_std_alphabets_agree(self):
        std = base64.b64encode(PUBLIC_DER).decode()
        url = base64.urlsafe_b64encode(PUBLIC_DER).decode().rstrip("=")
        self.assertEqual(base64url_decode_keycloak(std), PUBLIC_DER)
        self.assertEqual(base64url_decode_keycloak(url), PUBLIC_DER)


class TestAdversarial(unittest.TestCase):
    def test_mixed_case_none_post(self):
        for alg in ("none", "None", "NONE", "nOnE"):
            with self.subTest(alg):
                self.assertTrue(validate_pre(alg, None))
                self.assertFalse(validate_post(alg, None, symmetric_allowed=True))

    def test_lowercase_hs256(self):
        self.assertFalse(validate_post("hs256", None, symmetric_allowed=False))
        with self.assertRaises(LoaderError):
            loader_pre("hs256", CONFIGURED_KEY)

    def test_odd_types_never_accept(self):
        for alg in (256, [], {}, b"", ["HS256"]):
            for side in ("pre", "post"):
                with self.subTest(alg=alg, side=side):
                    self.assertEqual(grant_path(side, alg, None, CONFIGURED_KEY, b""), "UNREPRESENTABLE_ALG")
        for key in (42, [], {}, b""):
            with self.subTest(key=key):
                self.assertEqual(grant_path("pre", "HS256", None, key, b""), "UNREPRESENTABLE_KEY")

    def test_blank_keys(self):
        for key in (None, "", "   "):
            self.assertEqual(loader_pre("HS256", key)[0], "NO_KEY")
            self.assertEqual(loader_post("RS256", key)[0], "NO_KEY")

    def test_loader_hmac_removed(self):
        self.assertEqual(loader_post("HS256", CONFIGURED_KEY)[0], "NO_KEY")
        self.assertEqual(loader_post("RS256", CONFIGURED_KEY)[0], "ASYMMETRIC_KEY")

    def test_client_secret_path_still_allows_symmetric(self):
        # JWTClientSecretValidator overrides isSymmetricAlgorithmAllowed() -> true.
        self.assertTrue(validate_post("HS256", None, symmetric_allowed=True))


class TestResults(unittest.TestCase):
    def test_regen(self):
        from keycloakjwt.cli import _write_results
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(Path(tmp))
            for name in ("cases.csv", "summary.csv", "SHA256SUMS"):
                self.assertEqual((ROOT / "results" / name).read_bytes(), (Path(tmp) / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()

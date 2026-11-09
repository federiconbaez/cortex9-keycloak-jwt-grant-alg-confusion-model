import subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"src"))
from keycloakjwt.model import (
    CASES, evaluate_case, forge_hs256_with_public_pem, verify_hs256_with_public_pem,
    loader_pre, loader_post, validate_post, PUBLIC_PEM,
)

class T(unittest.TestCase):
    def test_all(self):
        for c in CASES:
            with self.subTest(c.id):
                self.assertTrue(evaluate_case(c)["ok"], evaluate_case(c))
    def test_pos_flip(self):
        flips = [evaluate_case(c) for c in CASES if c.kind=="pos"]
        self.assertEqual(len(flips), 3)
        for r in flips: self.assertTrue(r["flips"], r)
    def test_oracle(self):
        out = subprocess.check_output([sys.executable, str(ROOT/"scripts"/"derive_expected.py")], text=True)
        by = {c.id:c for c in CASES}
        for ln in out.splitlines():
            if not ln or ln.startswith("id"): continue
            cid, kind, pre, post = ln.split("\t")
            c = by[cid]
            self.assertEqual((pre, post), (c.pre, c.post))
    def test_forge_roundtrip(self):
        msg = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0ifQ"
        sig = forge_hs256_with_public_pem(msg)
        self.assertTrue(verify_hs256_with_public_pem(msg, sig))
        self.assertFalse(verify_hs256_with_public_pem(msg, sig[:-1]+bytes([sig[-1]^1])))
    def test_loader_hmac_removed(self):
        self.assertEqual(loader_pre("HS256"), "OCT_SECRET")
        self.assertEqual(loader_post("HS256"), "NULL")
        self.assertEqual(loader_post("RS256"), "ASYMMETRIC_KEY")
    def test_client_secret_path_still_allows_symmetric(self):
        # JWTClientSecretValidator sets isSymmetricAlgorithmAllowed=True.
        self.assertEqual(validate_post("HS256", None, symmetric_allowed=True), "ACCEPT")
    def test_regen(self):
        from keycloakjwt.cli import _write_results
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(Path(tmp))
            for name in ("cases.csv","summary.csv","SHA256SUMS"):
                self.assertEqual((ROOT/"results"/name).read_bytes(), (Path(tmp)/name).read_bytes())
if __name__ == "__main__":
    unittest.main()

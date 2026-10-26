"""Basic local security checks for the CloudShield Flask demo."""
import unittest
from app import app, derive_key, sha256

class SecurityTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_dashboard_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_health_endpoint_does_not_expose_secrets(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"secret", response.data.lower())

    def test_key_derivation_is_32_bytes_and_salted(self):
        self.assertEqual(len(derive_key("passphrase-123", b"a" * 16)), 32)
        self.assertNotEqual(derive_key("passphrase-123", b"a" * 16), derive_key("passphrase-123", b"b" * 16))

    def test_sha256_known_value(self):
        self.assertEqual(sha256(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

if __name__ == "__main__":
    unittest.main(verbosity=2)

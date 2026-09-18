"""
Tests for TargetValidator and SSRF protection.
"""

import unittest
from services.target_validator import TargetValidator

class TestTargetValidator(unittest.TestCase):
    def test_valid_domain(self):
        res = TargetValidator.normalize_and_validate("example.com")
        self.assertTrue(res["valid"])
        self.assertEqual(res["normalized_target"], "example.com")
        self.assertEqual(res["target_type"], "DOMAIN")
        self.assertFalse(res["is_private"])

    def test_url_normalization(self):
        res = TargetValidator.normalize_and_validate("https://example.com/admin/login?id=1")
        self.assertTrue(res["valid"])
        self.assertEqual(res["normalized_target"], "example.com")
        self.assertEqual(res["target_type"], "URL")

    def test_url_with_port(self):
        res = TargetValidator.normalize_and_validate("http://example.com:8080/api")
        self.assertTrue(res["valid"])
        self.assertEqual(res["normalized_target"], "example.com")
        self.assertEqual(res["port"], 8080)

    def test_valid_public_ipv4(self):
        res = TargetValidator.normalize_and_validate("93.184.216.34")
        self.assertTrue(res["valid"])
        self.assertEqual(res["normalized_target"], "93.184.216.34")
        self.assertEqual(res["target_type"], "IPV4")
        self.assertFalse(res["is_private"])

    def test_ssrf_blocks_loopback(self):
        res = TargetValidator.normalize_and_validate("127.0.0.1")
        self.assertFalse(res["valid"])
        self.assertTrue(res["is_private"])
        self.assertIn("SSRF", res["error"])

    def test_ssrf_blocks_private_rfc1918(self):
        for priv_ip in ["10.0.0.5", "192.168.1.1", "172.16.0.10"]:
            res = TargetValidator.normalize_and_validate(priv_ip)
            self.assertFalse(res["valid"])
            self.assertTrue(res["is_private"])

    def test_ssrf_blocks_cloud_metadata(self):
        res = TargetValidator.normalize_and_validate("169.254.169.254")
        self.assertFalse(res["valid"])
        self.assertTrue(res["is_private"])

    def test_allow_private_override(self):
        res = TargetValidator.normalize_and_validate("192.168.1.50", allow_private=True)
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_private"])

    def test_invalid_target_rejection(self):
        for bad in ["", "   ", "not a domain!", "http://"]:
            res = TargetValidator.normalize_and_validate(bad)
            self.assertFalse(res["valid"])

if __name__ == "__main__":
    unittest.main()

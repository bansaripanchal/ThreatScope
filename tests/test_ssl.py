"""
Tests for SslService certificate parser and condition checks.
"""

import unittest
from datetime import datetime, timezone, timedelta
from services.ssl_service import SslService

class TestSslService(unittest.TestCase):
    def test_parse_certificate_valid(self):
        # Mock cert structure similar to ssl.getpeercert()
        now = datetime.now(timezone.utc)
        future_date = (now + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")
        past_date = (now - timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")

        mock_cert = {
            "subject": ((("commonName", "example.com"),), (("organizationName", "Example Inc"),)),
            "issuer": ((("commonName", "DigiCert Global Root"),), (("organizationName", "DigiCert Inc"),)),
            "serialNumber": "0123456789ABCDEF",
            "notBefore": past_date,
            "notAfter": future_date,
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com"))
        }

        result = {
            "subject": {}, "issuer": {}, "conditions": [], "sans": [], 
            "days_remaining": None, "hostname_verified": False
        }

        SslService._parse_certificate(mock_cert, "example.com", result)

        self.assertEqual(result["subject"]["common_name"], "example.com")
        self.assertEqual(result["issuer"]["organization"], "DigiCert Inc")
        self.assertTrue(result["hostname_verified"])
        self.assertGreater(result["days_remaining"], 80)
        self.assertEqual(len(result["conditions"]), 0)

    def test_parse_certificate_expired(self):
        now = datetime.now(timezone.utc)
        expired_date = (now - timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
        past_date = (now - timedelta(days=100)).strftime("%b %d %H:%M:%S %Y GMT")

        mock_cert = {
            "subject": ((("commonName", "expired.com"),),),
            "issuer": ((("commonName", "Let's Encrypt"),),),
            "notBefore": past_date,
            "notAfter": expired_date,
            "subjectAltName": (("DNS", "expired.com"),)
        }

        result = {"subject": {}, "issuer": {}, "conditions": [], "sans": []}
        SslService._parse_certificate(mock_cert, "expired.com", result)
        self.assertTrue(any("EXPIRED" in c for c in result["conditions"]))

    def test_parse_certificate_hostname_mismatch(self):
        now = datetime.now(timezone.utc)
        future_date = (now + timedelta(days=60)).strftime("%b %d %H:%M:%S %Y GMT")
        mock_cert = {
            "subject": ((("commonName", "other-domain.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notBefore": future_date,
            "notAfter": future_date,
            "subjectAltName": (("DNS", "other-domain.com"),)
        }

        result = {"subject": {}, "issuer": {}, "conditions": [], "sans": []}
        SslService._parse_certificate(mock_cert, "requested-target.com", result)
        self.assertFalse(result["hostname_verified"])
        self.assertTrue(any("HOSTNAME_MISMATCH" in c for c in result["conditions"]))

if __name__ == "__main__":
    unittest.main()

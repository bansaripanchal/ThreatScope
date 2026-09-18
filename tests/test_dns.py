"""
Tests for DnsService parsing, SPF strength, and DMARC evaluation.
"""

import unittest
from services.dns_service import DnsService

class TestDnsService(unittest.TestCase):
    def test_spf_analysis_strict(self):
        spf_str = "v=spf1 include:_spf.google.com -all"
        res = DnsService._analyze_spf(spf_str)
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["all_policy"], "-all")
        self.assertIn("STRICT_HARDFAIL", res["strength"])

    def test_spf_analysis_softfail(self):
        spf_str = "v=spf1 ip4:192.0.2.0/24 ~all"
        res = DnsService._analyze_spf(spf_str)
        self.assertEqual(res["all_policy"], "~all")
        self.assertIn("SOFTFAIL", res["strength"])

    def test_spf_analysis_dangerous(self):
        spf_str = "v=spf1 +all"
        res = DnsService._analyze_spf(spf_str)
        self.assertEqual(res["all_policy"], "+all")
        self.assertIn("DANGEROUS", res["strength"])

    def test_dmarc_analysis_reject(self):
        dmarc_str = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"
        res = DnsService._analyze_dmarc(dmarc_str)
        self.assertEqual(res["policy"], "reject")
        self.assertIn("REJECT", res["enforcement"])
        self.assertEqual(res["rua"], "mailto:dmarc@example.com")

    def test_dmarc_analysis_none(self):
        dmarc_str = "v=DMARC1; p=none;"
        res = DnsService._analyze_dmarc(dmarc_str)
        self.assertEqual(res["policy"], "none")
        self.assertIn("NONE", res["enforcement"])

if __name__ == "__main__":
    unittest.main()

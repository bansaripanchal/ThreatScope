"""
Tests for SecurityHeadersService analysis and evaluation.
"""

import unittest
from services.security_headers_service import SecurityHeadersService

class TestSecurityHeaders(unittest.TestCase):
    def test_strong_security_headers(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()"
        }

        res = SecurityHeadersService.analyze(headers)
        self.assertEqual(res["present_count"], 6)
        self.assertEqual(res["missing_count"], 0)
        for h in res["headers"]:
            self.assertEqual(h["status"], "STRONG")

    def test_missing_security_headers(self):
        headers = {
            "Server": "nginx",
            "Content-Type": "text/html"
        }

        res = SecurityHeadersService.analyze(headers)
        self.assertEqual(res["present_count"], 0)
        self.assertEqual(res["missing_count"], 6)
        for h in res["headers"]:
            self.assertEqual(h["status"], "MISSING")

    def test_suboptimal_csp(self):
        headers = {
            "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
        }
        res = SecurityHeadersService.analyze(headers)
        csp_result = next(h for h in res["headers"] if h["header"] == "Content-Security-Policy")
        self.assertEqual(csp_result["status"], "SUBOPTIMAL")

if __name__ == "__main__":
    unittest.main()

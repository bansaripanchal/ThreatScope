"""
Tests for FindingService deterministic findings rules.
"""

import unittest
from services.finding_service import FindingService

class TestFindingService(unittest.TestCase):
    def test_missing_security_headers_generates_findings(self):
        target = "example.com"
        mock_data = {
            "security_headers": {
                "headers": [
                    {"header": "Content-Security-Policy", "status": "MISSING", "recommendation": "Set CSP"},
                    {"header": "Strict-Transport-Security", "status": "MISSING", "recommendation": "Set HSTS"},
                    {"header": "X-Frame-Options", "status": "MISSING", "recommendation": "Set XFO"}
                ]
            },
            "dns": {"status": "SUCCESS", "spf": None, "dmarc": None},
            "ports": {"open_ports": []},
            "ssl": {"status": "SUCCESS", "conditions": []},
            "http": {}
        }

        findings = FindingService.evaluate(target, mock_data)
        titles = [f["title"] for f in findings]

        self.assertIn("Missing Content-Security-Policy Header", titles)
        self.assertIn("Missing Strict-Transport-Security (HSTS) Header", titles)
        self.assertIn("Missing X-Frame-Options (Clickjacking Risk)", titles)
        self.assertIn("Missing SPF Record (Email Spoofing Risk)", titles)
        self.assertIn("Missing DMARC Policy Record", titles)

    def test_insecure_exposed_port_findings(self):
        target = "example.com"
        mock_data = {
            "ports": {
                "open_ports": [
                    {"port": 21, "service": "FTP", "banner": "ProFTPD 1.3"},
                    {"port": 3389, "service": "Microsoft RDP"}
                ]
            }
        }
        findings = FindingService.evaluate(target, mock_data)
        severities = {f["title"]: f["severity"] for f in findings}
        self.assertIn("Exposed Insecure FTP Service (Port 21)", severities)
        self.assertEqual(severities["Exposed Insecure FTP Service (Port 21)"], "HIGH")
        self.assertIn("Exposed Remote Desktop (RDP Port 3389)", severities)

if __name__ == "__main__":
    unittest.main()

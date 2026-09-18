"""
Tests for ReportService ensuring all 23 sections are properly compiled from real telemetry.
"""

import unittest
from services.report_service import ReportService

class TestReportService(unittest.TestCase):
    def test_all_23_sections_present(self):
        mock_inv = {
            "id": "ts-audit-999",
            "target": "example.com",
            "target_type": "DOMAIN",
            "normalized_target": "example.com",
            "status": "COMPLETED",
            "started_at": "2026-09-17T12:00:00Z",
            "completed_at": "2026-09-17T12:00:15Z",
            "duration_seconds": 15.0,
            "data": {
                "whois": {"status": "SUCCESS", "registrar": "Example Registrar"},
                "dns": {"status": "SUCCESS", "records": [{"type": "A", "name": "example.com", "value": "93.184.216.34", "ttl": 300}]},
                "ip_info": {"status": "SUCCESS", "ip": "93.184.216.34", "country": "United States"},
                "subdomains": {"status": "SUCCESS", "subdomains": [{"subdomain": "www.example.com", "status": "ACTIVE"}]},
                "endpoints": {"status": "SUCCESS", "endpoints": [{"endpoint": "/", "status_code": 200, "content_type": "text/html"}]},
                "ports": {"status": "SUCCESS", "open_ports": [{"port": 443, "service": "HTTPS", "protocol": "TCP"}]},
                "ssl": {"status": "SUCCESS", "subject": {"common_name": "example.com"}},
                "http": {"status": "SUCCESS", "raw_headers": ["Server: test"]},
                "security_headers": {"status": "SUCCESS", "headers": []},
                "technologies": [{"name": "Nginx", "category": "Web Server"}],
                "attack_surface": {"node_count": 5, "edge_count": 4},
                "findings": [{"title": "Test Finding", "severity": "MEDIUM", "affected_asset": "example.com", "evidence": "ev", "recommendation": "rec"}],
                "timeline": [{"operation": "DNS", "status": "SUCCESS", "duration_ms": 10}]
            }
        }

        report = ReportService.compile_report(mock_inv)

        # Verify presence of all 23 sections
        required_keys = [
            "cover",                  # 1
            "target",                 # 2
            "investigation_info",     # 3
            "scope",                  # 4
            "executive_summary",      # 5
            "target_overview",        # 6
            "whois",                  # 7
            "dns",                    # 8
            "ip_intelligence",        # 9
            "subdomains",             # 10
            "endpoints",              # 11
            "ports_and_services",     # 12
            "ssl_tls",                # 13
            "http_headers",           # 14
            "security_headers",       # 15
            "technologies",           # 16
            "attack_surface",         # 17
            "findings",               # 18
            "evidence",               # 19
            "recommendations",        # 20
            "timeline",               # 21
            "comparison",             # 22
            "limitations"             # 23
        ]

        self.assertEqual(len(required_keys), 23)
        for key in required_keys:
            self.assertIn(key, report, f"Section '{key}' missing from compiled report!")

        # Check executive summary fields
        self.assertEqual(report["executive_summary"]["findings_count"], 1)
        self.assertEqual(report["executive_summary"]["medium_count"], 1)

if __name__ == "__main__":
    unittest.main()

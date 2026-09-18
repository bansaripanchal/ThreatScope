"""
Tests for ComparisonService delta classification engine.
"""

import unittest
from services.comparison_service import ComparisonService

class TestComparisonService(unittest.TestCase):
    def test_comparison_added_and_removed(self):
        inv_a = {
            "id": "scan-1",
            "target": "example.com",
            "started_at": "2026-01-01T00:00:00Z",
            "status": "COMPLETED",
            "data": {
                "ports": {
                    "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 22, "service": "SSH"}]
                },
                "subdomains": {
                    "subdomains": [{"subdomain": "www.example.com", "status": "ACTIVE", "ips": ["1.1.1.1"]}]
                }
            }
        }

        inv_b = {
            "id": "scan-2",
            "target": "example.com",
            "started_at": "2026-02-01T00:00:00Z",
            "status": "COMPLETED",
            "data": {
                "ports": {
                    "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]
                },
                "subdomains": {
                    "subdomains": [
                        {"subdomain": "www.example.com", "status": "ACTIVE", "ips": ["1.1.1.1"]},
                        {"subdomain": "api.example.com", "status": "ACTIVE", "ips": ["1.1.1.2"]}
                    ]
                }
            }
        }

        diff = ComparisonService.compare_investigations(inv_a, inv_b)
        
        # Check ports diff
        port_diffs = {p["item"]: p["state"] for p in diff["categories"]["ports"]}
        self.assertEqual(port_diffs.get("Port 443/TCP"), "ADDED")
        self.assertEqual(port_diffs.get("Port 22/TCP"), "REMOVED")
        self.assertEqual(port_diffs.get("Port 80/TCP"), "UNCHANGED")

        # Check subdomains diff
        sub_diffs = {s["item"]: s["state"] for s in diff["categories"]["subdomains"]}
        self.assertEqual(sub_diffs.get("api.example.com"), "ADDED")
        self.assertEqual(sub_diffs.get("www.example.com"), "UNCHANGED")

        self.assertGreaterEqual(diff["summary"]["added"], 2)
        self.assertGreaterEqual(diff["summary"]["removed"], 1)

if __name__ == "__main__":
    unittest.main()

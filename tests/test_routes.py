"""
Integration tests for Flask application routes and API endpoints.
"""

import unittest
import json
from app import create_app
from config import Config, DATA_DIR

Config.DATABASE_PATH = str(DATA_DIR / "threatscope_integration_test.db")

class TestAppRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_dashboard_route(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"ThreatScope", resp.data)
        self.assertIn(b"Ethical Hacking", resp.data)

    def test_investigate_route_get(self):
        resp = self.client.get("/investigate")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Authorized Target Specification", resp.data)

    def test_attack_surface_route(self):
        resp = self.client.get("/attack-surface")
        self.assertEqual(resp.status_code, 200)

    def test_timeline_route(self):
        resp = self.client.get("/timeline")
        self.assertEqual(resp.status_code, 200)

    def test_compare_route(self):
        resp = self.client.get("/compare")
        self.assertEqual(resp.status_code, 200)

    def test_history_route(self):
        resp = self.client.get("/history")
        self.assertEqual(resp.status_code, 200)

    def test_reports_route(self):
        resp = self.client.get("/reports")
        self.assertEqual(resp.status_code, 200)

    def test_tools_route(self):
        resp = self.client.get("/tools")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/investigate", resp.headers.get("Location", ""))

    def test_about_route(self):
        resp = self.client.get("/about")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"About ThreatScope", resp.data)

    def test_api_validation_tool(self):
        resp = self.client.post("/api/tools/validate", json={"target": "example.com"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["valid"])
        self.assertEqual(data["normalized_target"], "example.com")

    def test_api_validation_tool_ssrf_blocked(self):
        resp = self.client.post("/api/tools/validate", json={"target": "127.0.0.1"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["valid"])
        self.assertTrue(data["is_private"])

    def test_api_investigate_launch_and_status(self):
        resp = self.client.post("/api/investigate", json={"target": "example.com"})
        self.assertEqual(resp.status_code, 202)
        data = resp.get_json()
        self.assertTrue(data["success"])
        inv_id = data["investigation_id"]
        self.assertTrue(inv_id.startswith("ts-"))

        # Poll status
        status_resp = self.client.get(f"/api/investigate/{inv_id}/status")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.get_json()
        self.assertTrue(status_data["success"])
        self.assertEqual(status_data["target"], "example.com")

if __name__ == "__main__":
    unittest.main()

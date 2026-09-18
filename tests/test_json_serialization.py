"""
Unit tests for safe JSON serialization, Jinja2 Undefined handling, and template robustness.
"""

import unittest
import datetime
from jinja2.runtime import Undefined
from app import create_app
from services.json_util import normalize_for_json, safe_json_dumps, safe_json_loads
from services.investigation_service import InvestigationService
from database.repository import InvestigationRepository

class TestJsonSerialization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_normalize_undefined_to_none(self):
        undef = Undefined(name="records")
        res = normalize_for_json(undef)
        self.assertIsNone(res)

    def test_normalize_complex_structure_with_undefined(self):
        complex_data = {
            "dns": {
                "records": Undefined(name="records"),
                "ttl": 300
            },
            "sets": {1, 2, 3},
            "timestamp": datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
            "binary": b"threatscope",
            "items": [Undefined(), "valid", {"nested": Undefined()}]
        }
        normalized = normalize_for_json(complex_data)
        self.assertIsNone(normalized["dns"]["records"])
        self.assertEqual(normalized["dns"]["ttl"], 300)
        self.assertIsInstance(normalized["sets"], list)
        self.assertIn(1, normalized["sets"])
        self.assertIn("2026-01-01T12:00:00", normalized["timestamp"])
        self.assertEqual(normalized["binary"], "threatscope")
        self.assertIsNone(normalized["items"][0])
        self.assertEqual(normalized["items"][1], "valid")
        self.assertIsNone(normalized["items"][2]["nested"])

    def test_safe_json_dumps_with_undefined(self):
        data = {"records": Undefined(name="records")}
        json_str = safe_json_dumps(data)
        self.assertEqual(json_str, '{"records": null}')

    def test_safe_json_loads(self):
        loaded = safe_json_loads('{"status": "SUCCESS", "ports": [80, 443]}')
        self.assertEqual(loaded["status"], "SUCCESS")
        self.assertEqual(loaded["ports"], [80, 443])

        # None / invalid loads
        self.assertEqual(safe_json_loads(None), {})
        self.assertEqual(safe_json_loads("invalid json"), {})

    def test_workspace_template_renders_pending_investigation(self):
        """Verify workspace template renders without error when investigation is fresh and pending."""
        res = InvestigationService.start_investigation("example.com")
        inv_id = res["investigation_id"]

        with self.app.app_context():
            resp = self.client.get(f"/investigate/{inv_id}")
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"example.com", resp.data)
            self.assertIn(b"DNS Records", resp.data)

    def test_workspace_template_renders_with_missing_keys(self):
        """Even if an investigation has completely empty dictionaries, workspace renders safely."""
        empty_inv_id = "ts-test-empty"
        InvestigationRepository.create(
            investigation_id=empty_inv_id,
            target="test-empty.com",
            target_type="DOMAIN",
            normalized_target="test-empty.com",
            status="RUNNING",
            data={
                "target": "test-empty.com",
                "target_type": "DOMAIN",
                "dns": {},
                "whois": {},
                "ip_info": {},
                "ports": {},
                "ssl": {},
                "http": {},
                "security_headers": {},
                "technologies": [],
                "subdomains": {},
                "endpoints": {},
                "attack_surface": {},
                "findings": [],
                "timeline": []
            }
        )

        with self.app.app_context():
            resp = self.client.get(f"/investigate/{empty_inv_id}")
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"test-empty.com", resp.data)

    def test_attack_surface_renders_safely(self):
        empty_inv_id = "ts-test-surface-empty"
        InvestigationRepository.create(
            investigation_id=empty_inv_id,
            target="test-surface.com",
            target_type="DOMAIN",
            normalized_target="test-surface.com",
            status="RUNNING",
            data={
                "target": "test-surface.com",
                "target_type": "DOMAIN",
                "attack_surface": {}
            }
        )
        with self.app.app_context():
            resp = self.client.get(f"/attack-surface/{empty_inv_id}")
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Attack Surface Map", resp.data)

            # Also test attack surface default route
            resp_default = self.client.get("/attack-surface")
            self.assertEqual(resp_default.status_code, 200)

if __name__ == "__main__":
    unittest.main()

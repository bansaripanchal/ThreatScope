"""
Tests for SQLite repository operations.
"""

import unittest
import os
from pathlib import Path
from config import Config, DATA_DIR

# Point test db to temporary path
Config.DATABASE_PATH = str(DATA_DIR / "threatscope_test.db")

from database.db import init_db
from database.repository import InvestigationRepository, TimelineRepository, FindingRepository

class TestDatabaseRepository(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    @classmethod
    def tearDownClass(cls):
        test_path = Path(Config.DATABASE_PATH)
        if test_path.exists():
            try:
                os.remove(test_path)
            except Exception:
                pass

    def test_investigation_crud(self):
        inv_id = "test-inv-001"
        InvestigationRepository.create(
            investigation_id=inv_id,
            target="test.example.com",
            target_type="DOMAIN",
            normalized_target="test.example.com",
            status="RUNNING",
            data={"test": "initial"}
        )

        record = InvestigationRepository.get_by_id(inv_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["target"], "test.example.com")
        self.assertEqual(record["status"], "RUNNING")
        self.assertEqual(record["data"]["test"], "initial")

        InvestigationRepository.update_status(inv_id, "COMPLETED", duration_seconds=12.5, findings_count=3)
        updated = InvestigationRepository.get_by_id(inv_id)
        self.assertEqual(updated["status"], "COMPLETED")
        self.assertEqual(updated["duration_seconds"], 12.5)

        # Timeline
        TimelineRepository.add_event(inv_id, "DNS Check", "SUCCESS", 45, "All records resolved")
        events = TimelineRepository.get_by_investigation(inv_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["operation"], "DNS Check")

        # Findings
        findings = [
            {"title": "Weak Cipher", "severity": "LOW", "description": "Desc", "affected_asset": "test", "evidence": "ev", "source": "src", "recommendation": "rec"}
        ]
        FindingRepository.add_findings(inv_id, findings)
        stored_findings = FindingRepository.get_by_investigation(inv_id)
        self.assertEqual(len(stored_findings), 1)
        self.assertEqual(stored_findings[0]["title"], "Weak Cipher")

        # Delete
        self.assertTrue(InvestigationRepository.delete(inv_id))
        self.assertIsNone(InvestigationRepository.get_by_id(inv_id))

if __name__ == "__main__":
    unittest.main()

"""
ThreatScope V2 - Repository Layer
Handles CRUD operations for investigations, timeline events, and findings.
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from database.db import get_db_connection
from services.json_util import safe_json_dumps, safe_json_loads

class InvestigationRepository:
    @staticmethod
    def create(investigation_id: str, target: str, target_type: str, normalized_target: str, 
               status: str = "PENDING", data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        data_json = safe_json_dumps(data or {})
        with get_db_connection() as conn:
            conn.execute("""
            INSERT INTO investigations (id, target, target_type, normalized_target, status, started_at, data_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (investigation_id, target, target_type, normalized_target, status, now, data_json, now))
        return InvestigationRepository.get_by_id(investigation_id)

    @staticmethod
    def update_status(investigation_id: str, status: str, completed_at: Optional[str] = None, 
                      duration_seconds: Optional[float] = None, findings_count: Optional[int] = None):
        with get_db_connection() as conn:
            updates = ["status = ?"]
            params = [status]
            if completed_at is not None:
                updates.append("completed_at = ?")
                params.append(completed_at)
            if duration_seconds is not None:
                updates.append("duration_seconds = ?")
                params.append(duration_seconds)
            if findings_count is not None:
                updates.append("findings_count = ?")
                params.append(findings_count)
            
            params.append(investigation_id)
            query = f"UPDATE investigations SET {', '.join(updates)} WHERE id = ?"
            conn.execute(query, tuple(params))

    @staticmethod
    def update_data(investigation_id: str, data: Dict[str, Any]):
        data_json = safe_json_dumps(data)
        with get_db_connection() as conn:
            conn.execute("UPDATE investigations SET data_json = ? WHERE id = ?", (data_json, investigation_id))

    @staticmethod
    def get_by_id(investigation_id: str) -> Optional[Dict[str, Any]]:
        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["data"] = safe_json_loads(d.get("data_json", ""), default={})
            return d

    @staticmethod
    def get_all(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM investigations ORDER BY created_at DESC LIMIT ? OFFSET ?", 
                (limit, offset)
            ).fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["data"] = safe_json_loads(item.get("data_json", ""), default={})
                results.append(item)
            return results

    @staticmethod
    def get_count() -> int:
        with get_db_connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM investigations").fetchone()
            return row["cnt"] if row else 0

    @staticmethod
    def delete(investigation_id: str) -> bool:
        with get_db_connection() as conn:
            cur = conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
            return cur.rowcount > 0

    @staticmethod
    def get_stats() -> Dict[str, Any]:
        with get_db_connection() as conn:
            total = conn.execute("SELECT COUNT(*) as cnt FROM investigations").fetchone()["cnt"]
            active = conn.execute("SELECT COUNT(*) as cnt FROM investigations WHERE status = 'RUNNING'").fetchone()["cnt"]
            completed = conn.execute("SELECT COUNT(*) as cnt FROM investigations WHERE status IN ('COMPLETED', 'PARTIAL')").fetchone()["cnt"]
            unique_targets = conn.execute("SELECT COUNT(DISTINCT target) as cnt FROM investigations").fetchone()["cnt"]
            
            crit_findings = conn.execute("SELECT COUNT(*) as cnt FROM findings WHERE severity = 'CRITICAL'").fetchone()["cnt"]
            high_findings = conn.execute("SELECT COUNT(*) as cnt FROM findings WHERE severity = 'HIGH'").fetchone()["cnt"]
            med_findings = conn.execute("SELECT COUNT(*) as cnt FROM findings WHERE severity = 'MEDIUM'").fetchone()["cnt"]
            low_findings = conn.execute("SELECT COUNT(*) as cnt FROM findings WHERE severity = 'LOW'").fetchone()["cnt"]
            info_findings = conn.execute("SELECT COUNT(*) as cnt FROM findings WHERE severity IN ('INFORMATION', 'OBSERVATION')").fetchone()["cnt"]

            return {
                "total_investigations": total,
                "active_scans": active,
                "completed_scans": completed,
                "unique_targets": unique_targets,
                "targets": unique_targets,
                "findings": {
                    "critical": crit_findings,
                    "high": high_findings,
                    "medium": med_findings,
                    "low": low_findings,
                    "information": info_findings,
                    "total": crit_findings + high_findings + med_findings + low_findings + info_findings
                }
            }


class TimelineRepository:
    @staticmethod
    def add_event(investigation_id: str, operation: str, status: str, 
                  duration_ms: Optional[int] = None, message: Optional[str] = None):
        now = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            conn.execute("""
            INSERT INTO timeline_events (investigation_id, timestamp, operation, status, duration_ms, message)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (investigation_id, now, operation, status, duration_ms, message or ""))

    @staticmethod
    def get_by_investigation(investigation_id: str) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM timeline_events WHERE investigation_id = ? ORDER BY id ASC", 
                (investigation_id,)
            ).fetchall()
            return [dict(r) for r in rows]


class FindingRepository:
    @staticmethod
    def add_findings(investigation_id: str, findings: List[Dict[str, Any]]):
        if not isinstance(findings, list):
            return
        now = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            for f in findings:
                if not isinstance(f, dict):
                    continue
                conn.execute("""
                INSERT INTO findings (investigation_id, title, severity, description, affected_asset, evidence, source, recommendation, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    investigation_id,
                    f.get("title", "Untitled Finding"),
                    f.get("severity", "INFORMATION").upper(),
                    f.get("description", ""),
                    f.get("affected_asset", ""),
                    f.get("evidence", ""),
                    f.get("source", ""),
                    f.get("recommendation", ""),
                    f.get("timestamp", now)
                ))

    @staticmethod
    def get_by_investigation(investigation_id: str) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE investigation_id = ? ORDER BY CASE severity "
                "WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 "
                "WHEN 'INFORMATION' THEN 5 ELSE 6 END, id ASC",
                (investigation_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_recent(limit: int = 10) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT f.*, i.target FROM findings f JOIN investigations i ON f.investigation_id = i.id "
                "ORDER BY f.id DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

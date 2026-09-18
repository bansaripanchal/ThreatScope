"""
ThreatScope V2 - Investigation Orchestrator Service
Coordinates all asynchronous reconnaissance modules, manages background thread lifecycles,
handles partial module failures gracefully, and synchronizes real-time audit telemetry.
"""

import uuid
import datetime
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

from database.repository import InvestigationRepository, TimelineRepository, FindingRepository
from services.target_validator import TargetValidator
from services.whois_service import WhoisService
from services.dns_service import DnsService
from services.ipinfo_service import IpInfoService
from services.port_scanner_service import PortScannerService
from services.ssl_service import SslService
from services.http_service import HttpService
from services.security_headers_service import SecurityHeadersService
from services.technology_service import TechnologyService
from services.subdomain_service import SubdomainService
from services.endpoint_service import EndpointService
from services.attack_surface_service import AttackSurfaceService
from services.finding_service import FindingService
from services.timeline_service import TimelineService

class InvestigationService:
    _executor = ThreadPoolExecutor(max_workers=5)

    @classmethod
    def start_investigation(cls, raw_target: str, allow_private: bool = False) -> Dict[str, Any]:
        """
        Validates the target and kicks off an asynchronous background investigation.
        Returns the initial investigation status immediately.
        """
        # 1. Validation & SSRF Enforcement
        validation = TargetValidator.normalize_and_validate(raw_target, allow_private=allow_private)
        if not validation["valid"]:
            return {
                "success": False,
                "error": validation["error"],
                "investigation_id": None
            }

        target = validation["normalized_target"]
        target_type = validation["target_type"]
        investigation_id = f"ts-{uuid.uuid4().hex[:10]}"

        # 2. Persist initial database record with complete default schemas
        initial_data = {
            "target": target,
            "target_type": target_type,
            "validation": validation,
            "whois": {
                "status": "PENDING",
                "registrar": None,
                "nameservers": [],
                "domain_status": [],
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "raw_rdap": None,
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "dns": {
                "status": "PENDING",
                "records": [],
                "records_by_type": {},
                "spf": None,
                "dmarc": None,
                "caa_records": [],
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "ip_info": {
                "status": "PENDING",
                "ip": None,
                "asn": None,
                "organization": None,
                "isp": None,
                "country": None,
                "country_code": None,
                "city": None,
                "region": None,
                "reverse_dns": None,
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "ports": {
                "status": "PENDING",
                "target": target,
                "open_ports": [],
                "open_ports_count": 0,
                "scanned_ports_count": 0,
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "ssl": {
                "status": "PENDING",
                "target": target,
                "port": 443,
                "tls_version": None,
                "cipher": {},
                "subject": {"common_name": None},
                "issuer": {"organization": None, "common_name": None},
                "sans": [],
                "days_remaining": None,
                "conditions": [],
                "hostname_verified": False,
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "http": {
                "status": "PENDING",
                "url": None,
                "status_code": None,
                "reason": None,
                "server": None,
                "content_type": None,
                "content_length": None,
                "latency_ms": 0,
                "headers": {},
                "raw_headers": [],
                "body_snippet": None,
                "set_cookies": [],
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "security_headers": {
                "status": "PENDING",
                "headers": [],
                "grade": "N/A",
                "present_count": 0,
                "missing_count": 0,
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "technologies": [],
            "subdomains": {
                "status": "PENDING",
                "subdomains": [],
                "total_discovered": 0,
                "active_count": 0,
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "endpoints": {
                "status": "PENDING",
                "endpoints": [],
                "total_endpoints": 0,
                "collection_time": None,
                "limitations": "Reconnaissance in progress"
            },
            "attack_surface": {
                "node_count": 0,
                "edge_count": 0,
                "nodes": [],
                "edges": []
            },
            "findings": [],
            "timeline": []
        }

        InvestigationRepository.create(
            investigation_id=investigation_id,
            target=target,
            target_type=target_type,
            normalized_target=target,
            status="RUNNING",
            data=initial_data
        )

        TimelineService.record(
            investigation_id=investigation_id,
            operation="Target Validation",
            status="SUCCESS",
            duration_ms=10,
            message=f"Target '{target}' validated as {target_type}; SSRF checks passed."
        )

        # 3. Launch background execution worker
        cls._executor.submit(cls._run_pipeline, investigation_id, target, target_type, validation)

        return {
            "success": True,
            "investigation_id": investigation_id,
            "target": target,
            "target_type": target_type,
            "status": "RUNNING"
        }

    @classmethod
    def _run_pipeline(cls, investigation_id: str, target: str, target_type: str, validation: Dict[str, Any]):
        """Runs all reconnaissance modules sequentially with fine-grained error isolation."""
        start_time = datetime.datetime.now(datetime.timezone.utc)
        current_data = InvestigationRepository.get_by_id(investigation_id)["data"]
        has_partial_error = False

        # --- Helper for step execution ---
        def execute_step(step_name: str, func, *args, default_on_error=None, **kwargs):
            nonlocal has_partial_error
            t0 = datetime.datetime.now(datetime.timezone.utc)
            try:
                res = func(*args, **kwargs)
                t1 = datetime.datetime.now(datetime.timezone.utc)
                dur = int((t1 - t0).total_seconds() * 1000)
                if isinstance(res, dict):
                    status = "SUCCESS" if res.get("status") in ("SUCCESS", None) else res.get("status")
                    msg = f"{step_name} completed with status {status}"
                elif isinstance(res, (list, tuple)):
                    status = "SUCCESS"
                    msg = f"{step_name} completed with {len(res)} items identified"
                else:
                    status = "SUCCESS"
                    msg = f"{step_name} completed"
                TimelineService.record(investigation_id, step_name, status, dur, msg)
                return res
            except Exception as e:
                t1 = datetime.datetime.now(datetime.timezone.utc)
                dur = int((t1 - t0).total_seconds() * 1000)
                has_partial_error = True
                err_msg = f"{step_name} failed: {str(e)}"
                TimelineService.record(investigation_id, step_name, "FAILED", dur, err_msg)
                if default_on_error is not None:
                    return default_on_error
                return {"status": "ERROR", "error": str(e), "trace": traceback.format_exc()}

        try:
            # Step 1: DNS Intelligence
            dns_res = execute_step("DNS Resolution", DnsService.resolve, target)
            current_data["dns"] = dns_res

            # Extract resolved IP for IP/Port scans
            resolved_ips = [r["value"] for r in dns_res.get("records", []) if r.get("type") in ("A", "AAAA")]
            primary_ip = resolved_ips[0] if resolved_ips else (target if target_type in ("IPV4", "IPV6") else None)

            # Step 2: WHOIS / RDAP (only for domains)
            if target_type in ("DOMAIN", "URL"):
                whois_res = execute_step("WHOIS / RDAP Intelligence", WhoisService.query, target)
                current_data["whois"] = whois_res

            # Step 3: IP Intelligence
            if primary_ip:
                ip_res = execute_step("IP Geolocation & ASN", IpInfoService.lookup, primary_ip)
                current_data["ip_info"] = ip_res

            # Step 4: Port & Service Enumeration
            port_host = primary_ip or target
            ports_res = execute_step("Port & Service Enumeration", PortScannerService.scan_target, port_host)
            current_data["ports"] = ports_res

            # Step 5: SSL / TLS Inspection
            ssl_res = execute_step("SSL / TLS Handshake", SslService.inspect, target, 443)
            current_data["ssl"] = ssl_res

            # Step 6: HTTP Response & Headers
            http_res = execute_step("HTTP Response Inspection", HttpService.probe, target, 443 if ssl_res.get("status") == "SUCCESS" else 80)
            current_data["http"] = http_res

            # Step 7: Security Headers Analysis
            sec_headers_res = execute_step("Security Headers Evaluation", SecurityHeadersService.analyze, http_res.get("headers", {}))
            current_data["security_headers"] = sec_headers_res

            # Step 8: Technology Detection
            tech_res = execute_step(
                "Technology Detection",
                TechnologyService.detect,
                headers=http_res.get("headers", {}) if isinstance(http_res, dict) else {},
                body_html=http_res.get("body_snippet", "") if isinstance(http_res, dict) else "",
                cookies=http_res.get("set_cookies", []) if isinstance(http_res, dict) else [],
                default_on_error=[]
            )
            current_data["technologies"] = tech_res if isinstance(tech_res, list) else []

            # Step 9: Subdomain Intelligence (for domains)
            if target_type in ("DOMAIN", "URL"):
                sub_res = execute_step("Subdomain Discovery", SubdomainService.discover, target)
                current_data["subdomains"] = sub_res

            # Step 10: Web Endpoint Discovery
            ep_res = execute_step(
                "Web Endpoint Discovery",
                EndpointService.discover,
                host=target,
                base_scheme="https" if (isinstance(ssl_res, dict) and ssl_res.get("status") == "SUCCESS") else "http",
                html_body=http_res.get("body_snippet", "") if isinstance(http_res, dict) else ""
            )
            current_data["endpoints"] = ep_res

            # Step 11: Attack Surface Graph Building
            surface_res = execute_step("Attack Surface Graph", AttackSurfaceService.build_graph, current_data)
            current_data["attack_surface"] = surface_res

            # Step 12: Findings Evaluation
            findings_res = execute_step("Findings Engine", FindingService.evaluate, target, current_data, default_on_error=[])
            current_data["findings"] = findings_res if isinstance(findings_res, list) else []

            # Persist findings to database table
            FindingRepository.add_findings(investigation_id, current_data["findings"])

            # Step 13: Finalize Investigation
            end_time = datetime.datetime.now(datetime.timezone.utc)
            duration_sec = round((end_time - start_time).total_seconds(), 2)
            final_status = "PARTIAL" if has_partial_error else "COMPLETED"

            # Pull timeline events to embed in data
            timeline_events = TimelineRepository.get_by_investigation(investigation_id)
            current_data["timeline"] = timeline_events

            # Update DB
            InvestigationRepository.update_data(investigation_id, current_data)
            InvestigationRepository.update_status(
                investigation_id=investigation_id,
                status=final_status,
                completed_at=end_time.isoformat(),
                duration_seconds=duration_sec,
                findings_count=len(findings_res)
            )

            TimelineService.record(
                investigation_id=investigation_id,
                operation="Investigation Completed",
                status="SUCCESS",
                duration_ms=int(duration_sec * 1000),
                message=f"Investigation finished in {duration_sec}s with status {final_status}. {len(findings_res)} findings recorded."
            )

        except Exception as e:
            end_time = datetime.datetime.now(datetime.timezone.utc)
            dur = round((end_time - start_time).total_seconds(), 2)
            TimelineService.record(investigation_id, "Pipeline Error", "FAILED", int(dur * 1000), f"Critical orchestrator exception: {str(e)}")
            InvestigationRepository.update_status(investigation_id, status="FAILED", completed_at=end_time.isoformat(), duration_seconds=dur)

    @classmethod
    def get_investigation(cls, investigation_id: str) -> Optional[Dict[str, Any]]:
        return InvestigationRepository.get_by_id(investigation_id)

    @classmethod
    def delete_investigation(cls, investigation_id: str) -> bool:
        return InvestigationRepository.delete(investigation_id)

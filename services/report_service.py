"""
ThreatScope V2 - Professional Report Service
Compiles authoritative, evidence-backed 23-section reconnaissance and VAPT reports
from actual stored investigation data.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List
from config import Config

class ReportService:
    @classmethod
    def compile_report(cls, investigation: Dict[str, Any], comparison: Dict[str, Any] = None) -> Dict[str, Any]:
        data = investigation.get("data", {})
        target = investigation.get("target", "Unknown")
        target_type = investigation.get("target_type", "DOMAIN")
        inv_id = investigation.get("id")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Cover
        cover = {
            "title": "Ethical Hacking Reconnaissance & Attack Surface Intelligence Report",
            "subtitle": f"Authoritative Security Assessment: {target}",
            "target": target,
            "target_type": target_type,
            "investigation_id": inv_id,
            "date": now,
            "auditor": "ThreatScope Security Engine",
            "confidentiality": "CONFIDENTIAL - RESTRICTED AUDIT TELEMETRY"
        }

        # 2. Target
        target_section = {
            "target": target,
            "normalized_target": investigation.get("normalized_target", target),
            "target_type": target_type,
            "status": investigation.get("status"),
            "resolved_ips": [r.get("value") for r in data.get("dns", {}).get("records", []) if r.get("type") in ("A", "AAAA")]
        }

        # 3. Investigation Information
        inv_info = {
            "id": inv_id,
            "started_at": investigation.get("started_at"),
            "completed_at": investigation.get("completed_at", "N/A"),
            "duration_seconds": investigation.get("duration_seconds", 0),
            "platform_version": Config.APP_VERSION,
            "status": investigation.get("status")
        }

        # 4. Scope
        scope = {
            "authorized_target": target,
            "boundaries": "Publicly accessible DNS, WHOIS, IP route tables, public standard ports, TLS certificates, and HTTP response headers.",
            "rules_of_engagement": "Strictly non-destructive, non-exploitative reconnaissance. SSRF guard rails enforced; zero payload delivery.",
            "mode": "Ethical Reconnaissance & Attack Surface Mapping"
        }

        # 5. Executive Summary
        findings = data.get("findings", [])
        crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in findings if f.get("severity") == "LOW")
        info_count = sum(1 for f in findings if f.get("severity") in ("INFORMATION", "OBSERVATION"))

        risk_posture = "SECURE"
        if crit_count > 0:
            risk_posture = "CRITICAL RISK"
        elif high_count > 0:
            risk_posture = "HIGH RISK"
        elif med_count > 0:
            risk_posture = "MODERATE RISK"
        elif low_count > 0:
            risk_posture = "LOW RISK"

        executive_summary = {
            "risk_posture": risk_posture,
            "findings_count": len(findings),
            "critical_count": crit_count,
            "high_count": high_count,
            "medium_count": med_count,
            "low_count": low_count,
            "info_count": info_count,
            "summary_text": (
                f"ThreatScope conducted a comprehensive reconnaissance analysis against {target}. "
                f"A total of {len(findings)} technical observations were recorded ({crit_count} Critical, "
                f"{high_count} High, {med_count} Medium, {low_count} Low). "
                f"The overall attack surface encompasses {len(data.get('subdomains', {}).get('subdomains', []))} subdomains, "
                f"{len(data.get('ports', {}).get('open_ports', []))} open public TCP ports, and "
                f"{len(data.get('technologies', []))} identified technology stack components."
            )
        }

        # 6. Target Overview
        target_overview = {
            "ips_count": len(target_section["resolved_ips"]),
            "subdomains_count": len(data.get("subdomains", {}).get("subdomains", [])),
            "ports_count": len(data.get("ports", {}).get("open_ports", [])),
            "endpoints_count": len(data.get("endpoints", {}).get("endpoints", [])),
            "technologies_count": len(data.get("technologies", [])),
            "dns_records_count": len(data.get("dns", {}).get("records", [])),
            "certificates_count": 1 if data.get("ssl", {}).get("status") == "SUCCESS" else 0,
            "findings_count": len(findings)
        }

        # 7. WHOIS
        whois_section = data.get("whois", {})

        # 8. DNS Intelligence
        dns_section = data.get("dns", {})

        # 9. IP Intelligence
        ip_section = data.get("ip_info", {})

        # 10. Subdomain Intelligence
        subdomain_section = data.get("subdomains", {})

        # 11. Endpoint Discovery
        endpoint_section = data.get("endpoints", {})

        # 12. Port & Service Enumeration
        port_section = data.get("ports", {})

        # 13. SSL/TLS
        ssl_section = data.get("ssl", {})

        # 14. HTTP Headers
        http_section = data.get("http", {})

        # 15. Security Headers
        sec_headers_section = data.get("security_headers", {})

        # 16. Technology Detection
        tech_section = data.get("technologies", [])

        # 17. Attack Surface
        surface_section = data.get("attack_surface", {})

        # 18. Findings
        findings_section = findings

        # 19. Evidence
        evidence_items = []
        for idx, f in enumerate(findings, 1):
            evidence_items.append({
                "id": idx,
                "finding_title": f.get("title"),
                "affected_asset": f.get("affected_asset"),
                "evidence": f.get("evidence"),
                "source": f.get("source"),
                "timestamp": f.get("timestamp")
            })

        # 20. Recommendations
        recommendations = []
        for f in findings:
            if f.get("recommendation") and f.get("recommendation") not in [r["action"] for r in recommendations]:
                recommendations.append({
                    "severity": f.get("severity"),
                    "title": f.get("title"),
                    "action": f.get("recommendation")
                })

        # 21. Recon Timeline
        timeline_section = data.get("timeline", [])

        # 22. Comparison Information
        comparison_section = comparison or {
            "status": "NO_PREVIOUS_BASELINE",
            "message": "This investigation was executed as a standalone baseline assessment."
        }

        # 23. Limitations / Sources
        limitations = {
            "sources": [
                "ICANN Registration Data Access Protocol (RFC 7480)",
                "Recursive Authoritative DNS Protocol (RFC 1035)",
                "Public Certificate Transparency (crt.sh) Logs",
                "BGP / Autonomous System Routing Tables",
                "Direct TLS Handshake & X.509 ASN.1 Parser",
                "RFC 9110 HTTP/1.1 Standard Request Architecture",
                "Non-Destructive TCP Connect Scanning (RFC 793)"
            ],
            "caveats": [
                "All tests were conducted from authorized external perimeter vantage points.",
                "Cloud WAFs, CDNs, and DDoS mitigation layers (e.g. Cloudflare, Akamai) may mask underlying origin server topologies.",
                "Redacted WHOIS entries conform to GDPR and Registrar Privacy shielding regulations.",
                "Port scans are bounded to standard security audit ports to ensure zero service disruption."
            ]
        }

        return {
            "cover": cover,
            "target": target_section,
            "investigation_info": inv_info,
            "scope": scope,
            "executive_summary": executive_summary,
            "target_overview": target_overview,
            "whois": whois_section,
            "dns": dns_section,
            "ip_intelligence": ip_section,
            "subdomains": subdomain_section,
            "endpoints": endpoint_section,
            "ports_and_services": port_section,
            "ssl_tls": ssl_section,
            "http_headers": http_section,
            "security_headers": sec_headers_section,
            "technologies": tech_section,
            "attack_surface": surface_section,
            "findings": findings_section,
            "evidence": evidence_items,
            "recommendations": recommendations,
            "timeline": timeline_section,
            "comparison": comparison_section,
            "limitations": limitations
        }

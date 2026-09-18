"""
ThreatScope V2 - REST API Routes
Provides endpoints for investigation lifecycle, live status polling,
scan comparison, data export, and standalone on-demand reconnaissance tools.
"""

from flask import Blueprint, request, jsonify
from database.repository import InvestigationRepository, TimelineRepository, FindingRepository
from services.investigation_service import InvestigationService
from services.comparison_service import ComparisonService
from services.target_validator import TargetValidator
from services.whois_service import WhoisService
from services.dns_service import DnsService
from services.ipinfo_service import IpInfoService
from services.port_scanner_service import PortScannerService
from services.ssl_service import SslService
from services.http_service import HttpService
from services.security_headers_service import SecurityHeadersService
from services.subdomain_service import SubdomainService
from services.endpoint_service import EndpointService
from services.report_service import ReportService

api_bp = Blueprint("api", __name__, url_prefix="/api")

# --- Investigation Endpoints ---

@api_bp.route("/investigate", methods=["POST"])
def start_investigation():
    data = request.get_json(silent=True) or request.form
    target = data.get("target", "").strip()
    allow_private = data.get("allow_private", False) in (True, "true", 1, "1")

    if not target:
        return jsonify({"success": False, "error": "Target parameter is required"}), 400

    res = InvestigationService.start_investigation(target, allow_private=allow_private)
    if not res["success"]:
        return jsonify(res), 400
    return jsonify(res), 202

@api_bp.route("/investigate/<investigation_id>/status")
def investigation_status(investigation_id):
    inv = InvestigationRepository.get_by_id(investigation_id)
    if not inv:
        return jsonify({"success": False, "error": "Investigation not found"}), 404

    timeline = TimelineRepository.get_by_investigation(investigation_id)
    findings = FindingRepository.get_by_investigation(investigation_id)
    
    return jsonify({
        "success": True,
        "id": inv["id"],
        "target": inv["target"],
        "target_type": inv["target_type"],
        "status": inv["status"],
        "started_at": inv["started_at"],
        "completed_at": inv["completed_at"],
        "duration_seconds": inv["duration_seconds"],
        "findings_count": len(findings),
        "timeline_events": timeline,
        "is_complete": inv["status"] in ("COMPLETED", "PARTIAL", "FAILED")
    })

@api_bp.route("/investigate/<investigation_id>")
def get_investigation(investigation_id):
    inv = InvestigationRepository.get_by_id(investigation_id)
    if not inv:
        return jsonify({"success": False, "error": "Investigation not found"}), 404
    return jsonify(inv)

@api_bp.route("/reports/<investigation_id>/json")
def get_report_json(investigation_id):
    inv = InvestigationRepository.get_by_id(investigation_id)
    if not inv:
        return jsonify({"success": False, "error": "Investigation not found"}), 404
    report_data = ReportService.compile_report(inv)
    return jsonify(report_data)

@api_bp.route("/investigate/<investigation_id>", methods=["DELETE"])
def delete_investigation(investigation_id):
    success = InvestigationRepository.delete(investigation_id)
    return jsonify({"success": success})

@api_bp.route("/investigations")
def list_investigations():
    limit = request.args.get("limit", 50, type=int)
    items = InvestigationRepository.get_all(limit=limit)
    return jsonify({"success": True, "count": len(items), "investigations": items})

@api_bp.route("/compare", methods=["POST"])
def compare_scans():
    body = request.get_json() or {}
    id_a = body.get("id_a")
    id_b = body.get("id_b")

    if not id_a or not id_b:
        return jsonify({"success": False, "error": "Both id_a and id_b parameters are required"}), 400

    inv_a = InvestigationRepository.get_by_id(id_a)
    inv_b = InvestigationRepository.get_by_id(id_b)

    if not inv_a or not inv_b:
        return jsonify({"success": False, "error": "One or both investigations could not be found"}), 404

    diff = ComparisonService.compare_investigations(inv_a, inv_b)
    return jsonify({"success": True, "diff": diff})

# --- Standalone Quick Recon Tools ---

@api_bp.route("/tools/validate", methods=["POST"])
def tool_validate():
    target = (request.get_json() or {}).get("target", "")
    res = TargetValidator.normalize_and_validate(target)
    return jsonify(res)

@api_bp.route("/tools/whois", methods=["POST"])
def tool_whois():
    target = (request.get_json() or {}).get("target", "")
    val = TargetValidator.normalize_and_validate(target)
    if not val["valid"]:
        return jsonify({"success": False, "error": val["error"]}), 400
    res = WhoisService.query(val["normalized_target"])
    return jsonify(res)

@api_bp.route("/tools/dns", methods=["POST"])
def tool_dns():
    target = (request.get_json() or {}).get("target", "")
    val = TargetValidator.normalize_and_validate(target)
    if not val["valid"]:
        return jsonify({"success": False, "error": val["error"]}), 400
    res = DnsService.resolve(val["normalized_target"])
    return jsonify(res)

@api_bp.route("/tools/ip", methods=["POST"])
def tool_ip():
    data = request.get_json() or {}
    ip = data.get("ip") or data.get("target") or ""
    val = TargetValidator.normalize_and_validate(ip)
    if not val["valid"]:
        return jsonify({"success": False, "error": val["error"]}), 400
    # Resolve if domain
    ip_to_check = val["normalized_target"]
    if val["target_type"] == "DOMAIN" and val.get("resolved_ips"):
        ip_to_check = val["resolved_ips"][0]
    res = IpInfoService.lookup(ip_to_check)
    return jsonify(res)

@api_bp.route("/tools/ports", methods=["POST"])
def tool_ports():
    data = request.get_json() or {}
    target = data.get("target", "")
    ports = data.get("ports")
    val = TargetValidator.normalize_and_validate(target)
    if not val["valid"]:
        return jsonify({"success": False, "error": val["error"]}), 400
    res = PortScannerService.scan_target(val["normalized_target"], ports=ports)
    return jsonify(res)

@api_bp.route("/tools/ssl", methods=["POST"])
def tool_ssl():
    data = request.get_json() or {}
    target = data.get("target", "")
    port = int(data.get("port", 443))
    val = TargetValidator.normalize_and_validate(target)
    if not val["valid"]:
        return jsonify({"success": False, "error": val["error"]}), 400
    res = SslService.inspect(val["normalized_target"], port=port)
    return jsonify(res)

@api_bp.route("/tools/headers", methods=["POST"])
def tool_headers():
    data = request.get_json() or {}
    target = data.get("target", "")
    val = TargetValidator.normalize_and_validate(target)
    if not val["valid"]:
        return jsonify({"success": False, "error": val["error"]}), 400
    http_res = HttpService.probe(val["normalized_target"])
    sec_res = SecurityHeadersService.analyze(http_res.get("headers", {}))
    return jsonify({
        "http": http_res,
        "security_headers": sec_res
    })

@api_bp.route("/tools/subdomains", methods=["POST"])
def tool_subdomains():
    data = request.get_json() or {}
    target = data.get("target", "")
    val = TargetValidator.normalize_and_validate(target)
    if not val["valid"] or val["target_type"] not in ("DOMAIN", "URL"):
        return jsonify({"success": False, "error": "A valid domain name is required"}), 400
    res = SubdomainService.discover(val["normalized_target"], max_subdomains=30)
    return jsonify(res)

@api_bp.route("/tools/endpoints", methods=["POST"])
def tool_endpoints():
    data = request.get_json() or {}
    target = data.get("target", "")
    val = TargetValidator.normalize_and_validate(target)
    if not val["valid"]:
        return jsonify({"success": False, "error": val["error"]}), 400
    res = EndpointService.discover(val["normalized_target"])
    return jsonify(res)

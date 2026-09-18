"""
ThreatScope V2 - Web Routes
Renders front-end views for Dashboard, Investigation Workspace, Attack Surface Map,
Timeline, Comparison, History, Reports, Standalone Tools, and About.
"""

from flask import Blueprint, render_template, request, redirect, url_for, abort
from database.repository import InvestigationRepository, TimelineRepository, FindingRepository
from services.investigation_service import InvestigationService
from services.comparison_service import ComparisonService
from services.report_service import ReportService

web_bp = Blueprint("web", __name__)

@web_bp.route("/")
def dashboard():
    stats = InvestigationRepository.get_stats()
    recent_investigations = InvestigationRepository.get_all(limit=10)
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_investigations=recent_investigations
    )

@web_bp.route("/investigate", methods=["GET", "POST"])
def investigate():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        allow_private = request.form.get("allow_private") == "true"
        res = InvestigationService.start_investigation(target, allow_private=allow_private)
        if res["success"]:
            return redirect(url_for("web.workspace", investigation_id=res["investigation_id"]))
        else:
            return render_template("investigate.html", error=res.get("error"), target=target)
    return render_template("investigate.html")

@web_bp.route("/investigate/<investigation_id>")
def workspace(investigation_id):
    inv = InvestigationRepository.get_by_id(investigation_id)
    if not inv:
        abort(404)
    timeline = TimelineRepository.get_by_investigation(investigation_id)
    findings = FindingRepository.get_by_investigation(investigation_id)

    # Determine primary IP for top-level display
    data = inv.get("data", {})
    primary_ip = None
    if inv.get("target_type") in ("IPV4", "IPV6"):
        primary_ip = inv.get("target")
    elif data.get("ip_info", {}).get("ip"):
        primary_ip = data["ip_info"]["ip"]
    elif data.get("ip", {}).get("primary", {}).get("ip"):
        primary_ip = data["ip"]["primary"]["ip"]
    elif data.get("dns", {}).get("records_by_type", {}).get("A"):
        primary_ip = data["dns"]["records_by_type"]["A"][0].get("value")
    elif data.get("dns", {}).get("records"):
        for r in data["dns"]["records"]:
            if r.get("type") in ("A", "AAAA"):
                primary_ip = r.get("value")
                break

    return render_template(
        "workspace.html",
        investigation=inv,
        timeline=timeline,
        findings=findings,
        primary_ip=primary_ip
    )

@web_bp.route("/attack-surface")
@web_bp.route("/attack-surface/<investigation_id>")
def attack_surface(investigation_id=None):
    if not investigation_id:
        latest = InvestigationRepository.get_all(limit=1)
        if latest:
            investigation_id = latest[0]["id"]
        else:
            return render_template("attack_surface.html", investigation=None, graph_data=None)

    inv = InvestigationRepository.get_by_id(investigation_id)
    if not inv:
        abort(404)

    graph_data = inv.get("data", {}).get("attack_surface", {})
    all_invs = InvestigationRepository.get_all(limit=20)
    return render_template("attack_surface.html", investigation=inv, graph_data=graph_data, all_investigations=all_invs)

@web_bp.route("/timeline")
@web_bp.route("/timeline/<investigation_id>")
def timeline(investigation_id=None):
    if not investigation_id:
        latest = InvestigationRepository.get_all(limit=1)
        if latest:
            investigation_id = latest[0]["id"]
        else:
            return render_template("timeline.html", investigation=None, timeline=[])

    inv = InvestigationRepository.get_by_id(investigation_id)
    if not inv:
        abort(404)

    events = TimelineRepository.get_by_investigation(investigation_id)
    all_invs = InvestigationRepository.get_all(limit=20)
    return render_template("timeline.html", investigation=inv, timeline=events, all_investigations=all_invs)

@web_bp.route("/compare")
def compare():
    all_invs = InvestigationRepository.get_all(limit=50)
    inv_a_id = request.args.get("a")
    inv_b_id = request.args.get("b")
    
    diff = None
    if inv_a_id and inv_b_id:
        inv_a = InvestigationRepository.get_by_id(inv_a_id)
        inv_b = InvestigationRepository.get_by_id(inv_b_id)
        if inv_a and inv_b:
            diff = ComparisonService.compare_investigations(inv_a, inv_b)

    return render_template("compare.html", all_investigations=all_invs, diff=diff, inv_a_id=inv_a_id, inv_b_id=inv_b_id)

@web_bp.route("/history")
def history():
    page = request.args.get("page", 1, type=int)
    limit = 25
    offset = (page - 1) * limit
    total_count = InvestigationRepository.get_count()
    investigations = InvestigationRepository.get_all(limit=limit, offset=offset)
    total_pages = max(1, (total_count + limit - 1) // limit)
    
    return render_template(
        "history.html",
        investigations=investigations,
        page=page,
        total_pages=total_pages,
        total_count=total_count
    )

@web_bp.route("/reports")
@web_bp.route("/reports/<investigation_id>")
def reports(investigation_id=None):
    if not investigation_id:
        latest = InvestigationRepository.get_all(limit=1)
        if latest:
            investigation_id = latest[0]["id"]
        else:
            return render_template("report.html", report=None, investigation=None)

    inv = InvestigationRepository.get_by_id(investigation_id)
    if not inv:
        abort(404)

    # Check for baseline to compare
    comparison_diff = None
    other_scans = InvestigationRepository.get_all(limit=5)
    for other in other_scans:
        if other["id"] != inv["id"] and other["target"] == inv["target"]:
            comparison_diff = ComparisonService.compare_investigations(other, inv)
            break

    report_data = ReportService.compile_report(inv, comparison=comparison_diff)
    all_invs = InvestigationRepository.get_all(limit=25)
    return render_template("report.html", report=report_data, investigation=inv, all_investigations=all_invs)

@web_bp.route("/tools")
def tools():
    return redirect(url_for("web.investigate"))

@web_bp.route("/about")
def about():
    return render_template("about.html")

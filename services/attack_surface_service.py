"""
ThreatScope V2 - Attack Surface Map Builder
Builds a deterministic, evidence-linked asset graph using actual reconnaissance findings.
Constructs typed nodes and authoritative relationship edges.
"""

from typing import Dict, List, Any

class AttackSurfaceService:
    @classmethod
    def build_graph(cls, investigation_data: Dict[str, Any]) -> Dict[str, Any]:
        nodes = []
        edges = []
        node_ids = set()

        def add_node(node_id: str, label: str, node_type: str, value: str, 
                     source: str = "", evidence: str = "", details: Dict[str, Any] = None):
            if node_id not in node_ids:
                nodes.append({
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "value": value,
                    "source": source,
                    "evidence": evidence,
                    "details": details or {}
                })
                node_ids.add(node_id)

        def add_edge(from_id: str, to_id: str, relationship: str, evidence: str = ""):
            if from_id in node_ids and to_id in node_ids:
                edges.append({
                    "from": from_id,
                    "to": to_id,
                    "relationship": relationship,
                    "label": relationship.replace("_", " "),
                    "evidence": evidence
                })

        target = investigation_data.get("target", "Target")
        target_type = investigation_data.get("target_type", "DOMAIN")
        target_id = f"target:{target}"

        # 1. Target Root Node
        add_node(
            node_id=target_id,
            label=target,
            node_type="target",
            value=target,
            source="Target Input",
            evidence=f"Authorized Scope: {target} ({target_type})"
        )

        # 2. DNS & IP Nodes
        dns_data = investigation_data.get("dns", {})
        ip_list = []
        records = dns_data.get("records", []) if isinstance(dns_data, dict) else []
        for r in records:
            if not isinstance(r, dict):
                continue
            rtype = r.get("type")
            rval = r.get("value")
            if rtype in ("A", "AAAA"):
                ip_node_id = f"ip:{rval}"
                add_node(
                    node_id=ip_node_id,
                    label=rval,
                    node_type="ip",
                    value=rval,
                    source=r.get("source", "DNS"),
                    evidence=f"DNS {rtype} record: {rval}"
                )
                add_edge(target_id, ip_node_id, "RESOLVES_TO", f"DNS {rtype} Resolution")
                if rval not in ip_list:
                    ip_list.append(rval)
            elif rtype in ("MX", "NS"):
                rec_id = f"dns:{rtype}:{rval}"
                add_node(
                    node_id=rec_id,
                    label=f"{rtype}: {rval[:20]}",
                    node_type="dns_record",
                    value=rval,
                    source=r.get("source", "DNS"),
                    evidence=f"DNS {rtype} Record"
                )
                add_edge(target_id, rec_id, "RESOLVES_TO", f"DNS {rtype} entry")

        # 3. Port & Service Nodes
        ports_data = investigation_data.get("ports", {})
        open_ports = ports_data.get("open_ports", []) if isinstance(ports_data, dict) else []
        for p in open_ports:
            if not isinstance(p, dict):
                continue
            port_num = p.get("port")
            svc_name = p.get("service", "Unknown")
            banner = p.get("banner")
            
            port_id = f"port:{port_num}"
            svc_id = f"service:{svc_name}:{port_num}"

            # Link port to resolved IP or target
            parent_id = f"ip:{ip_list[0]}" if ip_list else target_id

            add_node(
                node_id=port_id,
                label=f"Port {port_num}/TCP",
                node_type="port",
                value=str(port_num),
                source="Safe TCP Connect",
                evidence=f"TCP handshake succeeded on port {port_num}"
            )
            add_edge(parent_id, port_id, "EXPOSES_PORT", f"Open Port {port_num}")

            add_node(
                node_id=svc_id,
                label=svc_name,
                node_type="service",
                value=svc_name,
                source="Service Identification",
                evidence=banner or f"Service running on port {port_num}"
            )
            add_edge(port_id, svc_id, "RUNS_SERVICE", "Service Protocol")

        # 4. SSL / TLS Certificate Node
        ssl_data = investigation_data.get("ssl", {})
        if isinstance(ssl_data, dict) and ssl_data.get("status") == "SUCCESS" and ssl_data.get("subject"):
            cn = ssl_data.get("subject", {}).get("common_name") or target
            cert_id = f"cert:{cn}"
            add_node(
                node_id=cert_id,
                label=f"Cert: {cn[:20]}",
                node_type="certificate",
                value=cn,
                source=ssl_data.get("source", "TLS Handshake"),
                evidence=f"Valid Until: {ssl_data.get('valid_until')}; TLS: {ssl_data.get('tls_version')}"
            )
            add_edge(target_id, cert_id, "HAS_CERT", "Presents X.509 Certificate")

        # 5. Technology Nodes
        tech_list = investigation_data.get("technologies", [])
        if not isinstance(tech_list, list):
            tech_list = []
        for t in tech_list:
            if not isinstance(t, dict):
                continue
            tname = t.get("name")
            cat = t.get("category", "Technology")
            tech_id = f"tech:{tname}"
            add_node(
                node_id=tech_id,
                label=f"{tname}",
                node_type="technology",
                value=tname,
                source="Passive Signature Detection",
                evidence=t.get("evidence", "")
            )
            add_edge(target_id, tech_id, "USES_TECH", f"Detected {cat}")

        # 6. Subdomain Nodes
        sub_data = investigation_data.get("subdomains", {})
        sub_list = sub_data.get("subdomains", []) if isinstance(sub_data, dict) else []
        for s in sub_list:
            if not isinstance(s, dict):
                continue
            sub_name = s.get("subdomain")
            if s.get("status") == "ACTIVE":
                sub_id = f"subdomain:{sub_name}"
                add_node(
                    node_id=sub_id,
                    label=sub_name,
                    node_type="subdomain",
                    value=sub_name,
                    source=s.get("source", "Subdomain Discovery"),
                    evidence=f"Resolves to: {', '.join(s.get('ips', []))}"
                )
                add_edge(target_id, sub_id, "HAS_SUBDOMAIN", "Discovered Subdomain")

        # 7. Endpoint Nodes
        ep_data = investigation_data.get("endpoints", {})
        ep_list = ep_data.get("endpoints", []) if isinstance(ep_data, dict) else []
        for ep in ep_list:
            if not isinstance(ep, dict):
                continue
            if ep.get("status_code") in (200, 301, 302, 401, 403):
                path = ep.get("endpoint")
                ep_id = f"endpoint:{path}"
                add_node(
                    node_id=ep_id,
                    label=path,
                    node_type="endpoint",
                    value=path,
                    source=ep.get("source", "Endpoint Discovery"),
                    evidence=f"HTTP {ep.get('status_code')} ({ep.get('content_type')})"
                )
                add_edge(target_id, ep_id, "CONTAINS_ENDPOINT", f"HTTP {ep.get('status_code')}")

        return {
            "target": target,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "node_types": list(set(n["type"] for n in nodes))
        }

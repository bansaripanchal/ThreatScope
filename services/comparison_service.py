"""
ThreatScope V2 - Reconnaissance Comparison Service
Calculates multi-dimensional diffs between two stored investigations.
Classifies changes as ADDED, REMOVED, CHANGED, or UNCHANGED across all assets.
"""

from typing import Dict, List, Any

class ComparisonService:
    @classmethod
    def compare_investigations(cls, inv_a: Dict[str, Any], inv_b: Dict[str, Any]) -> Dict[str, Any]:
        data_a = inv_a.get("data", {})
        data_b = inv_b.get("data", {})

        diff = {
            "inv_a": {
                "id": inv_a.get("id"),
                "target": inv_a.get("target"),
                "started_at": inv_a.get("started_at"),
                "status": inv_a.get("status")
            },
            "inv_b": {
                "id": inv_b.get("id"),
                "target": inv_b.get("target"),
                "started_at": inv_b.get("started_at"),
                "status": inv_b.get("status")
            },
            "categories": {},
            "summary": {
                "added": 0,
                "removed": 0,
                "changed": 0,
                "unchanged": 0
            }
        }

        # 1. Subdomains comparison
        subs_a = {s.get("subdomain"): s for s in data_a.get("subdomains", {}).get("subdomains", [])}
        subs_b = {s.get("subdomain"): s for s in data_b.get("subdomains", {}).get("subdomains", [])}
        diff["categories"]["subdomains"] = cls._diff_sets(
            subs_a, subs_b, 
            label_extractor=lambda s: s.get("subdomain"),
            val_extractor=lambda s: f"Status: {s.get('status')}; IPs: {', '.join(s.get('ips', []))}"
        )

        # 2. IPs comparison
        ips_a = {r.get("value"): r for r in data_a.get("dns", {}).get("records", []) if r.get("type") in ("A", "AAAA")}
        ips_b = {r.get("value"): r for r in data_b.get("dns", {}).get("records", []) if r.get("type") in ("A", "AAAA")}
        diff["categories"]["ips"] = cls._diff_sets(
            ips_a, ips_b,
            label_extractor=lambda r: r.get("value"),
            val_extractor=lambda r: f"DNS {r.get('type')}"
        )

        # 3. Ports comparison
        ports_a = {p.get("port"): p for p in data_a.get("ports", {}).get("open_ports", [])}
        ports_b = {p.get("port"): p for p in data_b.get("ports", {}).get("open_ports", [])}
        diff["categories"]["ports"] = cls._diff_sets(
            ports_a, ports_b,
            label_extractor=lambda p: f"Port {p.get('port')}/TCP",
            val_extractor=lambda p: f"Service: {p.get('service')}"
        )

        # 4. Technologies comparison
        tech_a = {t.get("name"): t for t in data_a.get("technologies", [])}
        tech_b = {t.get("name"): t for t in data_b.get("technologies", [])}
        diff["categories"]["technologies"] = cls._diff_sets(
            tech_a, tech_b,
            label_extractor=lambda t: t.get("name"),
            val_extractor=lambda t: f"Category: {t.get('category')}"
        )

        # 5. DNS Records comparison
        dns_map_a = {f"{r.get('type')}:{r.get('value')}": r for r in data_a.get("dns", {}).get("records", [])}
        dns_map_b = {f"{r.get('type')}:{r.get('value')}": r for r in data_b.get("dns", {}).get("records", [])}
        diff["categories"]["dns"] = cls._diff_sets(
            dns_map_a, dns_map_b,
            label_extractor=lambda r: f"{r.get('type')} Record",
            val_extractor=lambda r: r.get("value")
        )

        # 6. Endpoints comparison
        ep_a = {e.get("endpoint"): e for e in data_a.get("endpoints", {}).get("endpoints", [])}
        ep_b = {e.get("endpoint"): e for e in data_b.get("endpoints", {}).get("endpoints", [])}
        diff["categories"]["endpoints"] = cls._diff_sets(
            ep_a, ep_b,
            label_extractor=lambda e: e.get("endpoint"),
            val_extractor=lambda e: f"HTTP {e.get('status_code')} ({e.get('content_type')})"
        )

        # 7. SSL / TLS comparison
        ssl_a = data_a.get("ssl", {})
        ssl_b = data_b.get("ssl", {})
        ssl_diffs = []
        for prop in ["tls_version", "valid_until", "serial_number"]:
            val_a = ssl_a.get(prop)
            val_b = ssl_b.get(prop)
            if val_a != val_b:
                state = "CHANGED" if (val_a and val_b) else ("ADDED" if val_b else "REMOVED")
                ssl_diffs.append({
                    "item": prop.replace("_", " ").title(),
                    "state": state,
                    "val_a": str(val_a),
                    "val_b": str(val_b)
                })
            else:
                ssl_diffs.append({
                    "item": prop.replace("_", " ").title(),
                    "state": "UNCHANGED",
                    "val_a": str(val_a),
                    "val_b": str(val_b)
                })
        diff["categories"]["ssl"] = ssl_diffs

        # 8. Findings comparison
        findings_a = {f.get("title"): f for f in data_a.get("findings", [])}
        findings_b = {f.get("title"): f for f in data_b.get("findings", [])}
        diff["categories"]["findings"] = cls._diff_sets(
            findings_a, findings_b,
            label_extractor=lambda f: f.get("title"),
            val_extractor=lambda f: f"Severity: {f.get('severity')}"
        )

        # Calculate totals across all categories
        for cat, items in diff["categories"].items():
            for item in items:
                st = item.get("state", "").lower()
                if st in diff["summary"]:
                    diff["summary"][st] += 1

        return diff

    @classmethod
    def _diff_sets(cls, dict_a: Dict, dict_b: Dict, label_extractor, val_extractor) -> List[Dict[str, Any]]:
        results = []
        keys_a = set(dict_a.keys())
        keys_b = set(dict_b.keys())

        # Unchanged & Changed
        for k in keys_a.intersection(keys_b):
            val_a = val_extractor(dict_a[k])
            val_b = val_extractor(dict_b[k])
            state = "UNCHANGED" if val_a == val_b else "CHANGED"
            results.append({
                "item": label_extractor(dict_b[k]),
                "state": state,
                "val_a": val_a,
                "val_b": val_b
            })

        # Added in B
        for k in keys_b - keys_a:
            results.append({
                "item": label_extractor(dict_b[k]),
                "state": "ADDED",
                "val_a": "None",
                "val_b": val_extractor(dict_b[k])
            })

        # Removed from A
        for k in keys_a - keys_b:
            results.append({
                "item": label_extractor(dict_a[k]),
                "state": "REMOVED",
                "val_a": val_extractor(dict_a[k]),
                "val_b": "None"
            })

        # Sort order: ADDED, REMOVED, CHANGED, UNCHANGED
        order = {"ADDED": 0, "REMOVED": 1, "CHANGED": 2, "UNCHANGED": 3}
        results.sort(key=lambda x: order.get(x["state"], 99))
        return results

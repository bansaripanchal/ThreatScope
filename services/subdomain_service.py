"""
ThreatScope V2 - Subdomain Intelligence Service
Discovers subdomains via public Certificate Transparency (crt.sh) logs and active DNS resolution.
Validates live HTTP/HTTPS status and records discovery provenance.
"""

import socket
import datetime
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Set
from config import Config

class SubdomainService:
    CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"

    @classmethod
    def discover(cls, domain: str, max_subdomains: int = 40) -> Dict[str, Any]:
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        clean_domain = domain.lower().strip().rstrip(".")

        result = {
            "status": "PENDING",
            "source": "Certificate Transparency Logs (crt.sh) & Active DNS Probing",
            "collection_time": start_time,
            "target": clean_domain,
            "total_discovered": 0,
            "active_count": 0,
            "subdomains": [],
            "limitations": "Certificate Transparency logs identify domains with publicly logged TLS certificates. Passive logs may include retired hosts. Active DNS verification confirms current routability."
        }

        discovered_names: Set[str] = set()

        # 1. Query crt.sh Certificate Transparency Logs
        try:
            url = cls.CRT_SH_URL.format(domain=clean_domain)
            headers = {"User-Agent": Config.USER_AGENT}
            resp = requests.get(url, headers=headers, timeout=Config.HTTP_TIMEOUT * 2)
            
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name_value = entry.get("name_value", "")
                    # May contain multiple names separated by newlines
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name.endswith(clean_domain) and name != clean_domain:
                            # Sanitize
                            if all(c.isalnum() or c in ".-" for c in name):
                                discovered_names.add(name)
                                if len(discovered_names) >= max_subdomains:
                                    break
                    if len(discovered_names) >= max_subdomains:
                        break
        except Exception:
            # crt.sh might be slow or rate-limited; proceed with DNS dictionary probing
            pass

        # 2. Add common DNS subdomain prefixes
        for prefix in Config.COMMON_SUBDOMAINS:
            candidate = f"{prefix}.{clean_domain}"
            discovered_names.add(candidate)

        # 3. Resolve and probe discovered candidates concurrently
        subdomain_results = []
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKER_THREADS) as executor:
            future_to_sub = {
                executor.submit(cls._verify_subdomain, sub, clean_domain): sub
                for sub in list(discovered_names)[:max_subdomains]
            }

            for future in as_completed(future_to_sub):
                try:
                    sub_data = future.result()
                    subdomain_results.append(sub_data)
                except Exception:
                    pass

        # Sort: Active subdomains first, then alphabetically
        subdomain_results.sort(key=lambda x: (x["status"] != "ACTIVE", x["subdomain"]))

        active_count = sum(1 for s in subdomain_results if s["status"] == "ACTIVE")

        result["subdomains"] = subdomain_results
        result["total_discovered"] = len(subdomain_results)
        result["active_count"] = active_count
        result["status"] = "SUCCESS" if subdomain_results else "NO_DATA"

        return result

    @classmethod
    def _verify_subdomain(cls, subdomain: str, parent_domain: str) -> Dict[str, Any]:
        """Verifies if a subdomain resolves and checks basic HTTP/HTTPS status."""
        ips = []
        status = "UNRESOLVED"
        http_code = None
        https_code = None
        server_banner = None

        # DNS Resolution
        try:
            results = socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for r in results:
                ip = r[4][0]
                if ip not in ips:
                    ips.append(ip)
            if ips:
                status = "ACTIVE"
        except Exception:
            pass

        # If resolves, safely probe HTTP / HTTPS status codes
        if status == "ACTIVE":
            # Quick check for HTTPS
            try:
                r_https = requests.head(
                    f"https://{subdomain}/", 
                    timeout=2.0, 
                    headers={"User-Agent": Config.USER_AGENT},
                    verify=False,
                    allow_redirects=False
                )
                https_code = r_https.status_code
                server_banner = r_https.headers.get("Server")
            except Exception:
                pass

            # Quick check for HTTP
            try:
                r_http = requests.head(
                    f"http://{subdomain}/", 
                    timeout=2.0, 
                    headers={"User-Agent": Config.USER_AGENT},
                    allow_redirects=False
                )
                http_code = r_http.status_code
                if not server_banner:
                    server_banner = r_http.headers.get("Server")
            except Exception:
                pass

        source = "Certificate Transparency" if subdomain not in [f"{p}.{parent_domain}" for p in Config.COMMON_SUBDOMAINS] else "DNS Wordlist Probing"

        return {
            "subdomain": subdomain,
            "ips": ips,
            "status": status,
            "http_status": http_code,
            "https_status": https_code,
            "server": server_banner,
            "source": source
        }

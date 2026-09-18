"""
ThreatScope V2 - Web Endpoint Discovery Service
Discovers public endpoints via bounded checks of standard administrative/API paths
and same-origin links extracted passively from homepage HTML.
Enforces non-destructive probing and bounded depths.
"""

import re
import datetime
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Set
from config import Config

class EndpointService:
    @classmethod
    def discover(cls, host: str, base_scheme: str = "https", html_body: str = "") -> Dict[str, Any]:
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        base_url = f"{base_scheme}://{host}"

        result = {
            "status": "PENDING",
            "source": "Safe Bounded Path Probes & Same-Origin Links",
            "collection_time": start_time,
            "target": host,
            "base_url": base_url,
            "total_endpoints": 0,
            "endpoints": [],
            "limitations": "Probing is bounded to standard public and well-known paths. The presence of an endpoint is an architectural observation and does not indicate vulnerability."
        }

        discovered_candidates: Dict[str, str] = {}  # path -> source

        # 1. Add well-known safe paths
        for path in Config.SAFE_PUBLIC_ENDPOINTS:
            discovered_candidates[path] = "Well-Known Public Path"

        # 2. Extract same-origin links from provided HTML body
        if html_body:
            extracted_links = cls._extract_same_origin_links(html_body, host)
            for path in extracted_links[:15]:  # Bound to 15 additional links
                if path not in discovered_candidates:
                    discovered_candidates[path] = "Same-Origin HTML Link"

        endpoints_list = []
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKER_THREADS) as executor:
            future_to_path = {
                executor.submit(cls._probe_endpoint, base_url, path, source): path
                for path, source in discovered_candidates.items()
            }

            for future in as_completed(future_to_path):
                try:
                    ep_res = future.result()
                    if ep_res:
                        endpoints_list.append(ep_res)
                except Exception:
                    pass

        # Sort: status code 200 first, then by path
        endpoints_list.sort(key=lambda x: (x["status_code"] != 200, x["endpoint"]))

        result["endpoints"] = endpoints_list
        result["total_endpoints"] = len(endpoints_list)
        result["status"] = "SUCCESS" if endpoints_list else "NO_DATA"

        return result

    @classmethod
    def _probe_endpoint(cls, base_url: str, path: str, source: str) -> Dict[str, Any]:
        full_url = urljoin(base_url, path)
        try:
            resp = requests.get(
                full_url,
                timeout=Config.HTTP_TIMEOUT,
                headers={"User-Agent": Config.USER_AGENT},
                verify=False,
                allow_redirects=False
            )
            
            content_length = len(resp.content) if resp.content else 0
            if "Content-Length" in resp.headers and resp.headers["Content-Length"].isdigit():
                content_length = int(resp.headers["Content-Length"])

            return {
                "endpoint": path,
                "url": full_url,
                "method": "GET",
                "status_code": resp.status_code,
                "response_size": content_length,
                "content_type": resp.headers.get("Content-Type", "Unknown"),
                "redirect_url": resp.headers.get("Location"),
                "source": source
            }
        except requests.exceptions.RequestException:
            # Skip unreachable endpoints to avoid clutter
            return None

    @classmethod
    def _extract_same_origin_links(cls, html: str, target_host: str) -> List[str]:
        # Regex extraction of href attributes
        raw_hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        paths: Set[str] = set()
        target_host_lower = target_host.lower()

        for href in raw_hrefs:
            href = href.strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            if href.startswith("/"):
                # Relative path
                clean_path = href.split("?")[0].split("#")[0]
                if clean_path and not clean_path.endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".svg", ".ico", ".woff", ".ttf")):
                    paths.add(clean_path)
            elif href.startswith(("http://", "https://")):
                try:
                    parsed = urlparse(href)
                    if parsed.hostname and (parsed.hostname.lower() == target_host_lower or parsed.hostname.lower().endswith(f".{target_host_lower}")):
                        clean_path = parsed.path or "/"
                        clean_path = clean_path.split("?")[0].split("#")[0]
                        if clean_path and not clean_path.endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".svg", ".ico", ".woff", ".ttf")):
                            paths.add(clean_path)
                except Exception:
                    pass

        return sorted(list(paths))

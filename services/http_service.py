"""
ThreatScope V2 - HTTP & Response Intelligence Service
Gathers HTTP/HTTPS response data, redirect chains, raw headers, and cookie attributes.
"""

import datetime
import requests
import urllib3
from typing import Dict, Any, List
from config import Config

# Suppress unverified HTTPS warning for intentional security reconnaissance
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HttpService:
    @classmethod
    def probe(cls, host: str, port: int = None, use_https: bool = True) -> Dict[str, Any]:
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scheme = "https" if use_https else "http"
        port_str = f":{port}" if port and port not in (80, 443) else ""
        url = f"{scheme}://{host}{port_str}/"

        result = {
            "status": "PENDING",
            "source": f"HTTP Client (RFC 9110) GET {url}",
            "collection_time": start_time,
            "url": url,
            "scheme": scheme,
            "status_code": None,
            "reason": None,
            "latency_ms": None,
            "redirect_chain": [],
            "server": None,
            "content_type": None,
            "content_length": None,
            "cache_control": None,
            "location": None,
            "set_cookies": [],
            "headers": {},
            "raw_headers": [],
            "body_snippet": None,
            "limitations": "Standard HTTP GET request with max 5 redirects followed and SSRF protection boundaries enforced."
        }

        session = requests.Session()
        session.headers.update({
            "User-Agent": Config.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close"
        })

        try:
            t0 = datetime.datetime.now(datetime.timezone.utc)
            # Disable automatic redirect following to capture full redirect chain accurately
            resp = session.get(url, timeout=Config.HTTP_TIMEOUT, allow_redirects=True, verify=False)
            t1 = datetime.datetime.now(datetime.timezone.utc)
            result["latency_ms"] = int((t1 - t0).total_seconds() * 1000)

            # Record redirect history
            if resp.history:
                for hist_resp in resp.history:
                    result["redirect_chain"].append({
                        "url": hist_resp.url,
                        "status_code": hist_resp.status_code,
                        "reason": hist_resp.reason,
                        "location": hist_resp.headers.get("Location")
                    })
            # Add final destination to redirect chain
            result["redirect_chain"].append({
                "url": resp.url,
                "status_code": resp.status_code,
                "reason": resp.reason,
                "location": None
            })

            result["status_code"] = resp.status_code
            result["reason"] = resp.reason
            result["server"] = resp.headers.get("Server")
            result["content_type"] = resp.headers.get("Content-Type")
            result["content_length"] = resp.headers.get("Content-Length")
            result["cache_control"] = resp.headers.get("Cache-Control")
            result["location"] = resp.headers.get("Location")

            # Store headers
            headers_dict = dict(resp.headers)
            result["headers"] = headers_dict
            result["raw_headers"] = [f"{k}: {v}" for k, v in headers_dict.items()]

            # Analyze Set-Cookie headers
            cookie_headers = resp.headers.get("Set-Cookie")
            if cookie_headers:
                result["set_cookies"] = cls._parse_cookies(cookie_headers)

            # Store safe body snippet (up to 32KB for technology identification)
            text_content = resp.text if resp.encoding else resp.content.decode("utf-8", errors="ignore")
            result["body_snippet"] = text_content[:32768]
            result["status"] = "SUCCESS"

        except requests.exceptions.SSLError as e:
            # If HTTPS fails, try HTTP fallback if initial request was HTTPS
            if use_https:
                fallback_res = cls.probe(host, port=80, use_https=False)
                fallback_res["limitations"] += f" (HTTPS failed: {str(e)}; fallback to HTTP succeeded)"
                return fallback_res
            result["status"] = "TLS_ERROR"
            result["limitations"] += f" SSL verification failed: {str(e)}"
        except requests.exceptions.Timeout:
            result["status"] = "TIMEOUT"
            result["limitations"] += f" Connection to {url} timed out after {Config.HTTP_TIMEOUT}s."
        except requests.exceptions.ConnectionError as e:
            if use_https:
                # Try HTTP fallback
                return cls.probe(host, port=80, use_https=False)
            result["status"] = "NETWORK_ERROR"
            result["limitations"] += f" Connection refused or target unreachable: {str(e)}"
        except Exception as e:
            result["status"] = "ERROR"
            result["limitations"] += f" HTTP probe exception: {str(e)}"

        return result

    @classmethod
    def _parse_cookies(cls, set_cookie_str: str) -> List[Dict[str, Any]]:
        cookies = []
        # Handle multiple cookies if separated or single
        cookie_parts = set_cookie_str.split(",")
        for cp in cookie_parts:
            items = [item.strip() for item in cp.split(";")]
            if not items:
                continue
            name_val = items[0]
            if "=" in name_val:
                cname, cval = name_val.split("=", 1)
            else:
                cname, cval = name_val, ""

            samesite_val = None
            for a in attrs:
                if a.startswith("samesite"):
                    parts = a.split("=", 1)
                    samesite_val = parts[1] if len(parts) > 1 else "true"
                    break

            cookies.append({
                "name": cname,
                "value": cval[:20] + "..." if len(cval) > 20 else cval,
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": samesite_val
            })
        return cookies

"""
ThreatScope V2 - Technology Detection Service
Passively detects server technologies, frameworks, CMS, JavaScript libraries,
CDNs, and security products from HTTP headers, cookies, and HTML signatures.
"""

import re
from typing import Dict, List, Any

class TechnologyService:
    # Signatures database
    SIGNATURES = [
        # Web Servers
        {"name": "Nginx", "category": "Web Server", "header": "server", "regex": r"nginx(?:/([0-9.]+))?", "confidence": "HIGH"},
        {"name": "Apache HTTP Server", "category": "Web Server", "header": "server", "regex": r"apache(?:/([0-9.]+))?", "confidence": "HIGH"},
        {"name": "Microsoft IIS", "category": "Web Server", "header": "server", "regex": r"microsoft-iis(?:/([0-9.]+))?", "confidence": "HIGH"},
        {"name": "Caddy", "category": "Web Server", "header": "server", "regex": r"caddy", "confidence": "HIGH"},
        {"name": "LiteSpeed", "category": "Web Server", "header": "server", "regex": r"litespeed", "confidence": "HIGH"},
        {"name": "Cloudflare Server", "category": "Web Server", "header": "server", "regex": r"cloudflare", "confidence": "HIGH"},

        # CDN & Reverse Proxies
        {"name": "Cloudflare", "category": "CDN", "header": "cf-ray", "regex": r".+", "confidence": "HIGH"},
        {"name": "Amazon CloudFront", "category": "CDN", "header": "via", "regex": r"cloudfront", "confidence": "HIGH"},
        {"name": "Fastly", "category": "CDN", "header": "via", "regex": r"varnish|fastly", "confidence": "HIGH"},
        {"name": "Akamai", "category": "CDN", "header": "server", "regex": r"akamaighost", "confidence": "HIGH"},

        # Frameworks & Platforms
        {"name": "PHP", "category": "Programming Language", "header": "x-powered-by", "regex": r"php(?:/([0-9.]+))?", "confidence": "HIGH"},
        {"name": "ASP.NET", "category": "Framework", "header": "x-powered-by", "regex": r"asp\.net", "confidence": "HIGH"},
        {"name": "Express.js", "category": "Framework", "header": "x-powered-by", "regex": r"express", "confidence": "HIGH"},
        {"name": "Next.js", "category": "Framework", "html": r'id="__next"|<script[^>]+next/dist', "confidence": "HIGH"},
        {"name": "Nuxt.js", "category": "Framework", "html": r'id="__nuxt"|data-n-head', "confidence": "HIGH"},
        {"name": "Django", "category": "Framework", "cookie": r"csrftoken", "confidence": "MEDIUM"},
        {"name": "Laravel", "category": "Framework", "cookie": r"laravel_session|XSRF-TOKEN", "confidence": "MEDIUM"},
        {"name": "Ruby on Rails", "category": "Framework", "header": "x-powered-by", "regex": r"phusion_passenger|rails", "confidence": "HIGH"},

        # CMS
        {"name": "WordPress", "category": "CMS", "html": r'wp-content|wp-includes|<meta name="generator" content="WordPress', "confidence": "HIGH"},
        {"name": "Drupal", "category": "CMS", "html": r'Drupal\.settings|<meta name="generator" content="Drupal', "confidence": "HIGH"},
        {"name": "Joomla", "category": "CMS", "html": r'<meta name="generator" content="Joomla', "confidence": "HIGH"},
        {"name": "Shopify", "category": "CMS", "html": r'cdn\.shopify\.com|Shopify\.theme', "confidence": "HIGH"},

        # Frontend Libraries
        {"name": "React", "category": "JavaScript", "html": r'data-reactroot|react\.production\.min\.js|__REACT_DEVTOOLS_GLOBAL_HOOK__', "confidence": "HIGH"},
        {"name": "Vue.js", "category": "JavaScript", "html": r'data-v-[a-f0-9]+|vue\.min\.js|__vue__', "confidence": "HIGH"},
        {"name": "Angular", "category": "JavaScript", "html": r'ng-version|ng-app|angular\.min\.js', "confidence": "HIGH"},
        {"name": "jQuery", "category": "JavaScript", "html": r'jquery(?:-([0-9.]+))?\.min\.js|jquery\.js', "confidence": "HIGH"},
        {"name": "Tailwind CSS", "category": "CSS", "html": r'class="[^"]*(?:flex|grid|hidden|text-|bg-|p-|m-)[^"]*"', "confidence": "LOW"},
        {"name": "Bootstrap", "category": "CSS", "html": r'bootstrap(?:\.min)?\.css|<div class="container(?:-fluid)?"', "confidence": "MEDIUM"},

        # Analytics
        {"name": "Google Analytics", "category": "Analytics", "html": r'google-analytics\.com/analytics\.js|googletagmanager\.com/gtag/js', "confidence": "HIGH"}
    ]

    @classmethod
    def detect(cls, headers: Dict[str, str], body_html: str = "", cookies: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        technologies = []
        detected_names = set()

        lower_headers = {k.lower(): v for k, v in headers.items()}
        cookie_names = [c.get("name", "") for c in (cookies or [])]
        cookie_string = "; ".join(cookie_names)

        for sig in cls.SIGNATURES:
            name = sig["name"]
            if name in detected_names:
                continue

            category = sig["category"]
            confidence = sig["confidence"]

            # Header match
            if "header" in sig:
                h_name = sig["header"]
                if h_name in lower_headers:
                    h_val = lower_headers[h_name]
                    match = re.search(sig["regex"], h_val, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() and match.group(1) else None
                        tech_name = f"{name} {version}" if version else name
                        technologies.append({
                            "name": tech_name,
                            "category": category,
                            "confidence": confidence,
                            "evidence": f"Header '{h_name}: {h_val}'"
                        })
                        detected_names.add(name)
                        continue

            # Cookie match
            if "cookie" in sig:
                if re.search(sig["cookie"], cookie_string, re.IGNORECASE):
                    technologies.append({
                        "name": name,
                        "category": category,
                        "confidence": confidence,
                        "evidence": f"Cookie signature matched '{sig['cookie']}'"
                    })
                    detected_names.add(name)
                    continue

            # HTML body match
            if "html" in sig and body_html:
                if re.search(sig["html"], body_html, re.IGNORECASE):
                    technologies.append({
                        "name": name,
                        "category": category,
                        "confidence": confidence,
                        "evidence": f"HTML pattern matched '{sig['html'][:40]}...'"
                    })
                    detected_names.add(name)
                    continue

        return technologies

"""
ThreatScope V2 - Security Headers Analysis Service
Inspects HTTP headers for critical defensive controls:
CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
Provides factual security significance and actionable remediation guidance without arbitrary scores.
"""

from typing import Dict, List, Any

class SecurityHeadersService:
    HEADERS_SPEC = [
        {
            "header": "Content-Security-Policy",
            "aliases": ["content-security-policy"],
            "purpose": "Restricts resources (scripts, images, media) the browser is allowed to load for a given page.",
            "significance": "Mitigates Cross-Site Scripting (XSS), Clickjacking, and malicious packet injection attacks.",
            "recommendation": "Configure a strict Content-Security-Policy restricting script-src, object-src, and base-uri directives."
        },
        {
            "header": "Strict-Transport-Security",
            "aliases": ["strict-transport-security"],
            "purpose": "Enforces secure HTTPS connections and instructs the browser to disallow insecure HTTP communication.",
            "significance": "Prevents SSL-stripping attacks and man-in-the-middle protocol downgrade vectors.",
            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
        },
        {
            "header": "X-Content-Type-Options",
            "aliases": ["x-content-type-options"],
            "purpose": "Prevents browsers from MIME-sniffing a response away from the declared Content-Type.",
            "significance": "Protects against drive-by downloads and user-uploaded file execution vulnerabilities.",
            "recommendation": "Set 'X-Content-Type-Options: nosniff'."
        },
        {
            "header": "X-Frame-Options",
            "aliases": ["x-frame-options"],
            "purpose": "Controls whether the website can be framed within an <iframe>, <embed>, or <object> tag.",
            "significance": "Provides robust defense against Clickjacking (UI redressing) attacks.",
            "recommendation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' if framing within identical origins is required."
        },
        {
            "header": "Referrer-Policy",
            "aliases": ["referrer-policy"],
            "purpose": "Governs which referrer information should be sent when requests are made from the document.",
            "significance": "Prevents accidental leakage of sensitive tokens, IDs, or internal URLs in HTTP Referer headers.",
            "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
        },
        {
            "header": "Permissions-Policy",
            "aliases": ["permissions-policy", "feature-policy"],
            "purpose": "Allows site owners to enable or disable browser features and APIs (camera, microphone, geolocation).",
            "significance": "Enforces least privilege on device APIs, restricting abuse by compromised embedded third-party scripts.",
            "recommendation": "Declare 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
        }
    ]

    @classmethod
    def analyze(cls, headers_dict: Dict[str, str]) -> Dict[str, Any]:
        # Case-insensitive headers lookup
        lower_headers = {k.lower(): v for k, v in headers_dict.items()}
        
        results = []
        present_count = 0
        missing_count = 0

        for spec in cls.HEADERS_SPEC:
            h_name = spec["header"]
            val = None
            for alias in spec["aliases"]:
                if alias in lower_headers:
                    val = lower_headers[alias]
                    break

            is_present = val is not None
            if is_present:
                present_count += 1
                status = cls._evaluate_header_strength(h_name, val)
            else:
                missing_count += 1
                status = "MISSING"

            results.append({
                "header": h_name,
                "present": is_present,
                "value": val,
                "status": status,
                "purpose": spec["purpose"],
                "significance": spec["significance"],
                "recommendation": spec["recommendation"]
            })

        # Deprecated header check: X-XSS-Protection
        xss_val = lower_headers.get("x-xss-protection")
        deprecated_headers = []
        if xss_val:
            deprecated_headers.append({
                "header": "X-XSS-Protection",
                "value": xss_val,
                "status": "DEPRECATED",
                "note": "X-XSS-Protection is deprecated in modern browsers and can introduce client-side security issues. Content-Security-Policy should be used instead."
            })

        return {
            "status": "SUCCESS" if headers_dict else "NO_DATA",
            "total_evaluated": len(cls.HEADERS_SPEC),
            "present_count": present_count,
            "missing_count": missing_count,
            "headers": results,
            "deprecated_headers": deprecated_headers,
            "source": "HTTP Response Headers Analysis"
        }

    @classmethod
    def _evaluate_header_strength(cls, header: str, value: str) -> str:
        val = value.lower().strip()
        if header == "Content-Security-Policy":
            if "default-src" in val or "script-src" in val:
                if "'unsafe-inline'" in val or "'unsafe-eval'" in val or "*" in val:
                    return "SUBOPTIMAL"
                return "STRONG"
            return "SUBOPTIMAL"
        elif header == "Strict-Transport-Security":
            if "max-age=" in val:
                try:
                    # check max-age seconds
                    parts = val.split(";")
                    for p in parts:
                        p = p.strip()
                        if p.startswith("max-age="):
                            age = int(p.split("=")[1])
                            if age >= 15768000:  # >= 6 months
                                return "STRONG"
                            return "SUBOPTIMAL"
                except Exception:
                    return "SUBOPTIMAL"
            return "SUBOPTIMAL"
        elif header == "X-Content-Type-Options":
            return "STRONG" if val == "nosniff" else "SUBOPTIMAL"
        elif header == "X-Frame-Options":
            return "STRONG" if val in ("deny", "sameorigin") else "SUBOPTIMAL"
        elif header == "Referrer-Policy":
            if any(term in val for term in ["no-referrer", "strict-origin", "origin-when-cross-origin"]):
                return "STRONG"
            return "SUBOPTIMAL"
        elif header == "Permissions-Policy":
            return "STRONG" if val else "SUBOPTIMAL"
        return "PRESENT"
